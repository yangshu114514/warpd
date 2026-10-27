//! 带 `SO_MARK` 的出站连接与 DNS 解析
//!
//! 所有离开本进程的流量（含 DNS）都必须打上 fwmark，这样内核策略路由
//! 才会把它们导入 table 100 → warp0 隧道。
//!
//! - TCP：socket2 建 socket → `set_mark` → 非阻塞 connect → 交给 tokio
//! - UDP（DNS）：socket2 建 UDP socket → `set_mark` → 直接收发 DNS 报文
//!
//! 不使用系统 getaddrinfo，因为那会走未打标的路径，造成 DNS 泄漏。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;

use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpStream, UdpSocket};

/// 给 socket 设置 `SO_MARK`。
///
/// 需要 `CAP_NET_ADMIN（或` `CAP_NET_RAW）；非` root 时会 EPERM。
// size_of::<u32>() 恒为 4，转 socklen_t 不可能截断；其余转换是 setsockopt 的固定签名。
#[allow(clippy::cast_possible_truncation)]
fn set_so_mark(fd: std::os::fd::RawFd, mark: u32) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::addr_of!(mark).cast::<libc::c_void>(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// 建立一个打过 `SO_MARK` 的 TCP 连接
///
/// 这是 SOCKS5 出站的主要入口。所有 CONNECT 目标都必须经过这里。
/// # Errors
///
/// 无法创建 socket、设置 `SO_MARK` 失败（通常缺 `CAP_NET_ADMIN`）、
/// 连接被拒绝，或超过 `timeout` 仍未建立连接。
pub async fn connect_marked(
    addr: SocketAddr,
    mark: u32,
    timeout: std::time::Duration,
) -> Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create TCP socket")?;

    // 关键：打 mark，让内核对这条连接应用 fwmark 策略路由
    set_so_mark(sock.as_raw_fd(), mark).with_context(|| {
        format!(
            "failed to set SO_MARK={mark:#x} on outbound socket (needs CAP_NET_ADMIN; \
             are we running as root?)"
        )
    })?;

    sock.set_nonblocking(true)?;
    sock.set_tcp_nodelay(true).ok();

    // 非阻塞 connect：EINPROGRESS 是正常现象
    match sock.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => {
            return Err(e).with_context(|| format!("immediate connect failure to {addr}"));
        }
    }

    // 转成 tokio TcpStream 并等待可写（= 连接完成）
    let std_stream: std::net::TcpStream = sock.into();
    let stream =
        TcpStream::from_std(std_stream).context("failed to convert socket into tokio TcpStream")?;

    match tokio::time::timeout(timeout, stream.writable()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(e).with_context(|| format!("socket error while connecting to {addr}"));
        }
        Err(_) => {
            return Err(anyhow!("connect to {addr} timed out after {timeout:?}"));
        }
    }

    // 检查 connect 是否真的成功（可写也可能是失败）
    if let Some(err) = stream.take_error()? {
        return Err(anyhow!("connect to {addr} failed: {err}"));
    }

    Ok(stream)
}

/// 打过 `SO_MARK` 的 DNS 解析器
pub struct MarkedResolver {
    mark: u32,
    /// 上游 DNS 服务器（默认 1.1.1.1:53，走隧道）
    servers: Vec<SocketAddr>,
    timeout: std::time::Duration,
}

impl MarkedResolver {
    /// # Panics
    ///
    /// 不会 panic：这里两个地址是硬编码的合法 IPv4 字面量。
    #[must_use]
    pub fn new(mark: u32) -> Self {
        Self {
            mark,
            servers: vec!["1.1.1.1:53".parse().unwrap(), "1.0.0.1:53".parse().unwrap()],
            timeout: std::time::Duration::from_secs(5),
        }
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn with_servers(mut self, servers: Vec<SocketAddr>) -> Self {
        self.servers = servers;
        self
    }

    /// 解析域名到 IP 列表（A + AAAA）
    ///
    /// DNS 查询本身也打 `SO_MARK，因此查询报文走` warp0 隧道，不会泄漏。
    /// # Errors
    ///
    /// A 与 AAAA 查询全部失败、DNS 服务器无响应，或响应报文无法解析。
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        // 如果本来就是 IP，直接返回
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let mut results = Vec::new();

        // A 记录
        match self.query(host, 1).await {
            Ok(ips) => results.extend(ips),
            Err(e) => log::debug!("A query for {host} failed: {e}"),
        }
        // AAAA 记录（失败不影响）
        match self.query(host, 28).await {
            Ok(ips) => results.extend(ips),
            Err(e) => log::debug!("AAAA query for {host} failed: {e}"),
        }

        if results.is_empty() {
            return Err(anyhow!("failed to resolve {host} (no A/AAAA records)"));
        }

        // IPv4 优先
        results.sort_by_key(|ip| i32::from(!ip.is_ipv4()));
        Ok(results)
    }

    /// 发送一次 DNS 查询（UDP，带 mark）
    async fn query(&self, host: &str, qtype: u16) -> Result<Vec<IpAddr>> {
        let query = build_dns_query(host, qtype)?;

        for server in &self.servers {
            match self.query_one(*server, &query).await {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => {}
                Err(e) => log::debug!("DNS server {server} failed: {e}"),
            }
        }
        Err(anyhow!("all DNS servers failed for {host}"))
    }

    async fn query_one(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<IpAddr>> {
        let domain = if server.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .context("failed to create UDP socket for DNS")?;

        // 关键：DNS socket 也打 mark，保证查询报文走 warp0，不泄漏
        set_so_mark(sock.as_raw_fd(), self.mark).context("failed to set SO_MARK on DNS socket")?;
        sock.set_nonblocking(true)?;

        // 转成 std UdpSocket 再交给 tokio（保留已设置的 fd 属性）
        let std_sock: std::net::UdpSocket = sock.into();
        std_sock
            .connect(server)
            .with_context(|| format!("failed to connect DNS socket to {server}"))?;
        let udp =
            UdpSocket::from_std(std_sock).context("failed to register DNS socket with tokio")?;

        // 发送
        udp.send(query).await.context("DNS send failed")?;

        // 期望的 ID（查询报文前 2 字节）
        let want_id = u16::from_be_bytes([query[0], query[1]]);

        // 接收：必须校验 ID，否则链路上任何人都能用一个伪造应答
        // 「抢先」回答我们的查询（经典的 DNS 缓存投毒）。虽然 socket 已
        // connect() 到指定 server，内核会过滤源地址，但源端口 + ID 的
        // 双重校验才是标准做法，缓存投毒攻击正是绕过前者命中的。
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = tokio::time::timeout_at(deadline, udp.recv(&mut buf))
                .await
                .map_err(|_| anyhow!("DNS query to {server} timed out"))?
                .context("DNS recv failed")?;

            if n < 2 {
                continue; // 太短，丢弃
            }
            let got_id = u16::from_be_bytes([buf[0], buf[1]]);
            if got_id != want_id {
                log::debug!(
                    "ignoring DNS response with mismatched id {got_id} (want {want_id}) from {server}"
                );
                continue;
            }
            return parse_dns_response(&buf[..n]);
        }
    }
}

/// 手工构造一个最小 DNS 查询报文
///
/// `label.len()` as u8 是安全的：上面已经显式拒绝了 >63 的 label。
#[allow(clippy::cast_possible_truncation)]
fn build_dns_query(host: &str, qtype: u16) -> Result<Vec<u8>> {
    // 每个查询用随机 ID：固定 ID 会让攻击者（或链路上任何一个能注入
    // UDP 包的人）无需猜测就能伪造应答。配合下面 parse 里的 ID 校验，
    // 才构成最基本的 DNS 反投毒防护。
    let id: u16 = rand::random();
    build_dns_query_with_id(host, qtype, id)
}

/// 带显式 ID 的版本（便于测试）
#[allow(clippy::cast_possible_truncation)]
fn build_dns_query_with_id(host: &str, qtype: u16, id: u16) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);

    // Header: ID, flags=0x0100 (RD), QDCOUNT=1
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // QNAME: 每个 label 前置长度
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(anyhow!("DNS label too long: {label}"));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // 根

    // QTYPE, QCLASS=IN
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    Ok(buf)
}

/// 解析 DNS 响应，提取 A/AAAA 记录
fn parse_dns_response(msg: &[u8]) -> Result<Vec<IpAddr>> {
    if msg.len() < 12 {
        return Err(anyhow!("DNS response too short"));
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut pos = 12;
    // 跳过 question 段
    for _ in 0..qdcount {
        pos = skip_dns_name(msg, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > msg.len() {
            return Err(anyhow!("malformed DNS question section"));
        }
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        pos = skip_dns_name(msg, pos)?;
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        // let rclass = u16::from_be_bytes([msg[pos+2], msg[pos+3]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > msg.len() {
            break;
        }

        match rtype {
            1 if rdlength == 4 => {
                // A
                let ip =
                    std::net::Ipv4Addr::new(msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3]);
                ips.push(IpAddr::V4(ip));
            }
            28 if rdlength == 16 => {
                // AAAA
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&msg[pos..pos + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlength;
    }

    Ok(ips)
}

/// 跳过 DNS 名字（支持压缩指针）
fn skip_dns_name(msg: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= msg.len() {
            return Err(anyhow!("DNS name runs past end of message"));
        }
        let len = msg[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        // 压缩指针：高两位为 11
        if len & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query() {
        let q = build_dns_query("example.com", 1).unwrap();
        // header 12 字节 + "example"(8) + "com"(4) + 根(1) + qtype/qclass(4)
        assert_eq!(q.len(), 12 + 1 + 7 + 1 + 3 + 1 + 4);
        assert_eq!(&q[12..13], &[7u8]); // len("example")
        assert_eq!(&q[13..20], b"example");
        assert_eq!(&q[20..21], &[3u8]); // len("com")
        assert_eq!(&q[21..24], b"com");
        assert_eq!(&q[24..25], &[0u8]);
    }

    #[test]
    fn test_build_query_with_explicit_id() {
        // 显式 ID 版本必须把 ID 原样写进前两字节，
        // 这是 query_one 里比对响应 ID 的依据。
        let q = build_dns_query_with_id("a.com", 1, 0xABCD).unwrap();
        assert_eq!(&q[0..2], &[0xAB, 0xCD]);
    }

    #[test]
    fn test_build_query_ids_are_random() {
        // 固定 ID 会让 DNS 应答可被无成本伪造；这里确认确实随机。
        let ids: std::collections::HashSet<u16> = (0..64)
            .map(|_| {
                let q = build_dns_query("example.com", 1).unwrap();
                u16::from_be_bytes([q[0], q[1]])
            })
            .collect();
        // 64 次随机里若只有 1 个值，几乎必然说明写死了
        assert!(ids.len() > 1, "DNS query IDs are not random: {ids:?}");
    }

    #[test]
    fn test_parse_real_a_response() {
        // 伪一个最小 A 响应：header + question + 1 answer
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes()); // standard response
        m.extend_from_slice(&1u16.to_be_bytes()); // QD
        m.extend_from_slice(&1u16.to_be_bytes()); // AN
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        // question: a.com A IN
        m.push(1);
        m.push(b'a');
        m.push(3);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        // answer: ptr to 12, type A, class IN, ttl, rdlen 4, 1.2.3.4
        m.extend_from_slice(&0xC00Cu16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&60u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[1, 2, 3, 4]);

        let ips = parse_dns_response(&m).unwrap();
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_parse_rejects_short() {
        assert!(parse_dns_response(&[0u8; 5]).is_err());
    }

    #[test]
    fn test_build_query_rejects_long_label() {
        let long = "a".repeat(70);
        assert!(build_dns_query(&format!("{long}.com"), 1).is_err());
    }
}
