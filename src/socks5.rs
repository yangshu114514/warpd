//! SOCKS5 服务器（RFC 1928，只实现 CONNECT）
//!
//! 设计要点：
//! - 只监听 loopback（默认 127.0.0.1:1080），绝不监听 0.0.0.0
//! - 只支持 CONNECT（不支持 BIND / UDP ASSOCIATE，按需求明确排除）
//! - 所有出站连接都经 marked dialer，打 `SO_MARK` → 走 warp0
//! - ATYP=DOMAIN 时域名由本代理解析（marked DNS），不会泄漏

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dialer::{connect_marked, MarkedResolver};

const SOCKS_VERSION: u8 = 0x05;

const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 服务器配置
#[derive(Clone)]
pub struct SocksConfig {
    /// 监听地址（必须是 loopback）
    pub listen: SocketAddr,
    /// 出站 `SO_MARK`
    pub mark: u32,
    /// 出站连接超时
    pub connect_timeout: std::time::Duration,
    /// 客户端握手（协商+请求）超时。防止半开连接永久占用 fd 和 task。
    pub handshake_timeout: std::time::Duration,
    /// 最大并发连接数。防止 fd 耗尽。
    pub max_connections: usize,
}

/// SOCKS5 服务器
pub struct SocksServer {
    cfg: SocksConfig,
    resolver: Arc<MarkedResolver>,
}

impl SocksServer {
    #[must_use]
    pub fn new(cfg: SocksConfig) -> Self {
        let resolver = Arc::new(MarkedResolver::new(cfg.mark));
        Self { cfg, resolver }
    }

    /// 校验监听地址必须是 loopback（硬性安全约束）
    /// # Errors
    ///
    /// 监听地址不是 loopback 地址。
    pub fn validate_bind(addr: &SocketAddr) -> Result<()> {
        if !addr.ip().is_loopback() {
            bail!(
                "refusing to listen on {addr}: SOCKS5 must bind to a loopback address \
                 (e.g. 127.0.0.1) to avoid exposing the proxy to the network"
            );
        }
        Ok(())
    }

    /// 启动服务器，阻塞直到进程退出
    /// # Errors
    ///
    /// 绑定端口失败，或监听地址不是 loopback。
    pub async fn run(self) -> Result<()> {
        Self::validate_bind(&self.cfg.listen)?;

        let listener = TcpListener::bind(self.cfg.listen)
            .await
            .with_context(|| format!("failed to bind SOCKS5 listener on {}", self.cfg.listen))?;
        log::info!(
            "SOCKS5 listening on {} (outbound SO_MARK={:#x})",
            self.cfg.listen,
            self.cfg.mark
        );

        let cfg = Arc::new(self.cfg);
        let resolver = self.resolver.clone();
        // 并发连接计数：用一个信号量限制总量，避免 fd 耗尽
        let limit = Arc::new(tokio::sync::Semaphore::new(cfg.max_connections.max(1)));

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("accept failed: {e}");
                    // 避免 busy loop
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };

            // 双保险：即使 bind 检查被绕过，也不服务非 loopback 来源
            if !peer.ip().is_loopback() {
                log::warn!("rejecting non-loopback SOCKS client from {peer}");
                continue;
            }

            // 并发已达上限时**直接拒绝**这条连接，而不是排队等待。
            // 原因是：排队会让 backlog 里的连接一直挂着，客户端看到的是
            // 「连上了但永远没响应」，比明确的拒绝更难排查，也更容易被
            // 用来堆积 fd。这里用 try_acquire 配合立即 continue 是有意为之。
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                log::warn!(
                    "too many concurrent SOCKS connections (limit {}), rejecting {}",
                    cfg.max_connections,
                    peer
                );
                continue;
            };

            let cfg = cfg.clone();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let _permit = permit; // 连接结束时自动归还
                log::debug!("new SOCKS5 connection from {peer}");
                if let Err(e) = handle_client(stream, cfg, resolver).await {
                    log::debug!("socks session ended with error: {e}");
                }
            });
        }
    }
}

/// 处理单个 SOCKS5 客户端会话
async fn handle_client(
    client: TcpStream,
    cfg: Arc<SocksConfig>,
    resolver: Arc<MarkedResolver>,
) -> Result<()> {
    client.set_nodelay(true).ok();

    // 先把「协商 + 请求 + 建连」整段握手放进超时里。
    // 这可以防止半开连接（客户端连上不吭声）永久占用 fd 和 task。
    // 注意：**不能**把后面的数据转发也包进超时，否则正常的长连接代理
    // 会在超时时间到点被无辜掐断。
    let (client, upstream) = tokio::time::timeout(
        cfg.handshake_timeout,
        handshake(client, cfg.clone(), resolver),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "SOCKS5 handshake timed out after {:?}",
            cfg.handshake_timeout
        )
    })??;

    // 握手完成，开始双向转发（不受握手超时约束）
    let mut client = client;
    let mut upstream = upstream;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// 完成 SOCKS5 握手并建立到目标的上游连接。
/// 返回 (客户端流, 上游流)，此时已可以开始转发。
async fn handshake(
    mut client: TcpStream,
    cfg: Arc<SocksConfig>,
    resolver: Arc<MarkedResolver>,
) -> Result<(TcpStream, TcpStream)> {
    // ---- 阶段 1：方法协商 ----
    let mut hdr = [0u8; 2];
    client
        .read_exact(&mut hdr)
        .await
        .context("failed reading greeting")?;
    if hdr[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS version {}", hdr[0]);
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client
        .read_exact(&mut methods)
        .await
        .context("failed reading auth methods")?;

    // 只支持 NO AUTH (0x00)
    if !methods.contains(&0x00) {
        client.write_all(&[SOCKS_VERSION, 0xFF]).await.ok();
        bail!("client offered no supported auth method");
    }
    client
        .write_all(&[SOCKS_VERSION, 0x00])
        .await
        .context("failed writing method selection")?;

    // ---- 阶段 2：请求 ----
    let mut req = [0u8; 4];
    client
        .read_exact(&mut req)
        .await
        .context("failed reading request")?;
    if req[0] != SOCKS_VERSION {
        bail!("bad request version {}", req[0]);
    }
    let cmd = req[1];
    let atyp = req[3];

    if cmd != CMD_CONNECT {
        // BIND(2) / UDP ASSOCIATE(3) 明确不支持
        reply_error(&mut client, REP_COMMAND_NOT_SUPPORTED)
            .await
            .ok();
        bail!("unsupported SOCKS5 command {cmd} (only CONNECT is implemented)");
    }

    // ---- 解析目标地址 ----
    let atyp_supported = matches!(atyp, ATYP_IPV4 | ATYP_IPV6 | ATYP_DOMAIN);
    if !atyp_supported {
        reply_error(&mut client, REP_ADDRESS_TYPE_NOT_SUPPORTED)
            .await
            .ok();
        bail!("unsupported address type {atyp}");
    }
    let target_host = read_target_host(&mut client, atyp).await?;
    let port = read_port(&mut client).await?;

    log::debug!("CONNECT {target_host}:{port}");

    // ---- 解析域名（打 mark 的 DNS，不泄漏） ----
    let ips = match resolver.resolve(&target_host).await {
        Ok(ips) => ips,
        Err(e) => {
            log::debug!("resolve failed for {target_host}: {e}");
            reply_error(&mut client, REP_HOST_UNREACHABLE).await.ok();
            return Err(e);
        }
    };

    // ---- 依次尝试连接（打 mark） ----
    let mut upstream: Option<TcpStream> = None;
    let mut last_err = None;
    for ip in &ips {
        let dest = SocketAddr::new(*ip, port);
        match connect_marked(dest, cfg.mark, cfg.connect_timeout).await {
            Ok(s) => {
                log::debug!("connected to {dest} for {target_host}");
                upstream = Some(s);
                break;
            }
            Err(e) => {
                log::debug!("connect to {dest} failed: {e}");
                last_err = Some(e);
            }
        }
    }

    let Some(upstream) = upstream else {
        let msg = last_err.map(|e| e.to_string()).unwrap_or_default();
        let rep = if msg.contains("refused") {
            REP_CONNECTION_REFUSED
        } else {
            REP_GENERAL_FAILURE
        };
        reply_error(&mut client, rep).await.ok();
        return Err(anyhow!(
            "all connection attempts failed for {target_host}:{port}"
        ));
    };

    // ---- 成功回复 ----
    reply_success(&mut client).await?;

    Ok((client, upstream))
}

/// 读取 CONNECT 请求中的目标主机（已是字符串形式）。
///
/// `ATYP=DOMAIN` 时返回的是域名本身，稍后由 `MarkedResolver` 通过隧道解析，
/// 这样既不会泄漏 DNS，也能正确处理 CDN 的多 IP 情况。
///
/// # Errors
///
/// 读取出错、IPv4/IPv6 字段长度不足，或域名不是合法 UTF-8。
async fn read_target_host(client: &mut TcpStream, atyp: u8) -> Result<String> {
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            client
                .read_exact(&mut b)
                .await
                .context("failed reading ipv4")?;
            Ok(IpAddr::V4(Ipv4Addr::from(b)).to_string())
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            client
                .read_exact(&mut b)
                .await
                .context("failed reading ipv6")?;
            Ok(IpAddr::V6(Ipv6Addr::from(b)).to_string())
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client
                .read_exact(&mut len)
                .await
                .context("failed reading domain len")?;
            let mut dom = vec![0u8; len[0] as usize];
            client
                .read_exact(&mut dom)
                .await
                .context("failed reading domain")?;
            String::from_utf8(dom).context("domain is not valid UTF-8")
        }
        other => bail!("unsupported address type {other}"),
    }
}

/// 读取 2 字节大端端口
///
/// # Errors
///
/// 客户端的端口字段读取失败。
async fn read_port(client: &mut TcpStream) -> Result<u16> {
    let mut port_b = [0u8; 2];
    client
        .read_exact(&mut port_b)
        .await
        .context("failed reading port")?;
    Ok(u16::from_be_bytes(port_b))
}

/// 回复成功（BND.ADDR 用 0.0.0.0:0）
async fn reply_success(client: &mut TcpStream) -> Result<()> {
    let mut resp = Vec::with_capacity(10);
    resp.push(SOCKS_VERSION);
    resp.push(REP_SUCCESS);
    resp.push(0x00); // RSV
    resp.push(ATYP_IPV4);
    resp.extend_from_slice(&[0, 0, 0, 0]);
    resp.extend_from_slice(&0u16.to_be_bytes());
    client
        .write_all(&resp)
        .await
        .context("failed writing success reply")?;
    Ok(())
}

/// 回复错误
async fn reply_error(client: &mut TcpStream, code: u8) -> Result<()> {
    let mut resp = Vec::with_capacity(10);
    resp.push(SOCKS_VERSION);
    resp.push(code);
    resp.push(0x00);
    resp.push(ATYP_IPV4);
    resp.extend_from_slice(&[0, 0, 0, 0]);
    resp.extend_from_slice(&0u16.to_be_bytes());
    client.write_all(&resp).await.ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_bind_accepts_loopback() {
        assert!(SocksServer::validate_bind(&"127.0.0.1:1080".parse().unwrap()).is_ok());
        assert!(SocksServer::validate_bind(&"127.0.0.2:1080".parse().unwrap()).is_ok());
        assert!(SocksServer::validate_bind(&"[::1]:1080".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_validate_bind_rejects_non_loopback() {
        // 这是硬性安全约束：绝不能监听到外部
        assert!(SocksServer::validate_bind(&"0.0.0.0:1080".parse().unwrap()).is_err());
        assert!(SocksServer::validate_bind(&"192.168.1.5:1080".parse().unwrap()).is_err());
        assert!(SocksServer::validate_bind(&"[::]:1080".parse().unwrap()).is_err());
        assert!(SocksServer::validate_bind(&"8.8.8.8:1080".parse().unwrap()).is_err());
    }
}
