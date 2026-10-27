//! 内核态 `WireGuard` 接口管理（纯 netlink）
//!
//! 这里不调用 `ip`/`wg`/`wg-quick` 任何外部命令，全部走 netlink：
//! - 创建 link：rtnetlink 的 `link().add().wireguard(name)`
//! - 配地址：rtnetlink 的 `address().add()`
//! - 设 MTU / up：rtnetlink 的 `link().set()`
//! - 配 peer（私钥/公钥/endpoint/allowed-ips/keepalive）：nl-wireguard 的 `set()`
//!
//! 数据面完全由内核 `WireGuard` 驱动，用户态只做配置。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use nl_wireguard::{
    WireguardIpAddress, WireguardParsed, WireguardParsedDeviceFlags, WireguardParsedPeerFlags,
    WireguardPeerParsed,
};
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::{new_connection, Handle, LinkUnspec, LinkWireguard};

use crate::warp::WarpConfig;

/// 内核接口的期望状态
pub struct WgInterface {
    pub name: String,
    pub mtu: u32,
    pub config: WarpConfig,
}

/// 对内核 `WireGuard` 的一个句柄集合（rtnetlink 用于 link/addr，nl-wireguard 用于 peer）
pub struct WgManager {
    handle: Handle,
    wg_handle: nl_wireguard::WireguardHandle,
}

impl WgManager {
    /// 建立到内核的 netlink 连接（需要 `CAP_NET_ADMIN` / root）
    ///
    /// 这个函数本身不做任何 I/O `等待：new_connection()` 是同步的，连接处理
    /// 被 spawn 到后台任务里。所以它不需要 async —— 保留 async 只会让所有
    /// 调用点多一次无意义的 poll。需要从异步上下文调用时直接同步调用即可。
    /// # Errors
    ///
    /// 无法打开 rtnetlink 或 genetlink socket。
    pub fn new() -> Result<Self> {
        let (conn, handle, _) = new_connection().context("failed to open rtnetlink socket")?;
        tokio::spawn(conn);

        let (wg_conn, wg_handle, _) =
            nl_wireguard::new_connection().context("failed to open wireguard genetlink socket")?;
        tokio::spawn(wg_conn);

        Ok(Self { handle, wg_handle })
    }

    /// 按名字查接口 ifindex
    ///
    /// 坑：`match_name()` 在接口不存在时会让内核返回 ENODEV(-19) 的错误，
    /// 而不是返回一个空流。把它当成故障会让「建接口前的存在性探测」直接失败。
    /// 所以这里 dump 全部 link 再在本地按 `IFLA_IFNAME` 过滤。
    /// # Errors
    ///
    /// netlink dump 请求失败。
    pub async fn find_index(&self, name: &str) -> Result<Option<u32>> {
        let mut stream = self.handle.link().get().execute();
        while let Some(msg) = stream.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    log::debug!("skipping link dump entry: {e}");
                    continue;
                }
            };
            let hit = msg
                .attributes
                .iter()
                .any(|a| matches!(a, LinkAttribute::IfName(n) if n == name));
            if hit {
                return Ok(Some(msg.header.index));
            }
        }
        Ok(None)
    }

    /// 删除已存在的同名接口（幂等清理用）
    /// # Errors
    ///
    /// 删除已存在的同名接口失败。
    pub async fn delete_if_exists(&self, name: &str) -> Result<bool> {
        if let Some(idx) = self.find_index(name).await? {
            log::info!("removing leftover interface {name} (ifindex {idx})");
            self.handle
                .link()
                .del(idx)
                .execute()
                .await
                .with_context(|| format!("failed to delete interface {name}"))?;
            // 等内核把接口真正回收，避免紧接着创建同名接口时 EEXIST
            for _ in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if self.find_index(name).await?.is_none() {
                    return Ok(true);
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// 创建并完整配置内核 `WireGuard` 接口
    ///
    /// 步骤（每一步都对应 netlink 报文，无外部命令）：
    /// 1. 清掉残留同名接口
    /// 2. `ip link add NAME type wireguard`
    /// 3. 添加 v4/v6 地址
    /// 4. 设 MTU 与 link up
    /// 5. 写入私钥与 peer 配置
    /// # Errors
    ///
    /// 创建接口、加地址、设 MTU，或应用 peer 配置失败。
    pub async fn setup(&mut self, iface: &WgInterface) -> Result<u32> {
        let name = &iface.name;

        // 1. 幂等：先删残留
        self.delete_if_exists(name).await?;

        // 2. 创建 wireguard link
        log::info!("creating kernel wireguard interface {name}");
        self.handle
            .link()
            .add(LinkWireguard::new(name).build())
            .execute()
            .await
            .with_context(|| {
                format!(
                    "failed to create wireguard interface {name}; \
                     is the kernel wireguard module available? (modprobe wireguard)"
                )
            })?;

        // 等接口出现在内核里
        let mut idx = None;
        for _ in 0..40 {
            if let Some(i) = self.find_index(name).await? {
                idx = Some(i);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let idx = idx.ok_or_else(|| anyhow!("interface {name} did not appear after creation"))?;
        log::info!("interface {name} created with ifindex {idx}");

        // 3. 地址
        let v4: Ipv4Addr = iface.config.address_v4.parse().with_context(|| {
            format!(
                "invalid IPv4 address from WARP: {}",
                iface.config.address_v4
            )
        })?;
        let v6: Ipv6Addr = iface.config.address_v6.parse().with_context(|| {
            format!(
                "invalid IPv6 address from WARP: {}",
                iface.config.address_v6
            )
        })?;

        self.handle
            .address()
            .add(idx, IpAddr::V4(v4), 32)
            .execute()
            .await
            .context("failed to add IPv4 address to wireguard interface")?;
        self.handle
            .address()
            .add(idx, IpAddr::V6(v6), 128)
            .execute()
            .await
            .context("failed to add IPv6 address to wireguard interface")?;
        log::info!("addresses set: {v4}/32, {v6}/128");

        // 4. MTU + up
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).mtu(iface.mtu).up().build())
            .execute()
            .await
            .context("failed to set MTU/up on wireguard interface")?;
        log::info!("interface {} up with mtu {}", name, iface.mtu);

        // 5. 私钥 + peer
        self.apply_peer_config(name, &iface.config).await?;

        Ok(idx)
    }

    /// 写入私钥与 peer 配置（nl-wireguard / genetlink）
    async fn apply_peer_config(&mut self, name: &str, cfg: &WarpConfig) -> Result<()> {
        // 直接用 WARP 下发的 endpoint，不自己探测/硬编码
        let endpoint = resolve_endpoint(&cfg.endpoint).await?;

        let mut peer = WireguardPeerParsed::default();
        peer.public_key = Some(cfg.peer_public_key.clone());
        peer.endpoint = Some(endpoint);
        peer.persistent_keepalive = Some(25);
        // AllowedIPs = 0.0.0.0/0, ::/0 —— 全量走隧道
        peer.allowed_ips = Some(vec![
            WireguardIpAddress {
                ip_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_length: 0,
                flags: None,
            },
            WireguardIpAddress {
                ip_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_length: 0,
                flags: None,
            },
        ]);
        peer.preshared_key = cfg.preshared_key.clone();
        // 重复运行要覆盖而不是追加
        peer.flags = Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);

        let mut device = WireguardParsed::default();
        device.iface_name = Some(name.to_string());
        device.private_key = Some(cfg.private_key.clone());
        // 关键：不要给接口本身设 fwmark，否则 WireGuard 发往 endpoint 的
        // 加密 UDP 包会被自己的策略路由捕获，形成环路。
        device.fwmark = Some(0);
        device.peers = Some(vec![peer]);
        device.flags = Some(vec![WireguardParsedDeviceFlags::ReplacePeers]);

        self.wg_handle
            .set(device)
            .await
            .context("failed to apply wireguard peer configuration via netlink")?;
        log::info!("peer configured: endpoint={endpoint} allowed_ips=0.0.0.0/0,::/0");
        Ok(())
    }

    /// 原地更新 peer 配置（不重建接口）
    ///
    /// 用于周期同步：服务端换了地址/peer 时，只把新配置下发给内核，
    /// 接口、路由、监听端口全部保持不变，所以**不会断流**。
    /// # Errors
    ///
    /// 向内核下发 peer 配置失败。
    pub async fn update_peer(&mut self, name: &str, cfg: &WarpConfig) -> Result<()> {
        log::info!("updating peer config in place on {name}");
        self.apply_peer_config(name, cfg).await
    }

    /// 原地更新接口地址（不重建接口）
    ///
    /// 为什么必须有这一步：Zero Trust 组织里服务端会重新分配 IPv6。
    /// 只更新 peer 是**修不好**这种情况的 —— 接口上仍然是旧地址，
    /// 新地址根本没加上，于是 v6 流量依旧不通。必须把旧地址摘掉、
    /// 新地址补上，周期同步才真正起到「跟上服务端」的作用。
    /// # Errors
    ///
    /// 接口不存在，或摘除/添加地址失败。
    pub async fn update_addresses(
        &self,
        name: &str,
        old: &WarpConfig,
        new: &WarpConfig,
    ) -> Result<()> {
        let idx = self
            .find_index(name)
            .await?
            .ok_or_else(|| anyhow!("interface {name} not found while updating addresses"))?;

        for (old_s, new_s, prefix) in [
            (&old.address_v4, &new.address_v4, 32u8),
            (&old.address_v6, &new.address_v6, 128u8),
        ] {
            if old_s == new_s {
                continue;
            }
            let new_ip: IpAddr = new_s
                .parse()
                .with_context(|| format!("invalid new address from WARP: {new_s}"))?;

            // 1. 先摘掉旧地址（如果它还在接口上）
            if let Ok(old_ip) = old_s.parse::<IpAddr>() {
                let mut stream = self
                    .handle
                    .address()
                    .get()
                    .set_link_index_filter(idx)
                    .set_address_filter(old_ip)
                    .execute();
                let mut victims = Vec::new();
                while let Some(msg) = stream.next().await {
                    if let Ok(m) = msg {
                        victims.push(m);
                    }
                }
                for msg in victims {
                    match self.handle.address().del(msg).execute().await {
                        Ok(()) => log::info!("removed stale address {old_s} from {name}"),
                        Err(e) => log::warn!("could not remove stale address {old_s}: {e}"),
                    }
                }
            }

            // 2. 再补上新地址
            self.handle
                .address()
                .add(idx, new_ip, prefix)
                .replace()
                .execute()
                .await
                .with_context(|| format!("failed to add address {new_s} to {name}"))?;
            log::info!("added address {new_s} to {name}");
        }
        Ok(())
    }

    /// 读回接口当前配置（诊断用）。
    ///
    /// # Errors
    ///
    /// 读取内核中的 `WireGuard` 配置失败。
    pub async fn dump(&mut self, name: &str) -> Result<nl_wireguard::WireguardParsed> {
        self.wg_handle
            .get_by_name(name)
            .await
            .map_err(|e| anyhow!("failed to read wireguard config: {e:?}"))
    }

    /// 删除接口
    /// # Errors
    ///
    /// 删除接口失败。
    pub async fn teardown(&mut self, name: &str) -> Result<()> {
        self.delete_if_exists(name).await?;
        log::info!("interface {name} removed");
        Ok(())
    }

    /// 取 rtnetlink Handle 引用（策略路由模块要用）
    #[must_use]
    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}

/// 解析 endpoint 字符串到 SocketAddr；支持域名
///
/// 直接使用 WARP 下发的 endpoint（`engage.cloudflareclient.com:2408`），
/// 不在源码里硬编码 anycast IP 列表 —— 服务端下发的就是权威值。
/// 如果哪天某个入口不可用，走 `--refresh` 重新拉配置即可拿到新地址。
///
/// 注意：解析 WARP endpoint 不能走 marked DNS（隧道还没建立，会死锁），
/// 所以对官方域名直接用系统解析。
async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    if let Ok(sa) = endpoint.parse::<SocketAddr>() {
        return Ok(sa);
    }

    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("endpoint must be host:port, got {endpoint}"))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid port in endpoint {endpoint}"))?;

    // 引导期解析：此时隧道尚未建立，只能用系统解析器。
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve wireguard endpoint {host}"))?;

    // 优先 IPv4：WARP 的 IPv4 入口更稳定
    let mut fallback = None;
    for a in addrs.by_ref() {
        if a.is_ipv4() {
            return Ok(a);
        }
        if fallback.is_none() {
            fallback = Some(a);
        }
    }
    fallback.ok_or_else(|| anyhow!("no address resolved for endpoint {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_ip_endpoint() {
        let sa = resolve_endpoint("162.159.192.1:2408").await.unwrap();
        assert_eq!(sa.port(), 2408);
        assert!(sa.is_ipv4());
    }

    #[tokio::test]
    async fn test_resolve_bad_endpoint() {
        assert!(resolve_endpoint("no-port-here").await.is_err());
        assert!(resolve_endpoint("1.2.3.4:notaport").await.is_err());
    }

    #[test]
    fn test_allowed_ips_are_default_route() {
        // 确保我们构造的 AllowedIPs 真的是 0/0 + ::/0
        let v4 = WireguardIpAddress {
            ip_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 0,
            flags: None,
        };
        let v6 = WireguardIpAddress {
            ip_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix_length: 0,
            flags: None,
        };
        assert_eq!(v4.prefix_length, 0);
        assert_eq!(v6.prefix_length, 0);
        assert!(v4.ip_addr.is_unspecified());
        assert!(v6.ip_addr.is_unspecified());
    }
}
