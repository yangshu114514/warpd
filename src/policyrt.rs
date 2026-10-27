//! fwmark 策略路由管理
//!
//! 核心思想（绝对不能污染主路由表）：
//! - 给打上 mark 的流量单独走一张独立表（默认 100）
//! - 表里的 default 指向 warp0
//! - 主路由表（main/254）完全不动
//!
//! 等价于：
//!   ip rule add fwmark 0x1 lookup 100 priority 100
//!   ip route add default dev warp0 table 100
//!   ip -6 rule add fwmark 0x1 lookup 100 priority 100
//!   ip -6 route add default dev warp0 table 100
//!   sysctl -w `net.ipv4.conf.all.src_valid_mark=1`
//!
//! 两个实测过的 netlink 坑（都会导致规则「静默失效」）：
//! 1. `RuleAddRequest` 默认 action 是 `RuleAction::Unspec，必须显式`
//!    .`action(RuleAction::ToTable)，否则` `ip rule show` 末尾显示 none 且规则不生效。
//! 2. `RouteMessageBuilder` / `RouteAddRequest` 默认写 main 表(254)，不显式
//!    .`table_id()` 会把路由塞进主表，既污染主表又让目标表为空。

use anyhow::{Context, Result};
use futures_util::StreamExt;
use rtnetlink::packet_route::route::RouteMessage;
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};
use std::net::{Ipv4Addr, Ipv6Addr};

/// 策略路由配置
#[derive(Debug, Clone)]
pub struct PolicyRouting {
    /// 要匹配的 fwmark
    pub mark: u32,
    /// 独立路由表号
    pub table: u32,
    /// rule 优先级（越小越先匹配）
    pub priority: u32,
    /// 隧道接口名
    pub iface: String,
}

impl PolicyRouting {
    pub fn new(mark: u32, table: u32, iface: impl Into<String>) -> Self {
        // priority 取 table 附近的值，避免和系统已有 rule 撞车
        let priority = table.clamp(100, 32000);
        Self {
            mark,
            table,
            priority,
            iface: iface.into(),
        }
    }
}

/// 策略路由管理器
pub struct RouteManager {
    handle: Handle,
}

impl RouteManager {
    #[must_use]
    pub fn new(handle: Handle) -> Self {
        Self { handle }
    }

    /// 安装策略路由（幂等：先清旧的再装）
    /// # Errors
    ///
    /// 添加 rule 或 default 路由失败（通常是权限不足或表号冲突）。
    pub async fn install(&self, cfg: &PolicyRouting, ifindex: u32) -> Result<()> {
        log::info!(
            "installing policy routing: fwmark {:#x} -> table {} -> {} (ifindex {})",
            cfg.mark,
            cfg.table,
            cfg.iface,
            ifindex
        );

        // 幂等：先清理可能存在的旧规则/路由
        if let Err(e) = self.cleanup(cfg, ifindex).await {
            log::debug!("pre-install cleanup reported: {e}");
        }

        // ---- IPv4：rule + default route ----
        self.add_rule(cfg, IpVersion::V4).await?;
        self.add_default_route(cfg, ifindex, IpVersion::V4).await?;

        // ---- IPv6：失败不致命（有些环境禁用了 v6） ----
        match self.add_rule(cfg, IpVersion::V6).await {
            Ok(()) => {
                if let Err(e) = self.add_default_route(cfg, ifindex, IpVersion::V6).await {
                    log::warn!("failed to add IPv6 default route (continuing): {e:#}");
                }
            }
            Err(e) => log::warn!("failed to add IPv6 rule (continuing): {e:#}"),
        }

        // ---- sysctl ----
        if let Err(e) = set_src_valid_mark() {
            log::warn!("failed to set net.ipv4.conf.all.src_valid_mark=1: {e:#}");
        }

        log::info!("policy routing installed (main table untouched)");
        Ok(())
    }

    /// 添加 fwmark rule
    ///
    /// 关键：必须显式 .`action(RuleAction::ToTable)，否则规则静默失效`。
    async fn add_rule(&self, cfg: &PolicyRouting, ver: IpVersion) -> Result<()> {
        let builder = self
            .handle
            .rule()
            .add()
            .fw_mark(cfg.mark)
            .table_id(cfg.table)
            .priority(cfg.priority)
            .action(RuleAction::ToTable);

        let res = match ver {
            IpVersion::V4 => builder.v4().execute().await,
            IpVersion::V6 => builder.v6().execute().await,
        };

        res.with_context(|| {
            format!(
                "failed to add {:?} rule: fwmark {:#x} -> table {}",
                ver, cfg.mark, cfg.table
            )
        })?;
        Ok(())
    }

    /// 添加独立表中的 default 路由
    ///
    /// 关键：必须显式 .`table_id()，否则会写进` main 表。
    async fn add_default_route(
        &self,
        cfg: &PolicyRouting,
        ifindex: u32,
        ver: IpVersion,
    ) -> Result<()> {
        let message = match ver {
            IpVersion::V4 => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .output_interface(ifindex)
                .table_id(cfg.table)
                .build(),
            IpVersion::V6 => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
                .output_interface(ifindex)
                .table_id(cfg.table)
                .build(),
        };

        self.handle
            .route()
            .add(message)
            .execute()
            .await
            .with_context(|| {
                format!(
                    "failed to add {:?} default route in table {} via ifindex {}",
                    ver, cfg.table, ifindex
                )
            })?;
        log::debug!("{:?} default route added to table {}", ver, cfg.table);
        Ok(())
    }

    /// 清理策略路由（删 rule + 独立表内的路由）
    ///
    /// 关键：这里要**无条件清空整张表**，不能只删「我们以为是自己的那条」。
    /// 原因：如果上次是异常退出（SIGKILL/panic），或者别的程序先占用了这张表，
    /// 残留的 default 路由会让我们后续的 add 失败（EEXIST），
    /// 结果是「规则装不上、隧道等于没接」。
    /// 这张表是本程序专用的（默认 100，且已被 `validate_table` 限定为私有表），
    /// 所以整表清空是安全且正确的语义。
    /// # Errors
    ///
    /// 枚举或删除路由/规则时 netlink 返回错误。
    pub async fn cleanup(&self, cfg: &PolicyRouting, ifindex: u32) -> Result<()> {
        log::info!("cleaning up policy routing (table {})", cfg.table);

        // 1. 枚举并删除这张表里的**所有**路由（不限 ifindex、不限目标网段）
        //
        // rtnetlink 0.23 的 route().get() 需要一个 RouteMessage 作为过滤器；
        // 传空的就能 dump 全表，再在本地按 header.table 过滤。
        for ver in [IpVersion::V4, IpVersion::V6] {
            let filter = match ver {
                IpVersion::V4 => RouteMessageBuilder::<Ipv4Addr>::new().build(),
                IpVersion::V6 => RouteMessageBuilder::<Ipv6Addr>::new().build(),
            };
            let mut stream = self.handle.route().get(filter).execute();
            let mut victims: Vec<RouteMessage> = Vec::new();
            while let Some(msg) = stream.next().await {
                let Ok(msg) = msg else { continue };
                if u32::from(msg.header.table) == cfg.table {
                    victims.push(msg);
                }
            }
            let n = victims.len();
            for msg in victims {
                if let Err(e) = self.handle.route().del(msg).execute().await {
                    log::debug!("failed to delete a route in table {}: {}", cfg.table, e);
                }
            }
            if n > 0 {
                log::info!(
                    "removed {} leftover route(s) from table {} ({:?})",
                    n,
                    cfg.table,
                    ver
                );
            }
        }

        // 2. 删除匹配 fwmark + table 的 rule
        self.delete_rules(cfg).await;

        // 3. 兜底：拿不到 ifindex 时也可能有残留，用 ip 命令刷一遍
        let _ = std::process::Command::new("ip")
            .args(["route", "flush", "table", &cfg.table.to_string()])
            .output();
        let _ = std::process::Command::new("ip")
            .args(["-6", "route", "flush", "table", &cfg.table.to_string()])
            .output();

        let _ = ifindex; // 保留参数以兼容既有调用点
        Ok(())
    }

    async fn delete_rules(&self, cfg: &PolicyRouting) {
        for ver in [IpVersion::V4, IpVersion::V6] {
            let mut stream = self.handle.rule().get(ver.clone()).execute();
            let mut to_delete: Vec<RuleMessage> = Vec::new();

            while let Some(msg) = stream.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        log::debug!("error listing {ver:?} rules: {e}");
                        break;
                    }
                };
                let has_mark = msg
                    .attributes
                    .iter()
                    .any(|a| matches!(a, RuleAttribute::FwMark(m) if *m == cfg.mark));
                let our_table = u32::from(msg.header.table) == cfg.table;
                if has_mark && our_table {
                    to_delete.push(msg);
                }
            }

            for rule in to_delete {
                if let Err(e) = self.handle.rule().del(rule).execute().await {
                    log::debug!("failed to delete {ver:?} rule: {e}");
                }
            }
        }
    }
}

/// 写入 `net.ipv4.conf.all.src_valid_mark` = 1
///
/// `WireGuard` + fwmark 策略路由的标准要求：让内核做反向路径校验时考虑
/// fwmark，否则 marked 入站回包可能被判为 martian 而丢弃。
fn set_src_valid_mark() -> Result<()> {
    let path = "/proc/sys/net/ipv4/conf/all/src_valid_mark";
    // 先读，已经是 1 就不写（有些环境该文件只读）
    if let Ok(cur) = std::fs::read_to_string(path) {
        if cur.trim() == "1" {
            return Ok(());
        }
    }
    std::fs::write(
        path, b"1
",
    )
    .with_context(|| format!("failed to write {path}"))?;
    Ok(())
}

/// 读当前 `src_valid_mark` 值（诊断用）
#[must_use]
pub fn get_src_valid_mark() -> Option<String> {
    std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/src_valid_mark")
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_from_table() {
        let p = PolicyRouting::new(1, 100, "warp0");
        assert_eq!(p.priority, 100);
        assert_eq!(p.table, 100);
        assert_eq!(p.mark, 1);

        // clamp 到上限
        let p2 = PolicyRouting::new(1, 99999, "warp0");
        assert_eq!(p2.priority, 32000);
    }

    #[test]
    fn test_src_valid_mark_readable() {
        // 在 Linux 上应该能读到 0 或 1
        if let Some(v) = get_src_valid_mark() {
            assert!(v == "0" || v == "1", "unexpected value: {v}");
        }
    }
}
