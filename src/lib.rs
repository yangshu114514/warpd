//! warpd —— 原生 Rust WARP 客户端
//!
//! 架构：
//!   WARP 注册（HTTP）  →  `WarpConfig`
//!                           ↓
//!   内核 `WireGuard` 配置（netlink: rtnetlink + nl-wireguard）
//!                           ↓
//!   fwmark 策略路由（table 100 → warp0）
//!                           ↓
//!   SOCKS5 (127.0.0.1:1080) —— 出站打 `SO_MARK` → 走 warp0
//!
//! 数据面完全是内核态 WireGuard；用户态只做控制面与代理。

pub mod dialer;
pub mod policyrt;
pub mod socks5;
pub mod warp;
pub mod wgkey;
pub mod wgnet;

pub mod preflight;
pub mod store;
