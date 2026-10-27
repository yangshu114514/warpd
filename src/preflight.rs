//! 启动前环境检查
//!
//! 明确的三件事：
//! 1. 必须是 root，或至少有 `CAP_NET_ADMIN`
//! 2. 内核必须支持 WireGuard（模块已加载或可加载）
//! 3. 平台必须是 Linux

use anyhow::{bail, Result};

/// 检查是否具备配置内核网络所需的权限
/// # Errors
///
/// 既不是 root，也没有 `CAP_NET_ADMIN` + `CAP_NET_RAW`。
pub fn check_privileges() -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        log::debug!("running as root (euid=0)");
        return Ok(());
    }

    // 非 root 时尝试检测 capability
    if has_cap_net_admin() {
        log::info!("running as non-root (euid={euid}) but CAP_NET_ADMIN is present");
        return Ok(());
    }

    bail!(
        "insufficient privileges: warpd needs root or CAP_NET_ADMIN to create \
         a kernel WireGuard interface and to set SO_MARK on outbound sockets. \
         Try: sudo warpd  (or run under systemd with AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW)"
    )
}

/// 从 /proc/self/status 解析 CapEff，检查 `CAP_NET_ADMIN` (bit 12)
fn has_cap_net_admin() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let hexval = rest.trim();
            if let Ok(mask) = u64::from_str_radix(hexval, 16) {
                const CAP_NET_ADMIN: u64 = 12;
                const CAP_NET_RAW: u64 = 13;
                let net_admin = mask & (1 << CAP_NET_ADMIN) != 0;
                let net_raw = mask & (1 << CAP_NET_RAW) != 0;
                return net_admin && net_raw;
            }
        }
    }
    false
}

/// 检查内核 `WireGuard` 支持
/// # Errors
///
/// 内核不支持 WireGuard，且尝试 modprobe 后仍不可用。
pub fn check_wireguard_support() -> Result<()> {
    // 已加载？
    if std::path::Path::new("/sys/module/wireguard").exists() {
        log::debug!("kernel wireguard module is loaded");
        return Ok(());
    }

    // 未加载：尝试 modprobe
    log::info!("wireguard module not loaded, trying to load it");
    let out = std::process::Command::new("modprobe")
        .arg("wireguard")
        .output();

    match out {
        Ok(o) if o.status.success() => {
            if std::path::Path::new("/sys/module/wireguard").exists() {
                log::info!("kernel wireguard module loaded");
                return Ok(());
            }
            // modprobe 成功但模块没出现：可能编译进内核了
            log::debug!("modprobe succeeded but /sys/module/wireguard absent; assuming builtin");
            Ok(())
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            // 如果是 builtin，modprobe 会说 "Module wireguard not found" 之类
            if std::path::Path::new("/sys/module/wireguard").exists() {
                return Ok(());
            }
            bail!(
                "kernel WireGuard support is not available: modprobe wireguard failed: {}. \
                 Install it with: apt install wireguard-modules (Debian/Ubuntu) or \
                 ensure CONFIG_WIREGUARD=m in your kernel",
                stderr.trim()
            )
        }
        Err(e) => {
            log::warn!(
                "could not run modprobe ({e}); assuming wireguard is builtin or module is loaded"
            );
            Ok(())
        }
    }
}

/// 平台检查：本项目只做 Linux 内核态 `WireGuard`
/// # Errors
///
/// 不是在 Linux 上运行。
pub fn check_platform() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("warpd only supports Linux (kernel WireGuard via netlink)");
    }
    Ok(())
}

/// 跑完所有检查
/// # Errors
///
/// 任一项平台、权限或内核支持检查未通过。
pub fn run_all() -> Result<()> {
    check_platform()?;
    check_privileges()?;
    check_wireguard_support()?;
    Ok(())
}
