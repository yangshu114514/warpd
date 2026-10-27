//! 配置持久化
//!
//! WARP 注册会消耗 Cloudflare 的配额，所以注册一次就把结果存下来，
//! 后续启动直接复用，只有显式 --reset 时才重新注册。
//! 这也让「第二次启动不报错」的幂等要求更彻底。

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::warp::WarpConfig;

/// 默认配置路径
pub fn default_path() -> PathBuf {
    if let Ok(p) = std::env::var("WARPD_STATE_FILE") {
        return PathBuf::from(p);
    }
    if unsafe { libc::geteuid() } == 0 {
        PathBuf::from("/var/lib/warpd/warp.json")
    } else {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|_| PathBuf::from("."));
        base.join("warpd").join("warp.json")
    }
}

/// 载入已保存的配置
/// # Errors
///
/// 读取失败，或文件内容不是合法 JSON。
pub fn load(path: &Path) -> Result<Option<WarpConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read state file {}", path.display()))?;
    let cfg: WarpConfig = serde_json::from_str(&raw)
        .with_context(|| format!("state file {} is corrupt", path.display()))?;
    Ok(Some(cfg))
}

/// 保存配置（权限 0600，因为含私钥）
///
/// 安全性要点：临时文件必须在**创建时**就是 0600，不能先按 umask(022)
/// 落成 0644 再 chmod——那中间有一个全局可读的窗口，而这文件里是私钥。
/// 另外 chmod 失败必须报错，不能 .`ok()` 吞掉（NFS/overlayfs 下会静默留 0644）。
/// # Errors
///
/// 创建目录、创建临时文件、写入，或 rename 失败；权限无法收紧到 0600 时也报错。
pub fn save(path: &Path, cfg: &WarpConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create state dir {}", parent.display()))?;
        // 目录也收紧到 0700：目录可读 = 能枚举到文件名
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("failed to chmod state dir {}", parent.display()))?;
        }
    }
    let json = serde_json::to_string_pretty(cfg)?;

    // 先写临时文件再 rename，避免半写坏文件。
    //
    // 临时文件名必须**唯一**：进程内有后台的周期同步任务也会写同一份配置，
    // 若都用固定的 warp.json.tmp，两个写入方会互相截断对方的半成品，
    // 甚至出现「A rename 之后 B 还在写」→ B 的 rename 把 A 的结果覆盖。
    // 加上 pid + 纳秒时间戳后，每个写入者各写各的，最后一次 rename 生效。
    let unique = format!(
        "json.tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
    );
    let tmp = path.with_extension(unique);

    // 关键：用 OpenOptions 在创建时就指定 0600，避免出现 0644 的中间态
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("failed to create temp state file {}", tmp.display()))?;
        f.write_all(json.as_bytes())
            .with_context(|| format!("failed to write temp state file {}", tmp.display()))?;
        f.sync_all().ok();

        // 某些文件系统会忽略 mode()，这里再确认一次且**不吞错误**
        let meta =
            std::fs::metadata(&tmp).with_context(|| format!("failed to stat {}", tmp.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).with_context(
                || {
                    format!(
                        "state file {} has mode {:o} but 0600 is required (it holds a private key)",
                        tmp.display(),
                        mode
                    )
                },
            )?;
        }
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, &json)
            .with_context(|| format!("failed to write temp state file {}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to move state file into place at {}", path.display()))?;
    log::info!("WARP configuration saved to {}", path.display());
    Ok(())
}

/// 删除已保存的配置
/// # Errors
///
/// 删除状态文件失败。
pub fn clear(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("failed to remove state file {}", path.display()))?;
        log::info!("removed state file {}", path.display());
    }
    Ok(())
}
