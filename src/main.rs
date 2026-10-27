//! warpd 主程序
//!
//! 启动顺序（失败即回滚，退出时按逆序清理）：
//!   1. 预检（root / `CAP_NET_ADMIN` / 内核 wireguard）
//!   2. 取得 WARP 配置（复用已存的，或重新注册）
//!   3. netlink 创建并配置 warp0
//!   4. 安装 fwmark 策略路由（table 100 → warp0）
//!   5. 启动 SOCKS5（仅 127.0.0.1）
//!   6. 等待 SIGTERM/SIGINT，然后清理

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};

use warpd::policyrt::{PolicyRouting, RouteManager};
use warpd::socks5::{SocksConfig, SocksServer};
use warpd::warp::{RegistrationMode, WarpConfig};
use warpd::wgnet::{WgInterface, WgManager};
use warpd::{preflight, store};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// 普通消费者模式（匿名免费注册）
    Consumer,
    /// Zero Trust（Teams）模式，需要 --team
    Zerotrust,
}

#[derive(Parser, Debug)]
#[command(
    name = "warpd",
    version,
    about = "Native Rust WARP client: kernel WireGuard via netlink + loopback SOCKS5",
    long_about = "warpd creates a kernel-mode WireGuard interface (warp0) via netlink, connects it to \
Cloudflare WARP, and exposes a loopback-only SOCKS5 proxy whose outbound traffic is forced \
through the tunnel using SO_MARK + policy routing. The main routing table is never modified."
)]
// 命令行开关天然是一组布尔标志（reset/refresh/check_only/cleanup_only/zt_login），
// 拆成子枚举只会让 clap 的用法变得不直观，得不偿失。
#[allow(clippy::struct_excessive_bools)]
struct Cli {
    /// SOCKS5 listen address. Must be a loopback address.
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: SocketAddr,

    /// `SO_MARK` value applied to outbound sockets (hex allowed, e.g. 0x1)
    #[arg(long, default_value = "0x1", value_parser = parse_mark)]
    mark: u32,

    /// Policy routing table id (independent from main table)
    #[arg(long, default_value_t = 100)]
    table: u32,

    /// Kernel `WireGuard` interface name
    #[arg(long, default_value = "warp0")]
    iface: String,

    /// Interface MTU
    #[arg(long, default_value_t = 1280)]
    mtu: u32,

    /// Registration mode
    #[arg(long, value_enum, default_value_t = Mode::Consumer)]
    mode: Mode,

    /// Zero Trust team name (only used to print the portal URL where you obtain a JWT)
    #[arg(long)]
    team: Option<String>,

    /// Zero Trust Access JWT (required with --mode zerotrust).
    /// Obtain it by logging in at https://<team>.cloudflareaccess.com/warp
    #[arg(long, env = "WARPD_ZT_JWT", hide_env_values = true)]
    zt_jwt: Option<String>,

    /// Interactive Zero Trust login: prints the authentication link, waits for you
    /// to paste the JWT from your browser, then registers and saves the config.
    /// Like the official WARP client: "here is a link, sign in, done".
    #[arg(long)]
    zt_login: bool,

    /// Path to the state file holding the WARP config
    #[arg(long)]
    state: Option<PathBuf>,

    /// Force re-registration, ignoring any saved config
    #[arg(long)]
    reset: bool,

    /// Periodically re-fetch the device config from Cloudflare while running,
    /// so a server-side address change (common with Zero Trust) is picked up
    /// without a restart. Accepts s/m/h/d suffixes, e.g. `--sync-interval 1h`,
    /// `--sync-interval 6h`, `--sync-interval 1d`. Use `off` to disable.
    /// Default: 1h.
    #[arg(long, default_value = "1h")]
    sync_interval: String,

    /// Refresh the saved device config from Cloudflare before starting.
    /// Useful for Zero Trust, whose assigned IPv6 can change server-side;
    /// a stale IPv6 makes v6 traffic fail. No browser login needed — it reuses
    /// the stored device id and access token.
    #[arg(long)]
    refresh: bool,

    /// Connect timeout for outbound SOCKS5 dials (seconds)
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,

    /// Timeout for the whole SOCKS5 handshake (greeting + request + outbound dial),
    /// in seconds. Prevents half-open clients from pinning file descriptors.
    #[arg(long, default_value_t = 60)]
    handshake_timeout: u64,

    /// Maximum number of concurrent SOCKS5 connections
    #[arg(long, default_value_t = 1024)]
    max_connections: usize,

    /// Don't touch the network: only validate preflight checks and exit
    #[arg(long)]
    check_only: bool,

    /// Only remove leftover kernel state (routes, rules, interface) and exit.
    /// Useful as a systemd `ExecStopPost`= safety net after an unclean death
    /// (SIGKILL, panic, OOM) where normal cleanup never ran.
    #[arg(long)]
    cleanup_only: bool,
}

/// 解析 mark，支持 0x 前缀的十六进制。
///
/// 安全性要求：mark 绝对不能是 0。
/// 因为 fwmark 规则匹配「等于 0」时会命中**所有未打标的流量**，包括
/// `WireGuard` 自己发往 endpoint 的加密 UDP 包（我们刻意让它不带 mark）。
/// 那样一来加密包会被再次导入隧道，形成自锁环路，宿主机会直接失去网络
/// 且无法自愈（因为规则在启动时就装上了）。
fn parse_mark(s: &str) -> Result<u32, String> {
    let t = s.trim();
    let v = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("invalid hex mark {s:?}: {e}"))?
    } else {
        t.parse::<u32>()
            .map_err(|e| format!("invalid mark {s:?}: {e}"))?
    };
    if v == 0 {
        return Err(
            "SO_MARK must not be 0: a fwmark rule matching 0 would capture every \
             unmarked packet (including WireGuard's own encrypted UDP) and lock the \
             host out of the network. Use a non-zero mark such as 0x1."
                .to_string(),
        );
    }
    Ok(v)
}

/// 解析周期参数：支持 `30s` / `5m` / `1h` / `2d` / `off`。
///
/// 为什么需要周期同步：WARP（尤其 Zero Trust）会由服务端重新分配 IPv6
/// 甚至换 peer 配置。本地配置一旦过期，隧道里对应地址的流量就不通。
/// 定期 `GET /reg/{id}` 拉一次最新配置是成本极低的对策。
fn parse_interval(s: &str) -> Result<Option<Duration>, String> {
    // 下限：太频繁会被 Cloudflare 限流（429）。
    const MIN_SECS: u64 = 60;
    // 上限：超过一年没有实际意义，且让配置更易读地报错。
    const MAX_SECS: u64 = 365 * 86400;
    let t = s.trim().to_ascii_lowercase();
    if matches!(t.as_str(), "off" | "none" | "never" | "0") {
        return Ok(None);
    }
    let (num, unit) = t.split_at(
        t.find(|c: char| c.is_ascii_alphabetic())
            .ok_or_else(|| format!("interval {s:?} needs a unit, e.g. 1h"))?,
    );
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("interval value {num:?} is not a number"))?;
    if n == 0 {
        return Ok(None);
    }
    // 用 checked_mul 而不是直接乘：release 构建下整数溢出是静默回绕的。
    // 例如 --sync-interval 213503982334601d 会回绕成几秒，然后疯狂打 WARP
    // API 直到被 429 封掉。这里宁可明确报错。
    let mult: u64 = match unit.trim() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600,
        "d" | "day" | "days" => 86400,
        other => return Err(format!("unknown interval unit {other:?}")),
    };
    let secs = n
        .checked_mul(mult)
        .ok_or_else(|| format!("interval {s:?} overflows"))?;
    if secs < MIN_SECS {
        return Err(format!(
            "interval must be at least {MIN_SECS}s to avoid Cloudflare rate limiting"
        ));
    }
    if secs > MAX_SECS {
        return Err(format!("interval must not exceed {}d", MAX_SECS / 86400));
    }
    Ok(Some(Duration::from_secs(secs)))
}

/// 校验策略路由表号是否安全。
///
/// 必须避开 Linux 的保留表：
///   0     = unspec
///   253   = default
///   254   = main     ← 用了就直接污染主路由表，违反本项目硬约束
///   255   = local
/// 另外必须 <= 255，因为 netlink 的 RuleHeader.table 是 u8；超过 255 时
/// rtnetlink 会把它塞进属性，导致我们自己的清理逻辑按 header.table 匹配不上，
/// 规则会一次次叠加删不掉。
fn validate_table(table: u32) -> Result<()> {
    const RESERVED: &[(u32, &str)] = &[
        (0, "unspec"),
        (253, "default"),
        (254, "main"),
        (255, "local"),
    ];
    if let Some((_, name)) = RESERVED.iter().find(|(v, _)| *v == table) {
        bail!(
            "--table {table} is the reserved '{name}' table. warpd must use a private table \
             (default 100) so the main routing table stays untouched."
        );
    }
    if table > 255 {
        bail!(
            "--table {table} exceeds 255. The kernel's rule header stores the table in a u8, \
             so values above 255 cannot be matched back during cleanup and rules would \
             accumulate on every restart. Pick a private table in 1..=252 (default 100)."
        );
    }
    if table == 0 {
        bail!("--table 0 is not a valid routing table");
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    // 日志：默认 info
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    // 关键：信号处理器必须在**任何耗时操作之前**装好。
    // 否则从进程启动到 run() 里第一次 poll shutdown_signal() 之间有一个
    // 「裸奔窗口」（WARP 注册最坏可达数分钟）。在这个窗口里收到 SIGTERM
    // 会被默认处置直接杀死，清理代码一点机会都没有，会永久留下
    // warp0 + fwmark 规则 + table 100 路由，其中那条规则会把所有
    // mark 命中的流量黑洞掉。
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    spawn_signal_handlers(shutdown_tx);

    // 若启动过程中被要求退出，run() 内部会通过 shutdown_rx 感知并回滚。
    if let Err(e) = run(shutdown_rx).await {
        log::error!("fatal: {e:#}");
        // 明确以非 0 退出，方便 systemd Restart=on-failure 生效
        std::process::exit(1);
    }
}

/// 立刻安装 SIGTERM / SIGINT 处理器，把「需要退出」广播出去。
fn spawn_signal_handlers(tx: tokio::sync::watch::Sender<bool>) {
    use tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => Some(s),
            Err(e) => {
                log::warn!("could not install SIGTERM handler: {e}");
                None
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => Some(s),
            Err(e) => {
                log::warn!("could not install SIGINT handler: {e}");
                None
            }
        };

        let why = match (&mut sigterm, &mut sigint) {
            (Some(t), Some(i)) => tokio::select! {
                _ = t.recv() => "SIGTERM",
                _ = i.recv() => "SIGINT",
            },
            (Some(t), None) => {
                t.recv().await;
                "SIGTERM"
            }
            (None, Some(i)) => {
                i.recv().await;
                "SIGINT"
            }
            (None, None) => {
                // 两个都装不上，退化成只能等 Ctrl+C
                let _ = tokio::signal::ctrl_c().await;
                "CTRL_C"
            }
        };

        log::info!("received {why}, requesting shutdown");
        let _ = tx.send(true);
    });
}

/// 创建内核 `WireGuard` 接口并安装策略路由，返回 `(ifindex, 清理上下文)`。
///
/// 关键：整个过程中所有创建的资源都由 [`BootGuard`] 托管。无论在哪一步
/// 失败（`?` 提前返回、panic、bail!），Drop 都会依次回滚「路由 → 接口」，
/// 绝不留下半残状态——尤其是那条会把带 mark 流量导入死隧道的 fwmark 规则。
///
/// # Errors
///
/// 配置校验失败、创建接口失败、添加地址失败，或安装策略路由失败。
/// 启动窗口内收到退出信号时也会返回错误（不触碰网络）。
async fn bring_up_tunnel(
    cli: &Cli,
    warp_cfg: &WarpConfig,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) -> Result<(u32, CleanupCtx)> {
    let mut boot = BootGuard::new(cli.iface.clone(), cli.mark, cli.table);

    // 启动窗口内也要能响应退出请求
    if *shutdown_rx.borrow() {
        bail!("shutdown requested during startup, aborting before touching the network");
    }

    // 先校验配置，避免带着坏数据去动内核
    warp_cfg
        .validate()
        .context("WARP configuration is not usable")?;

    let mut wg = WgManager::new()?;

    let iface = WgInterface {
        name: cli.iface.clone(),
        mtu: cli.mtu,
        config: warp_cfg.clone(),
    };
    let ifindex = wg
        .setup(&iface)
        .await
        .context("failed to set up kernel WireGuard interface")?;
    boot.ifindex = Some(ifindex);
    log::debug!("boot guard armed with ifindex {ifindex}");

    let route_cfg = PolicyRouting::new(cli.mark, cli.table, cli.iface.clone());
    let routes = RouteManager::new(wg.handle().clone());
    routes
        .install(&route_cfg, ifindex)
        .await
        .context("failed to install policy routing")?;
    boot.routing_installed = true;

    // 启动完成，守卫解除（后续由显式 cleanup 负责）
    boot.disarm();

    Ok((
        ifindex,
        CleanupCtx {
            routes,
            route_cfg,
            ifindex,
            iface_name: cli.iface.clone(),
        },
    ))
}

/// 仅清理内核残留（--cleanup-only）
///
/// 这是「不干净死亡」的兜底：panic=abort / SIGKILL / OOM 都会跳过正常清理
/// 路径，留下 `warp0` + fwmark rule + table 路由。其中那条 rule 会把所有
/// 带 mark 的流量导入死隧道，属于必须清除的状态。systemd unit 用
/// `ExecStopPost=` 调用它，保证服务停下时内核状态一定干净。
async fn do_cleanup_only(cli: &Cli) {
    log::info!("--cleanup-only: removing leftover kernel state");
    cleanup_leftovers(&cli.iface, cli.mark, cli.table).await;
    log::info!("--cleanup-only: done");
}

/// 校验命令行参数并把 `--sync-interval` 解析成 `Duration`。
///
/// 抽成独立函数有两个好处：`run()` 保持可读（它本来就很长了），
/// 而且 `--check-only` 这条只读路径也能覆盖到全部参数校验。
///
/// # Errors
///
/// SOCKS 监听地址不是 loopback、表号命中保留表或超过 255、
/// mark 为 0，或 --sync-interval 无法解析。
fn validate_cli(cli: &Cli) -> Result<Option<Duration>> {
    // SOCKS 只能监听 loopback
    SocksServer::validate_bind(&cli.socks)?;
    // 表号不能是 main/default/local，也不能 >255（否则清理失效）
    validate_table(cli.table)?;
    // mark 已在 parse_mark 里保证非 0，这里再兜一层（防止将来改默认值）
    if cli.mark == 0 {
        bail!("SO_MARK must not be 0 (it would capture WireGuard's own encrypted UDP)");
    }
    // 周期同步参数在这里就解析，好让 --check-only 也能报出非法值
    parse_interval(&cli.sync_interval).map_err(|e| anyhow::anyhow!("invalid --sync-interval: {e}"))
}

async fn run(mut shutdown_rx: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    let cli = Cli::parse();

    // ---- 0a. 参数安全校验 ----
    let sync_interval = validate_cli(&cli)?;

    // ---- 1. 预检 ----
    log::info!("warpd v{} starting", env!("CARGO_PKG_VERSION"));
    preflight::run_all().context("preflight checks failed")?;

    // --check-only 是纯只读探测：它不该占用单实例锁，否则一次本该
    // 无副作用的预检会在 /tmp 留下 flock 文件，也可能被正在运行的服务
    // 误判成「已有实例」而失败。所以放在拿锁之前。
    if cli.check_only {
        log::info!("preflight checks passed (--check-only, exiting)");
        return Ok(());
    }

    // ---- 1b. 单实例锁 ----
    // warpd 会独占一个接口名 + 一张策略路由表，两个实例同时跑会互相破坏
    // （第二个实例要么 EEXIST，要么把第一个的规则覆盖掉）。这里用 flock
    // 提前拦住，比建完接口才失败要清楚得多。
    let _instance_lock = match InstanceLock::acquire(&cli.iface) {
        Ok(l) => l,
        Err(e) => {
            bail!(
                "another warpd instance appears to be running (lock for interface '{}' is held): {}. \
                 Stop it first, or use a different --iface/--table.",
                cli.iface,
                e
            )
        }
    };

    // ---- 仅清理模式 ----
    // 这是「不干净死亡」的兜底：panic=abort / SIGKILL / OOM 都会跳过
    // 正常清理路径，留下 warp0 + fwmark rule + table 100 路由。
    // 其中那条 rule 会把所有带 mark 的流量导入死隧道，属于必须清除的状态。
    // systemd unit 用 ExecStopPost= 调用它，保证服务停下时内核状态一定干净。
    if cli.cleanup_only {
        do_cleanup_only(&cli).await;
        return Ok(());
    }

    // ---- Zero Trust 交互式登录 ----
    if cli.zt_login {
        do_zt_login(&cli).await?;
        return Ok(());
    }

    // ---- 2. 取得 WARP 配置 ----
    let state_path = cli.state.clone().unwrap_or_else(store::default_path);
    let warp_cfg = obtain_warp_config(&cli, &state_path).await?;
    log::info!(
        "WARP config ready: endpoint={} address={}/32",
        warp_cfg.endpoint,
        warp_cfg.address_v4
    );

    // ---- 3+4. 内核 WireGuard 与策略路由 ----
    let (ifindex, cleanup_ctx) = bring_up_tunnel(&cli, &warp_cfg, &shutdown_rx).await?;

    // ---- 5. SOCKS5 ----
    let socks_cfg = SocksConfig {
        listen: cli.socks,
        mark: cli.mark,
        connect_timeout: Duration::from_secs(cli.connect_timeout),
        // 握手（协商+请求+出站建连）整体超时
        handshake_timeout: Duration::from_secs(cli.handshake_timeout),
        // 并发连接上限，防 fd 耗尽
        max_connections: cli.max_connections,
    };
    let server = SocksServer::new(socks_cfg);

    // 先探测一下端口能否绑定，绑定失败要回滚接口与路由，
    // 而不是留下一个「隧道建好了但没有代理」的进程。
    if let Err(e) = tokio::net::TcpListener::bind(cli.socks).await {
        log::error!("cannot bind SOCKS5 listener on {}: {}", cli.socks, e);
        cleanup_ctx.cleanup().await;
        return Err(e).context("SOCKS5 listener bind failed (rolled back tunnel)");
    }

    log_startup_banner(&cli, ifindex);

    // ---- 6. 等待信号，然后清理 ----
    // 记录是否是「非正常退出」，决定最终退出码。
    // 这点很关键：systemd unit 用 Restart=on-failure，如果 SOCKS 线程崩了
    // 我们还返回 exit code 0，systemd 会认为服务正常结束、永不重启，
    // 结果是隧道还在但代理已死，且无人知晓。
    let mut exit_result: Result<()> = Ok(());

    // ---- 周期同步服务端配置 ----
    // WARP（尤其 Zero Trust）会由服务端重新分配地址。定时拉一次最新配置并
    // 原地更新内核 peer（不重建接口、不断流），比让用户手动重启友好得多。
    let sync_handle = sync_interval.map(|interval| {
        let state = state_path.clone();
        let iface = cli.iface.clone();
        let mut sd = shutdown_rx.clone();
        log::info!(
            "periodic config sync enabled: every {}",
            humantime_short(interval)
        );
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(interval) => {}
                    _ = sd.changed() => {
                        log::debug!("config sync stopped (shutdown)");
                        return;
                    }
                }
                match periodic_sync(&state, &iface).await {
                    Ok(true) => log::info!("config sync: updated peer on {iface}"),
                    Ok(false) => log::debug!("config sync: no change"),
                    Err(e) => log::warn!("config sync failed (will retry): {e:#}"),
                }
            }
        })
    });

    tokio::select! {
        res = server.run() => {
            if let Err(e) = res {
                log::error!("SOCKS5 server stopped unexpectedly: {e:#}");
                exit_result = Err(e).context("SOCKS5 server terminated");
            }
        }
        _ = shutdown_rx.changed() => {
            log::info!("shutdown requested, stopping SOCKS5 listener");
        }
    }

    // 停掉后台同步
    if let Some(h) = sync_handle {
        h.abort();
    }

    // 清理（顺序：listener 已随 select 结束，接着 rule/route，最后接口）
    cleanup_ctx.cleanup().await;

    exit_result
}

/// 打印启动横幅（把这段从 `run()` 抽出来，避免单函数过长）
fn log_startup_banner(cli: &Cli, ifindex: u32) {
    log::info!("=====================================================");
    log::info!("warpd is up");
    log::info!("  interface : {} (ifindex {})", cli.iface, ifindex);
    log::info!("  socks5    : {}", cli.socks);
    log::info!("  so_mark   : {:#x} -> table {}", cli.mark, cli.table);
    log::info!("  mode      : {:?}", cli.mode);
    log::info!("=====================================================");
}

/// 把 Duration 渲染成人能读的短字符串
fn humantime_short(d: Duration) -> String {
    let s = d.as_secs();
    if s % 86400 == 0 {
        format!("{}d", s / 86400)
    } else if s % 3600 == 0 {
        format!("{}h", s / 3600)
    } else if s % 60 == 0 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

/// 周期同步：重新拉取服务端配置，若有变化则原地更新内核。
///
/// 返回 Ok(true) 表示确实更新了，Ok(false) 表示无变化。
///
/// 关键设计：**不重建接口**。只把新的 endpoint / peer 公钥 / allowed-ips
/// 以及**接口地址**重新下发给内核，接口本身和策略路由保持不变，因此不会断流。
///
/// 为什么要更新地址而不只是 peer：Zero Trust 组织里服务端会重新分配 IPv6。
/// 只改 peer 的话，接口上挂着的是旧地址、新地址从未被加上，v6 流量会一直
/// 不通 —— 这种「看起来同步成功了、实际却没修好」是最难排查的。
async fn periodic_sync(state_path: &std::path::Path, iface: &str) -> Result<bool> {
    let Some(current) = store::load(state_path)? else {
        return Ok(false);
    };

    if current.device_id.is_empty() || current.access_token.is_empty() {
        return Err(anyhow::anyhow!(
            "cannot sync: saved config has no device_id/access_token"
        ));
    }

    let fresh = warpd::warp::refresh_config(&current).await?;

    // 分开判断两类变化，原因见下面的注释。
    let addr_changed =
        fresh.address_v4 != current.address_v4 || fresh.address_v6 != current.address_v6;
    let peer_changed =
        fresh.peer_public_key != current.peer_public_key || fresh.endpoint != current.endpoint;

    if !addr_changed && !peer_changed {
        return Ok(false);
    }

    // 原地更新内核（接口本身和策略路由都不动）
    let mut wg = WgManager::new()?;

    // 1. 先改地址。
    // Zero Trust 服务端会重新分配 IPv6，而「只更新 peer」修不好这种情况——
    // 接口上还是旧地址，新地址从未被加上，v6 流量照旧不通。
    if addr_changed {
        wg.update_addresses(iface, &current, &fresh).await?;
    }

    // 2. 只有 peer 真的变了才重设 peer。
    // 这一步不能无条件执行：重设 endpoint 会让内核作废旧会话并强制重新握手，
    // 也就是有一次真实的短暂断流。仅仅地址变化时完全没必要付这个代价。
    if peer_changed {
        wg.update_peer(iface, &fresh).await?;
    }

    // 落盘放在内核更新成功之后：否则会出现「磁盘上是新配置、内核里是旧配置」
    // 的不一致状态，下次启动还会把错的当成对的。
    store::save(state_path, &fresh)?;

    Ok(true)
}

/// 交互式 Zero Trust 登录（--zt-login）
///
/// 与官方 WARP 客户端一致的体验：打印认证链接 → 用户在浏览器登录 →
/// 粘贴 JWT → 注册并保存配置。
///
/// # Errors
///
/// 缺少 --team、注册被 Cloudflare 拒绝，或配置无法保存。
async fn do_zt_login(cli: &Cli) -> Result<()> {
    let state_path = cli.state.clone().unwrap_or_else(store::default_path);
    let team = cli
        .team
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--zt-login requires --team <your-team-name>"))?;
    let cfg = interactive_zt_login(&team, &state_path, cli.reset).await?;
    log::info!("Zero Trust login complete: {}", cfg.summarize());
    log::info!(
        "configuration saved to {}. Now start the tunnel with: warpd",
        state_path.display()
    );
    Ok(())
}

/// 取得 WARP 配置：优先复用已保存的，否则注册
async fn obtain_warp_config(cli: &Cli, state_path: &std::path::Path) -> Result<WarpConfig> {
    // 注意：这里**不**提前检查 JWT。
    // 原因：Zero Trust 注册成功后配置会落盘，之后每次启动都直接复用，
    // 完全不需要再给 JWT。若在读取缓存之前就强制要求 JWT，会导致
    // 「已经注册过却启动不了」这种荒谬状况。JWT 只在真正要注册时才需要，
    // 检查放在下面的注册分支里。

    if cli.reset {
        log::info!("--reset given, ignoring saved configuration");
        store::clear(state_path).ok();
    } else {
        // 注意：损坏的状态文件不应该让守护进程直接退出。
        // 对 systemd 服务来说，「配置坏了 → 自动重新注册」远比「启动失败 →
        // 进入 restart 循环且永远起不来」要好。所以这里把解析失败降级成警告，
        // 继续走重新注册路径（并把坏文件备份下来便于排查）。
        match store::load(state_path) {
            Ok(Some(cfg)) => {
                if cli.refresh {
                    log::info!("--refresh: fetching the latest device config from Cloudflare");
                    match warpd::warp::refresh_config(&cfg).await {
                        Ok(fresh) => {
                            if let Err(e) = store::save(state_path, &fresh) {
                                log::warn!("could not persist refreshed config: {e:#}");
                            }
                            log::info!("configuration refreshed");
                            return Ok(fresh);
                        }
                        Err(e) => {
                            // 刷新失败不致命：继续用旧配置，总比起不来好
                            log::warn!(
                                "refresh failed ({e}); continuing with the saved configuration"
                            );
                            return Ok(cfg);
                        }
                    }
                }
                log::info!(
                    "reusing saved WARP configuration from {} (use --reset to re-register, --refresh to update)",
                    state_path.display()
                );
                return Ok(cfg);
            }
            Ok(None) => {
                log::info!("no saved WARP configuration, will register a new device");
            }
            Err(e) => {
                log::warn!(
                    "saved configuration at {} is unusable ({}); backing it up and re-registering",
                    state_path.display(),
                    e
                );
                let bak = state_path.with_extension("json.corrupt");
                if let Err(be) = std::fs::rename(state_path, &bak) {
                    log::warn!("could not back up corrupt state file: {be}");
                    store::clear(state_path).ok();
                } else {
                    log::info!("corrupt state backed up to {}", bak.display());
                }
            }
        }
    }

    let mode = match cli.mode {
        Mode::Consumer => RegistrationMode::Consumer,
        Mode::Zerotrust => {
            // JWT 只在「确实需要注册新设备」时才必需；
            // 已有保存配置的情况在上面已经 return 了，走不到这里。
            let jwt = match cli.zt_jwt.clone() {
                Some(j) if !j.trim().is_empty() => j,
                _ => {
                    let hint = cli
                        .team
                        .as_deref().map_or_else(|| {
                            "\n\n  Tip: run `warpd --zt-login --team <your-team>` for a guided flow."
                                .to_string()
                        }, |t| {
                            let team = warpd::warp::normalize_team(t);
                            let link = warpd::warp::zero_trust_portal_url(&team);
                            format!(
                                "\n\n  Sign in at {link}\n  then copy the JWT and pass --zt-jwt <jwt>,\n  or simply run: warpd --zt-login --team {team}"
                            )
                        });
                    bail!(
                        "--mode zerotrust needs a JWT to enroll this device, but none was provided \
                         (--zt-jwt or WARPD_ZT_JWT).{hint}"
                    );
                }
            };
            RegistrationMode::ZeroTrust { jwt }
        }
    };

    log::info!("registering with Cloudflare WARP ({:?} mode)", cli.mode);
    let cfg = warpd::warp::register(mode)
        .await
        .context("WARP registration failed")?;

    // 保存以便下次复用
    if let Err(e) = store::save(state_path, &cfg) {
        log::warn!("could not persist WARP configuration: {e:#}");
    }

    Ok(cfg)
}

/// 清理上下文：确保 rule/route/接口按序删除
struct CleanupCtx {
    routes: RouteManager,
    route_cfg: PolicyRouting,
    ifindex: u32,
    iface_name: String,
}

/// 启动守卫：在 setup/install 全部成功之前，任何提前返回（? 运算符、
/// panic、bail!）都会触发 Drop，把已经创建的内核资源删干净。
///
/// 这是 H2 的修复：原实现只在路由装好之后才构造 `CleanupCtx`，
/// 导致 `setup()` 成功但后续任一环节失败时会残留 warp0 / rule / 路由。
/// 其中残留的 fwmark 规则会把所有带该 mark 的流量导入一个无人维护的隧道。
struct BootGuard {
    iface_name: String,
    mark: u32,
    table: u32,
    ifindex: Option<u32>,
    routing_installed: bool,
    armed: bool,
}

impl BootGuard {
    fn new(iface_name: String, mark: u32, table: u32) -> Self {
        Self {
            iface_name,
            mark,
            table,
            ifindex: None,
            routing_installed: false,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BootGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        log::warn!(
            "startup did not complete; rolling back kernel state for {}",
            self.iface_name
        );

        // Drop 里不能 await，只能同步尽力清理。
        // 更彻底的清理由 --cleanup-only 子命令兜底（systemd ExecStopPost 调用）。
        rollback_blocking(&self.iface_name, self.mark, self.table);
    }
}

/// 同步兜底清理：用子进程方式执行，避免在 Drop 里做异步 netlink。
/// 之所以能做同步，是因为这些都是独立的短命令，且失败也无害。
fn rollback_blocking(iface: &str, mark: u32, table: u32) {
    // 先删策略路由（顺序很重要：先摘规则，才不会拦截流量）
    let cmds: Vec<(&str, Vec<String>)> = vec![
        (
            "ip",
            vec![
                "rule".into(),
                "del".into(),
                "fwmark".into(),
                format!("{:#x}", mark),
                "table".into(),
                table.to_string(),
            ],
        ),
        (
            "ip",
            vec![
                "-6".into(),
                "rule".into(),
                "del".into(),
                "fwmark".into(),
                format!("{:#x}", mark),
                "table".into(),
                table.to_string(),
            ],
        ),
        (
            "ip",
            vec![
                "route".into(),
                "flush".into(),
                "table".into(),
                table.to_string(),
            ],
        ),
        (
            "ip",
            vec![
                "-6".into(),
                "route".into(),
                "flush".into(),
                "table".into(),
                table.to_string(),
            ],
        ),
        ("ip", vec!["link".into(), "del".into(), iface.into()]),
    ];

    for (prog, args) in cmds {
        match std::process::Command::new(prog).args(&args).output() {
            Ok(o) if o.status.success() => {
                log::debug!("rollback: {} {} ok", prog, args.join(" "));
            }
            Ok(o) => {
                log::debug!(
                    "rollback: {} {} -> {}",
                    prog,
                    args.join(" "),
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => log::debug!("rollback: could not run {prog}: {e}"),
        }
    }
    log::info!("rollback finished for {iface}");
}

impl CleanupCtx {
    async fn cleanup(&self) {
        log::info!("cleaning up...");

        // 1. 策略路由（rule + table 内路由）
        if let Err(e) = self.routes.cleanup(&self.route_cfg, self.ifindex).await {
            log::warn!("failed to clean up policy routing: {e:#}");
        } else {
            log::info!("policy routing removed");
        }

        // 2. 接口本身
        let mut wg = match WgManager::new() {
            Ok(w) => w,
            Err(e) => {
                log::warn!("could not reopen netlink to remove interface: {e:#}");
                return;
            }
        };
        if let Err(e) = wg.teardown(&self.iface_name).await {
            log::warn!("failed to remove interface {}: {:#}", self.iface_name, e);
        }

        log::info!("cleanup complete");
    }
}

/// 交互式 Zero Trust 登录向导
///
/// 流程（与 Cloudflare 官方 WARP 客户端一致）：
///   1. 打印认证链接（并先探测 team 是否存在，给出明确反馈）
///   2. 用户在任意已登录 Cloudflare 的浏览器里打开该链接完成登录
///   3. 从浏览器复制 JWT 粘回终端
///   4. warpd 用该 JWT 调 WARP 注册 API，成功则保存配置
///
/// 为什么必须由用户粘贴 JWT：JWT 由 Cloudflare 用私钥签名，服务端严格验签，
/// 客户端无法伪造（伪造会得到 invalid claim type）。这一步是协议限制。
async fn interactive_zt_login(
    team: &str,
    state_path: &std::path::Path,
    reset: bool,
) -> Result<WarpConfig> {
    use std::io::{BufRead, Write};

    // 已经登录过且不要求重置，直接复用
    if reset {
        store::clear(state_path).ok();
    } else if let Some(cfg) = store::load(state_path)? {
        log::info!(
            "already have a saved Zero Trust configuration at {} (use --reset to re-enroll)",
            state_path.display()
        );
        return Ok(cfg);
    }

    let team_norm = warpd::warp::normalize_team(team);
    let portal = warpd::warp::zero_trust_portal_url(&team_norm);

    // 先探测 team，避免用户白跑一趟浏览器
    print!("\nChecking Zero Trust team '{team_norm}'... ");
    let _ = std::io::stdout().flush();
    match warpd::warp::check_team_exists(&team_norm).await {
        Ok(true) => println!("OK"),
        Ok(false) => {
            println!("NOT FOUND");
            bail!(
                "Zero Trust team '{team_norm}' does not exist (or WARP is not enabled for it). \n\
                 Verify the team name in Cloudflare Zero Trust dashboard > Settings > Team name,\n\
                 and make sure 'WARP' is enabled under Settings > WARP Client."
            );
        }
        Err(e) => {
            println!("could not verify ({e})");
            log::warn!("continuing without team verification");
        }
    }

    println!();
    println!("──────────────────────────────────────────────────────────────");
    println!("  1. Open this link in a browser where you are signed in to");
    println!("     Cloudflare (your Zero Trust organization):");
    println!();
    println!("     {portal}");
    println!();
    println!("  2. Sign in. The page will show a 'warp' redirect containing");
    println!("     a JWT (a long string starting with 'eyJ...').");
    println!("     If it does not redirect, copy the jwt= value from the URL,");
    println!("     or run this in the browser console:");
    println!();
    println!("       document.querySelector(\"meta[http-equiv='refresh']\")?.content");
    println!();
    println!("  3. Paste the JWT below and press Enter.");
    println!("──────────────────────────────────────────────────────────────");
    println!();

    print!("JWT: ");
    let _ = std::io::stdout().flush();

    let mut jwt = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut jwt)
        .context("failed to read JWT from stdin")?;
    let jwt = jwt.trim().to_string();

    if jwt.is_empty() {
        bail!("no JWT provided");
    }
    // 容错：用户可能把整个 URL 粘进来
    let jwt = extract_jwt(&jwt);

    if !jwt.starts_with("eyJ") {
        bail!(
            "that does not look like a JWT (it should start with 'eyJ'). \n\
             Make sure you copied the full token, not a partial string."
        );
    }

    println!();
    println!("Registering this device with WARP using your Zero Trust identity...");

    let cfg = warpd::warp::register(warpd::warp::RegistrationMode::ZeroTrust { jwt: jwt.clone() })
        .await
        .context("Zero Trust registration failed")?;

    store::save(state_path, &cfg)?;
    println!();
    println!("✔ Zero Trust registration successful");
    println!("  endpoint : {}", cfg.endpoint);
    println!("  address  : {}/32", cfg.address_v4);
    println!("  saved to : {}", state_path.display());
    println!();
    println!("Now start the tunnel with:  warpd");

    Ok(cfg)
}

/// 从用户粘贴的内容里提取 JWT。
/// 支持三种形式：裸 JWT、包含 jwt=... 的 URL、meta refresh 的 content 值。
fn extract_jwt(input: &str) -> String {
    let s = input.trim().trim_matches('"').trim_matches('\'');

    // 已经是裸 JWT
    if s.starts_with("eyJ") && !s.contains(' ') && !s.contains('=') {
        return s.to_string();
    }

    // URL 里找 jwt=
    if let Some(pos) = s.find("jwt=") {
        let rest = &s[pos + 4..];
        let end = rest.find(['&', ' ', '"', '\'']).unwrap_or(rest.len());
        let tok = &rest[..end];
        // URL 解码（jwt 里可能有 %2B 等，但通常是 base64url，直接可用）
        return url_decode(tok);
    }

    // 形如 "...com.cloudflare.warp://...?jwt=..." 已经覆盖
    s.to_string()
}

/// 极简 percent-decoding（JWT 里基本不会用到，但保险）
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                }
            };
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 彻底清除 warpd 可能留下的内核状态（幂等，可重复执行）
async fn cleanup_leftovers(iface: &str, mark: u32, table: u32) {
    // 先删策略路由：先摘规则，避免在删除接口的过程中流量被黑洞
    let mut wg = match WgManager::new() {
        Ok(w) => w,
        Err(e) => {
            log::error!("cannot open netlink to clean up: {e:#}");
            return;
        }
    };

    let idx = wg.find_index(iface).await.ok().flatten();
    let route_cfg = PolicyRouting::new(mark, table, iface.to_string());
    let routes = RouteManager::new(wg.handle().clone());

    // 即使拿不到 ifindex 也要尝试删 rule（rule 不依赖 ifindex）
    match routes.cleanup(&route_cfg, idx.unwrap_or(0)).await {
        Ok(()) => log::info!("policy routing cleaned (table {table})"),
        Err(e) => log::warn!("policy routing cleanup issue: {e:#}"),
    }

    if idx.is_some() {
        match wg.teardown(iface).await {
            Ok(()) => log::info!("interface {iface} removed"),
            Err(e) => log::warn!("could not remove interface {iface}: {e:#}"),
        }
    } else {
        log::info!("interface {iface} not present, nothing to remove");
    }

    // 最后用 ip 命令兜底刷一遍独立表（防止有我们没识别的残留路由）
    let _ = std::process::Command::new("ip")
        .args(["route", "flush", "table", &table.to_string()])
        .output();
    let _ = std::process::Command::new("ip")
        .args(["-6", "route", "flush", "table", &table.to_string()])
        .output();
}

/// 单实例锁（基于 flock 的文件锁，进程退出自动释放）
struct InstanceLock {
    _file: std::fs::File,
}

impl InstanceLock {
    fn acquire(iface: &str) -> Result<Self> {
        use std::io::Write;
        use std::os::fd::AsRawFd;

        // 用接口名区分，允许用户在不同接口上并行跑多个实例（高级用法）
        let safe: String = iface
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = format!("/tmp/warpd-{safe}.lock");

        // 注意：这里**不能** truncate，因为要先拿到 flock 才能安全改写内容；
        // 若在加锁前就截断，会把另一个正在运行的实例的 pid 记录抹掉。
        // 拿到锁之后再用 set_len(0) 清空并写入自己的 pid。
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("failed to open lock file {path}"))?;

        // LOCK_EX | LOCK_NB：非阻塞独占锁
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // 把自己的 pid 写进锁文件，方便排查
            return Err(anyhow::anyhow!("{err}"));
        }

        // 记录持有者
        let mut f = &file;
        let _ = f.set_len(0);
        let _ = writeln!(f, "{}", std::process::id());

        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mark_hex() {
        assert_eq!(parse_mark("0x1").unwrap(), 1);
        assert_eq!(parse_mark("0x10").unwrap(), 16);
        assert_eq!(parse_mark("0XFF").unwrap(), 255);
    }

    #[test]
    fn test_parse_mark_decimal() {
        assert_eq!(parse_mark("1").unwrap(), 1);
        assert_eq!(parse_mark("255").unwrap(), 255);
    }

    #[test]
    fn test_parse_mark_invalid() {
        assert!(parse_mark("abc").is_err());
        assert!(parse_mark("0xZZ").is_err());
    }

    #[test]
    fn test_mark_zero_is_rejected() {
        // C1: mark 0 会让 fwmark 规则命中所有未打标流量（含 WireGuard 自己的
        // 加密 UDP），导致隧道自锁、整机断网。必须拒绝。
        assert!(parse_mark("0").is_err(), "mark 0 must be rejected");
        assert!(parse_mark("0x0").is_err(), "mark 0x0 must be rejected");
        assert!(parse_mark("0x00").is_err());
    }

    #[test]
    fn test_table_rejects_reserved() {
        // C2: 这些是内核保留表，用了就违反「不污染主路由表」约束
        assert!(validate_table(254).is_err(), "main table must be rejected");
        assert!(
            validate_table(253).is_err(),
            "default table must be rejected"
        );
        assert!(validate_table(255).is_err(), "local table must be rejected");
        assert!(validate_table(0).is_err(), "table 0 must be rejected");
    }

    #[test]
    fn test_table_rejects_over_255() {
        // H8: >255 时 kernel 存不进 u8 header，清理逻辑匹配不上，规则会叠加
        assert!(validate_table(256).is_err());
        assert!(validate_table(1000).is_err());
    }

    #[test]
    fn test_table_accepts_private() {
        assert!(validate_table(100).is_ok());
        assert!(validate_table(200).is_ok());
        assert!(validate_table(252).is_ok());
        assert!(validate_table(1).is_ok());
    }

    #[test]
    fn test_interval_units() {
        assert_eq!(
            parse_interval("1h").unwrap(),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            parse_interval("6h").unwrap(),
            Some(Duration::from_secs(21600))
        );
        assert_eq!(
            parse_interval("1d").unwrap(),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(
            parse_interval("2m").unwrap(),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_interval("90s").unwrap(),
            Some(Duration::from_secs(90))
        );
        // 大小写与空格应被容忍
        assert_eq!(
            parse_interval(" 1H ").unwrap(),
            Some(Duration::from_secs(3600))
        );
    }

    #[test]
    fn test_interval_off() {
        for s in ["off", "none", "never", "0", "OFF"] {
            assert_eq!(parse_interval(s).unwrap(), None, "failed on {s:?}");
        }
    }

    #[test]
    fn test_interval_rejects_garbage() {
        assert!(parse_interval("abc").is_err(), "no unit, not a number");
        assert!(parse_interval("1x").is_err(), "unknown unit");
        assert!(parse_interval("h").is_err(), "no number");
        assert!(parse_interval("-5h").is_err(), "negative");
    }

    #[test]
    fn test_interval_rejects_below_minimum() {
        // 下限 60s：太频繁会被 Cloudflare 429
        assert!(parse_interval("30s").is_err());
        assert!(parse_interval("59s").is_err());
        assert!(parse_interval("1m").is_ok());
    }

    #[test]
    fn test_interval_overflow_is_rejected_not_wrapped() {
        // u64 乘法溢出：在 debug 下 panic、release 下回绕成小数。
        // 回绕会让「4 亿天」变成一个很小的间隔，进而高频打 API。
        // parse_interval 必须返回 Err 而不是静默回绕。
        let huge = format!("{}d", u64::MAX / 1000);
        assert!(
            parse_interval(&huge).is_err(),
            "overflowing interval must be rejected, not wrapped"
        );
    }

    #[test]
    fn test_humantime_short() {
        assert_eq!(humantime_short(Duration::from_secs(60)), "1m");
        assert_eq!(humantime_short(Duration::from_secs(3600)), "1h");
        assert_eq!(humantime_short(Duration::from_secs(86400)), "1d");
        // 非整除的秒数原样输出
        assert_eq!(humantime_short(Duration::from_secs(90)), "90s");
    }

    #[test]
    fn test_extract_jwt() {
        // 裸 JWT
        assert_eq!(
            extract_jwt("eyJhbGciOi.payload.sig"),
            "eyJhbGciOi.payload.sig"
        );
        // 带引号
        assert_eq!(
            extract_jwt("\"eyJhbGciOi.payload.sig\""),
            "eyJhbGciOi.payload.sig"
        );
        // URL 形式
        assert_eq!(
            extract_jwt("https://x.cloudflareaccess.com/warp#jwt=eyJabc.def.ghi&foo=1"),
            "eyJabc.def.ghi"
        );
    }
}
