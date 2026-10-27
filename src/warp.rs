//! Cloudflare WARP 注册与配置获取
//!
//! 支持两种模式：
//! 1. Consumer（普通用户）：向 api.cloudflareclient.com 匿名注册，免费
//! 2. Zero Trust（Teams）：向 <team>.cloudflareaccess.com 注册，需要 team name +
//!    邮箱验证码或 Access JWT
//!
//! 两者最终都产出同一份 `WarpConfig`：`WireGuard` 私钥、peer 公钥、endpoint、
//! 接口地址。这份配置直接喂给 netlink 层写入内核 `WireGuard`。

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::wgkey;

/// WARP 注册 API 的基址。
///
/// 注意：Cloudflare 会下线旧版本号（例如 v0a192c 已 404），所以这里用
/// fallback 列表逐个尝试，不硬编码单一版本。实测 v0a2158 可用。
const API_HOST: &str = "https://api.cloudflareclient.com";

/// 按优先级尝试的 API 版本号
const API_VERSIONS: &[&str] = &["v0a2158", "v0a2483", "v0a4000", "v0a1000"];

/// Zero Trust 获取团队 JWT 的网页地址模板（仅用于提示用户去取 JWT）
const ZT_PORTAL_FMT: &str = "https://{team}.cloudflareaccess.com/warp";

/// 从 WARP 拿到的、可以直接用于内核 `WireGuard` 的配置
// 注意：这里**故意不 derive Debug**。
// WarpConfig 含 WireGuard 私钥，如果 derive(Debug)，任何 {:?} 都会把私钥
// 明文打进 journald / 日志文件。需要打印时用 summarize()。
#[derive(Clone, Serialize, Deserialize)]
pub struct WarpConfig {
    /// `WireGuard` 接口私钥（base64）
    pub private_key: String,
    /// peer 公钥（base64）
    pub peer_public_key: String,
    /// peer endpoint，例如 engage.cloudflareclient.com:2408
    pub endpoint: String,
    /// 接口 IPv4 地址（不带掩码）
    pub address_v4: String,
    /// 接口 IPv6 地址（不带掩码）
    pub address_v6: String,
    /// 可选：预共享密钥
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    /// 注册时 Cloudflare 分配的 client id。
    /// 它是握手包 reserved 字段的来源（base64 解码后 3 字节），也用于诊断。
    #[serde(default)]
    pub client_id: String,
    /// 账号 license（Zero Trust / 迁移设备时用）
    #[serde(default)]
    pub license: String,
    /// 设备 id。用于调 `GET /reg/{id}` 刷新配置。
    ///
    /// 为什么必须存：Zero Trust 的 IPv6 地址会由服务端变更，配置若不刷新，
    /// 旧 IPv6 会导致 v6 不通。usque 的 README 明确提到这一点。
    #[serde(default)]
    pub device_id: String,
    /// 注册时下发的 access token。刷新配置时作为 Bearer 凭据。
    #[serde(default)]
    pub access_token: String,
    /// 账号 TTL（RFC3339 字符串）。快到期的设备建议重新注册。
    #[serde(default)]
    pub account_ttl: String,
}

impl WarpConfig {
    /// 校验一份配置是否可用于建立隧道。
    /// 在碰内核之前就把明显坏掉的配置挡下来，避免留下半配置的接口。
    /// # Errors
    ///
    /// 配置中的密钥不是合法 32 字节 base64，地址不是合法 IP，或 endpoint 缺少端口。
    pub fn validate(&self) -> Result<()> {
        if !crate::wgkey::is_valid_key(&self.private_key) {
            bail!("private_key in the WARP config is not a valid 32-byte base64 WireGuard key");
        }
        if !crate::wgkey::is_valid_key(&self.peer_public_key) {
            bail!("peer_public_key in the WARP config is not a valid 32-byte base64 WireGuard key");
        }
        self.address_v4
            .parse::<std::net::Ipv4Addr>()
            .with_context(|| {
                format!(
                    "address_v4 is not a valid IPv4 address: {}",
                    self.address_v4
                )
            })?;
        self.address_v6
            .parse::<std::net::Ipv6Addr>()
            .with_context(|| {
                format!(
                    "address_v6 is not a valid IPv6 address: {}",
                    self.address_v6
                )
            })?;
        if !self.endpoint.contains(':') {
            bail!("endpoint must be host:port, got {:?}", self.endpoint);
        }
        Ok(())
    }

    /// 安全摘要：可安全打印到日志，不含任何密钥材料
    #[must_use]
    pub fn summarize(&self) -> String {
        format!(
            "endpoint={} addr_v4={} addr_v6={} peer={}*** client_id={}",
            self.endpoint,
            self.address_v4,
            self.address_v6,
            self.peer_public_key.chars().take(6).collect::<String>(),
            if self.client_id.is_empty() {
                "-"
            } else {
                &self.client_id
            },
        )
    }
}

impl std::fmt::Debug for WarpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 显式脱敏：私钥与预共享密钥永不出现。
        // 必须列出**全部**字段：漏掉字段的 Debug 会让人误以为结构里没有
        // 那项数据，排查时反而更容易出错。
        f.debug_struct("WarpConfig")
            .field("endpoint", &self.endpoint)
            .field("address_v4", &self.address_v4)
            .field("address_v6", &self.address_v6)
            .field("peer_public_key", &self.peer_public_key)
            .field("private_key", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("license", &self.license)
            .field("device_id", &self.device_id)
            .field(
                "access_token",
                &if self.access_token.is_empty() {
                    "<none>"
                } else {
                    "<redacted>"
                },
            )
            .field("account_ttl", &self.account_ttl)
            .field(
                "preshared_key",
                &if self.preshared_key.is_some() {
                    "<redacted>"
                } else {
                    "<none>"
                },
            )
            .finish()
    }
}

/// ------------- 原始 API 响应结构 -------------

#[derive(Debug, Deserialize)]
struct RegResponse {
    /// Cloudflare 分配的设备 id，用于 `GET /reg/{id}` 刷新配置。
    id: String,
    #[serde(default)]
    account: Account,
    config: RegConfig,
    #[serde(default)]
    token: String,
}

#[derive(Debug, Default, Deserialize)]
struct Account {
    #[serde(default)]
    license: String,
    /// 账号到期时间（RFC3339）。90 天左右。
    #[serde(default)]
    ttl: String,
}

#[derive(Debug, Deserialize)]
struct RegConfig {
    client_id: String,
    #[serde(default)]
    peers: Vec<Peer>,
    interface: Interface,
}

#[derive(Debug, Deserialize)]
struct Peer {
    public_key: String,
    endpoint: Endpoint,
}

#[derive(Debug, Deserialize)]
struct Endpoint {
    host: String,
}

#[derive(Debug, Deserialize)]
struct Interface {
    addresses: Addresses,
}

#[derive(Debug, Deserialize)]
struct Addresses {
    v4: String,
    v6: String,
}

// ------------- HTTP 客户端 -------------

fn http_client() -> Result<reqwest::Client> {
    http_client_builder()
        .build()
        .context("failed to build HTTP client")
}

/// 不跟随重定向的客户端（用于探测 team 是否存在）。
///
/// reqwest 默认会跟随 302，一路跳到 Access 登录页拿到 200，
/// 那样「302 = 需要登录 = team 存在」的判断就永远不成立。
fn http_client_no_redirect() -> Result<reqwest::Client> {
    http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build HTTP client")
}

fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(15))
        .user_agent("okhttp/3.12.1")
        // 关键：必须显式禁用环境代理。
        // 否则如果宿主机设了 HTTP_PROXY/HTTPS_PROXY，WARP 注册请求会走那个
        // 代理——不仅绕过了我们自己的 SO_MARK 路径，还会把 Cloudflare 注册
        // 流量暴露给无关的第三方。warpd 的定位是「直连 WARP API」。
        .no_proxy()
}

fn now_tos() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // 转成 2024-01-01T00:00:00.000Z 形式（Cloudflare 只校验格式）
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.000Z")
}

/// 把 unix 秒转成 UTC 民用日期时间（避免引入 chrono）
///
/// 这里的 u64 -> u32 转换都由算法本身保证在范围内（月 1-12、日 1-31、
/// 时 0-23、分/秒 0-59），因此截断不可能发生。
#[allow(clippy::cast_possible_truncation)]
// 单字符变量名是 Howard Hinnant 日期算法的既有记号（y/m/d/h/mi/s），
// 改名只会让这个已经被广泛验证的公式变得难以对照，反而增加出错风险。
#[allow(clippy::many_single_char_names)]
fn civil_from_unix(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    // 用饱和转换而不是裸 as：u64 极大值直接 as i64 会变成负数，
    // 让算法得出荒唐的年份。实际用不到这么远的未来，但按饱和处理更稳。
    let days = i64::try_from(secs / 86400).unwrap_or(i64::MAX);
    let rem = secs % 86400;
    let (h, mi, s) = (
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    );

    // Howard Hinnant 的 days_from_civil 逆运算
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    // era * 146097 <= z 且 z >= 0 时非负；这里已由上面的三元保证。
    let doe = z - era * 146_097;
    let doe = u64::try_from(doe).unwrap_or(0);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

/// 注册模式
#[derive(Debug, Clone)]
pub enum RegistrationMode {
    /// 普通消费者模式（匿名免费注册）
    Consumer,
    /// Zero Trust（Teams）模式
    ///
    /// 关键事实（经实测确证）：Zero Trust **没有独立端点**，它和消费者模式
    /// 用同一个注册 URL，唯一差别是多一个 HTTP 头
    /// `CF-Access-Jwt-Assertion: <团队 JWT>`。
    /// team name 不参与注册请求，仅用于拼出取 JWT 的门户地址。
    ZeroTrust {
        /// 团队 JWT（从 https://<team>.cloudflareaccess.com/warp 登录后取得）
        jwt: String,
    },
}

/// 注册一个新的 WARP 设备，返回可直接用于内核 `WireGuard` 的配置
/// # Errors
///
/// 注册请求失败、被限流，或返回体不含可用 peer。
pub async fn register(mode: RegistrationMode) -> Result<WarpConfig> {
    match mode {
        RegistrationMode::Consumer => register_with_token(None).await,
        RegistrationMode::ZeroTrust { jwt } => {
            if jwt.trim().is_empty() {
                bail!("Zero Trust mode requires a non-empty Access JWT");
            }
            register_with_token(Some(&jwt)).await
        }
    }
}

/// 向 WARP 注册设备。
///
/// `jwt` 为 None 时是消费者模式；为 Some 时带 `CF-Access-Jwt-Assertion`
/// 头走 Zero Trust。
///
/// 注意两个实测坑：
/// 1. 同一公钥二次注册会返回 401 "Invalid public key (1001)"——那不代表
///    端点故障，而是这个 key 已被注册过。所以每次注册都生成新密钥。
/// 2. 短时高频注册会触发 IP 级 429 限流（冷却 60-120s），因此配置要持久化
///    复用，不要反复注册。
async fn register_with_token(jwt: Option<&str>) -> Result<WarpConfig> {
    let client = http_client()?;

    // 关键：每个 API 版本尝试都用**全新的密钥对**。
    // Cloudflare 对「已注册过的公钥」返回 401 (code 1001)。如果复用同一把
    // 公钥去试多个版本号，第一个 1001 之后余下的必然全失败，会被误判成
    // 「端点全挂了」。所以这里把「生成密钥 + 提交」放在同一个循环里。
    let (priv_key, text) = post_registration_with_fresh_keys(&client, jwt).await?;

    let parsed: RegResponse = serde_json::from_str(&text)
        .with_context(|| format!("unexpected registration response: {}", truncate(&text, 400)))?;

    let peer = parsed
        .config
        .peers
        .first()
        .ok_or_else(|| anyhow!("registration response contained no peers"))?;

    Ok(WarpConfig {
        private_key: priv_key,
        peer_public_key: peer.public_key.clone(),
        endpoint: peer.endpoint.host.clone(),
        address_v4: parsed.config.interface.addresses.v4.clone(),
        address_v6: parsed.config.interface.addresses.v6.clone(),
        preshared_key: None,
        client_id: parsed.config.client_id.clone(),
        license: if parsed.account.license.is_empty() {
            parsed.token.clone()
        } else {
            parsed.account.license.clone()
        },
        device_id: parsed.id.clone(),
        access_token: parsed.token.clone(),
        account_ttl: parsed.account.ttl.clone(),
    })
}

/// 每个版本用新密钥尝试注册，返回 (私钥, 成功响应体)
async fn post_registration_with_fresh_keys(
    client: &reqwest::Client,
    jwt: Option<&str>,
) -> Result<(String, String)> {
    let mut last_err: Option<String> = None;

    for ver in API_VERSIONS {
        // 每次尝试生成全新的密钥对（见上方 1001 说明）
        let (priv_key, pub_key) = wgkey::generate_keypair();

        let body = serde_json::json!({
            "key": pub_key,
            "install_id": "",
            "fcm_token": "",
            "tos": now_tos(),
            "model": "PC",
            "locale": "en_US",
            "type": "Linux",
            "serial_number": "",
        });

        let url = format!("{API_HOST}/{ver}/reg");
        let mut req = client
            .post(&url)
            .header("CF-Client-Version", "a-6.81-2410012252.0")
            .header("Content-Type", "application/json")
            .header("User-Agent", "1.1.1.1/6.81");

        if let Some(token) = jwt {
            req = req.header("CF-Access-Jwt-Assertion", token.trim());
        }

        let resp = match req.json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(format!("{ver}: network error: {e}"));
                continue;
            }
        };

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            log::debug!("WARP registration succeeded with API version {ver}");
            return Ok((priv_key, text));
        }

        if status.as_u16() == 429 {
            bail!(
                "WARP registration is rate-limited (HTTP 429) by Cloudflare. \
                 Wait 1-2 minutes before retrying. Reuse a saved config to avoid re-registering."
            );
        }

        if status.as_u16() == 404 {
            last_err = Some(format!("{ver}: endpoint not found (version retired)"));
            continue;
        }

        // 400 + 已知错误码：JWT 无效/过期，或该组织未启用 WARP
        let zt_rejected = text.contains("bad device request")
            || text.contains("\"code\":2004")
            || text.contains("invalid claim type")
            || text.contains("\"code\":2001");
        if status.as_u16() == 400 && jwt.is_some() && zt_rejected {
            bail!(
                "Zero Trust enrollment was rejected by Cloudflare (code 2004, 'bad device request').\n\
                 This usually means one of:\n\
                 \x20 - the JWT has expired (they are short-lived, ~1-5 minutes: paste it immediately)\n\
                 \x20 - the JWT was copied incompletely or from the wrong organization\n\
                 \x20 - WARP is not enabled for this Zero Trust organization\n\
                 \x20   (Dashboard > Settings > WARP Client > enable WARP)\n\
                 \x20 - the device enrollment policy blocks this device\n\
                 Get a fresh link, sign in again, and paste the new JWT right away."
            );
        }

        last_err = Some(format!(
            "{}: HTTP {}: {}",
            ver,
            status,
            truncate(&text, 200)
        ));
    }

    bail!(
        "WARP registration failed on all API versions. Last error: {}",
        last_err.unwrap_or_else(|| "unknown".to_string())
    )
}

/// 把用户可能输入的多种形式规范化成纯 team 名
///
/// 接受：
///   yangshu114514
///   yangshu114514.cloudflareaccess.com
///   <https://yangshu114514.cloudflareaccess.com>
///   <https://yangshu114514.cloudflareaccess.com/warp>
#[must_use]
pub fn normalize_team(input: &str) -> String {
    let t = input.trim().trim_end_matches('/');
    let t = t.strip_prefix("https://").unwrap_or(t);
    let t = t.strip_prefix("http://").unwrap_or(t);
    // 去掉路径部分
    let t = t.split('/').next().unwrap_or(t);
    // 去掉 .cloudflareaccess.com 后缀
    let t = t.strip_suffix(".cloudflareaccess.com").unwrap_or(t);
    t.to_string()
}

/// 返回 Zero Trust 门户地址，供用户去取 JWT
#[must_use]
pub fn zero_trust_portal_url(team: &str) -> String {
    ZT_PORTAL_FMT.replace("{team}", &normalize_team(team))
}

/// 探测一个 team 是否存在（返回 Ok(true/false)）
///
/// 判定依据（实测）：存在的 team，/warp 会 302 跳到 Access 登录页；
/// 不存在的 team 返回 404。这样可以在让用户去浏览器之前就给出明确反馈。
/// # Errors
///
/// 无法访问该团队的门户地址。
pub async fn check_team_exists(team: &str) -> Result<bool> {
    let team = normalize_team(team);
    if team.is_empty() {
        bail!("team name must not be empty");
    }
    let url = format!("https://{team}.cloudflareaccess.com/warp");

    // 关键：必须关闭自动重定向。
    // reqwest 默认会跟随 302 一路跳到 Access 登录页，最后拿到的永远是 200，
    // 那样这里的状态码判断就完全失效了（什么 team 都返回 true）。
    // 我们要看的是**第一跳**的状态码本身。
    let client = http_client_no_redirect()?;

    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to reach {url}"))?;

    let code = resp.status().as_u16();
    // 302 = 需要登录 = team 存在且 WARP 应用已配置
    // 404 = team 不存在
    // 200 = 已登录态或公开，也说明 team 存在
    Ok(matches!(code, 200 | 302 | 303 | 307))
}

/// 用已保存的凭据刷新设备配置（`GET /reg/{id}`）
///
/// 为什么需要：Zero Trust 组织里，服务端会重新分配 IPv6 地址。如果本地
/// 配置里的 IPv6 过期，v6 流量会直接不通。刷新一次即可拿到最新地址，
/// 无需让用户重新走一遍浏览器登录（JWT 早已用完）。
///
/// 需要 `device_id` 与 `access_token`（注册响应里的 id / token）。
/// # Errors
///
/// 缺少 `device_id` / `access_token`，或所有 API 版本都刷新失败。
pub async fn refresh_config(current: &WarpConfig) -> Result<WarpConfig> {
    if current.device_id.is_empty() || current.access_token.is_empty() {
        bail!(
            "cannot refresh: the saved configuration has no device_id/access_token \
             (it was created by an older warpd version). Re-register with --reset."
        );
    }

    let client = http_client()?;
    let mut last_err: Option<String> = None;

    for ver in API_VERSIONS {
        let url = format!("{}/{}/reg/{}", API_HOST, ver, current.device_id);
        let resp = match client
            .get(&url)
            .bearer_auth(&current.access_token)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(format!("{ver}: network error: {e}"));
                continue;
            }
        };

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            let parsed: RegResponse = serde_json::from_str(&text).with_context(|| {
                format!("unexpected refresh response: {}", truncate(&text, 300))
            })?;

            let peer = parsed
                .config
                .peers
                .first()
                .ok_or_else(|| anyhow!("refresh response contained no peers"))?;

            // 关键：私钥是我们自己的，不随刷新变化；其余字段用服务端最新值
            let refreshed = WarpConfig {
                private_key: current.private_key.clone(),
                peer_public_key: peer.public_key.clone(),
                endpoint: peer.endpoint.host.clone(),
                address_v4: parsed.config.interface.addresses.v4.clone(),
                address_v6: parsed.config.interface.addresses.v6.clone(),
                preshared_key: current.preshared_key.clone(),
                client_id: parsed.config.client_id.clone(),
                license: if parsed.account.license.is_empty() {
                    current.license.clone()
                } else {
                    parsed.account.license.clone()
                },
                device_id: parsed.id.clone(),
                access_token: if parsed.token.is_empty() {
                    current.access_token.clone()
                } else {
                    parsed.token.clone()
                },
                account_ttl: parsed.account.ttl.clone(),
            };

            if refreshed.address_v6 != current.address_v6 {
                log::info!(
                    "server assigned a new IPv6: {} -> {}",
                    current.address_v6,
                    refreshed.address_v6
                );
            }
            if refreshed.address_v4 != current.address_v4 {
                log::info!(
                    "server assigned a new IPv4: {} -> {}",
                    current.address_v4,
                    refreshed.address_v4
                );
            }

            return Ok(refreshed);
        }

        if status.as_u16() == 404 {
            last_err = Some(format!("{ver}: device not found (version retired?)"));
            continue;
        }

        last_err = Some(format!(
            "{}: HTTP {}: {}",
            ver,
            status,
            truncate(&text, 200)
        ));
    }

    bail!(
        "failed to refresh WARP configuration: {}",
        last_err.unwrap_or_else(|| "unknown".to_string())
    )
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut end = n;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_tos_format() {
        let s = now_tos();
        // 形如 2026-10-27T15:47:47.000Z
        // lint 会把 .000Z 当成文件扩展名而误报 case-sensitive 比较，
        // 这里改用切片比较，语义完全等价。
        assert_eq!(&s[19..24], ".000Z", "got {s}");
        assert_eq!(s.len(), 24, "got {s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }

    #[test]
    fn test_civil_from_unix() {
        // 1970-01-01T00:00:00Z
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        // 2024-02-29T12:34:56Z (闰年)
        let t = 1_709_210_096;
        let (y, mo, d, _, _, _) = civil_from_unix(t);
        assert_eq!((y, mo, d), (2024, 2, 29));
    }

    #[test]
    fn test_warp_config_debug_redacts_private_key() {
        // H7: 私钥绝不能出现在 Debug 输出里（可能被打进 journald）
        let cfg = WarpConfig {
            private_key: "SUPER_SECRET_PRIVATE_KEY_DO_NOT_LEAK".to_string(),
            peer_public_key: "peerpub=".to_string(),
            endpoint: "engage.cloudflareclient.com:2408".to_string(),
            address_v4: "172.16.0.2".to_string(),
            address_v6: "2606::1".to_string(),
            preshared_key: None,
            client_id: "abc".to_string(),
            license: "lic".to_string(),
            device_id: "dev-id".to_string(),
            access_token: "tok".to_string(),
            account_ttl: "2027-01-01T00:00:00Z".to_string(),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("SUPER_SECRET_PRIVATE_KEY_DO_NOT_LEAK"),
            "private key leaked in Debug output: {dbg}"
        );
        assert!(dbg.contains("redacted"));

        // summarize() 同样不能泄漏
        let s = cfg.summarize();
        assert!(!s.contains("SUPER_SECRET"));
    }

    #[test]
    fn test_normalize_team_forms() {
        // 注意：这里必须调用**真正的** normalize_team。
        // 旧版本在这个测试里复制了一份等价逻辑来自测，那样即使被测函数
        // 完全坏掉测试也照样通过 —— 等于没测。
        for input in [
            "myteam",
            "myteam.cloudflareaccess.com",
            "https://myteam.cloudflareaccess.com",
            "https://myteam.cloudflareaccess.com/",
            "https://myteam.cloudflareaccess.com/warp",
            "http://myteam.cloudflareaccess.com/warp",
            "  myteam  ",
        ] {
            assert_eq!(normalize_team(input), "myteam", "failed on {input:?}");
        }
    }

    #[test]
    fn test_portal_url_built_from_any_form() {
        // 无论用户怎么输入，门户链接都必须拼对
        let want = "https://myteam.cloudflareaccess.com/warp";
        assert_eq!(zero_trust_portal_url("myteam"), want);
        assert_eq!(
            zero_trust_portal_url("https://myteam.cloudflareaccess.com/warp"),
            want
        );
    }

    #[test]
    fn test_truncate_is_utf8_safe() {
        // truncate 会把服务端响应体截断后打进日志，绝不能因为切在多字节
        // 字符中间而 panic。
        let s = "中文字符串测试中文字符串测试";
        for n in 0..s.len() {
            let _ = truncate(s, n);
        }
        assert!(truncate(s, 6).ends_with("..."));
    }
}
