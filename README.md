# warpd

> 单二进制、非 Docker 的原生 Rust WARP 客户端：**通过 netlink 创建内核态 WireGuard 接口 `warp0` 连接 Cloudflare WARP，并内置一个只监听 127.0.0.1 的 SOCKS5 代理**，出站流量靠 SO_MARK + fwmark 策略路由被强制导入内核隧道。主路由表始终不动。

一句话：**数据面在内核（kernel WireGuard），用户态只做控制面 + 代理。**

---

## 架构

```text
┌──────────────────────────────────────────────────────────────┐
│ 应用（curl / 浏览器 / 任意支持 SOCKS5 的程序）                 │
└───────────────────────────┬──────────────────────────────────┘
              SOCKS5 / TCP  │ 127.0.0.1:1080（只监听 loopback）
┌───────────────────────────▼──────────────────────────────────┐
│ warpd（用户态，单进程，无需 wg / wg-quick）                     │
│                                                              │
│  控制面                       数据面的"入口"                    │
│  ├─ WARP 注册 (HTTPS)         ├─ SOCKS5 CONNECT (RFC 1928)    │
│  ├─ rtnetlink 建 warp0        ├─ marked DNS（自建报文编解码）    │
│  ├─ nl-wireguard 配 peer      └─ socket2 setsockopt(SO_MARK)   │
│  └─ fwmark 策略路由                                            │
└───────────────────────────┬──────────────────────────────────┘
              TCP/UDP 出站  │ 已打 fwmark 0x1
┌───────────────────────────▼──────────────────────────────────┐
│ Linux 内核（数据面全部在这里，零拷贝、无用户态加解密）            │
│                                                              │
│   ip rule: fwmark 0x1 → lookup 100   (priority 100)           │
│   table 100: default dev warp0                                │
│                     │                                         │
│              ┌──────▼──────┐                                  │
│              │   warp0     │  WireGuard 加解密（内核模块）       │
│              └──────┬──────┘                                  │
└─────────────────────┼────────────────────────────────────────┘
   加密后的 UDP:2408  │  未打 mark（device fwmark = 0）→ 走主路由表
┌─────────────────────▼────────────────────────────────────────┐
│ eth0 → engage.cloudflareclient.com:2408 → Cloudflare → 目标站点 │
└──────────────────────────────────────────────────────────────┘

主路由表（main / 254）全程未被修改；只有打了 mark 的流量走 table 100。
```

启动顺序（`src/main.rs`，失败即回滚、退出时逆序清理）：

1. 预检：Linux 平台、root 或 `CAP_NET_ADMIN`+`CAP_NET_RAW`、内核 wireguard 可用
2. 取得 WARP 配置（复用已存 state，或 `--reset` 重新注册）
3. netlink 创建并配置 `warp0`（建 link → 加地址 → MTU/up → 写私钥 + peer）
4. 安装 fwmark 策略路由（rule + table 100 的 default 路由）
5. 启动 SOCKS5（仅 loopback）
6. 等 SIGTERM / SIGINT，然后删除 rule/route、最后删除接口

---

## 为什么用内核态 WireGuard

warpd 不做用户态隧道。对比 `boringtun` / `wireguard-go` 这类用户态实现：

| 维度 | 用户态实现（boringtun / wireguard-go） | 本次实现（内核 wireguard 模块） |
|---|---|---|
| 每个包的处理路径 | 内核 TUN → 上下文切换到用户态 → 用户态加解密 → 再写回 socket | 内核 netdevice 层直接加解密，不离开内核 |
| 上下文切换 | 每包 2 次以上（读 TUN / 写 socket） | 0 次用户态切换 |
| 内存拷贝 | 用户态缓冲区与内核缓冲区之间来回拷贝 | 共享 skb，无额外拷贝 |
| 加解密实现 | 用户态 ChaCha20-Poly1305（依赖 crate 与 CPU 特性） | 内核 WireGuard 的 ChaCha20-Poly1305 实现 |
| 多队列 / GSO | 单进程通常单队列 | 内核支持多队列与 UDP GSO/GRO，聚合小包、按 CPU 并行 |
| 进程模型 | 需要常驻用户态转发进程，进程死隧道就断 | 隧道是内核对象，控制面进程退出后接口仍在（本项目主动清理） |
| 与策略路由配合 | mark 打在用户态转发 socket 上，路径长且容易漏 | mark 直接打在业务 socket 上，一次 `ip rule` 命中即进隧道 |

最关键的一条不是吞吐数字，而是**路径可预测**：应用发的 TCP 包在内核里就完成「查 rule→查 table 100→进 warp0→加密→出 eth0」全过程，用户态只在建连时设一次 `SO_MARK`。没有用户态转发进程，就没有第二条可能泄漏出去的路径。

> 具体吞吐/延迟差异随 CPU、内核版本（GSO/GRO 支持）、包大小而变，本文不给未实测的数字。
>
> 代价是**必须依赖内核 wireguard 模块**（`CONFIG_WIREGUARD=m` 或 `y`），无法在缺少该模块的内核上运行 —— 见「已知限制」。

---

## 快速开始

### 依赖

- Linux（只支持 Linux；只有这里才有 netlink、SO_MARK、fwmark 策略路由）
- 内核 wireguard 模块（现代发行版一般已内置；否则 `modprobe wireguard`）
- root 或 `CAP_NET_ADMIN` + `CAP_NET_RAW`
- 编译期：Rust ≥ 1.80

### 从源码编译（在 Linux 上）

```bash
git clone <repo> warpd && cd warpd
cargo build --release
sudo ./target/release/warpd --check-only   # 只做环境检查，不碰网络
sudo ./target/release/warpd                # 默认 127.0.0.1:1080
```

### 交叉编译静态 musl 二进制（在 Windows / macOS 上）

产物是静态 ELF，直接 scp 到任意 x86_64 Linux 运行，不依赖 glibc：

```bash
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild          # 需要 zig
cargo zigbuild --release --target x86_64-unknown-linux-musl
# 产物：target/x86_64-unknown-linux-musl/release/warpd
```

`file` 应显示 `ELF 64-bit LSB pie executable, x86-64, statically linked`。全部依赖都是纯 Rust（rtnetlink / nl-wireguard / socket2 / rustls），**不需要 musl-gcc，不需要 C 编译器** —— 这也是选型时排除 `defguard_wireguard_rs`（硬依赖 boringtun）的原因。

### 安装为系统服务

```bash
sudo ./deploy/install.sh                                  # 自动找二进制
sudo ./deploy/install.sh /path/to/warpd                   # 或显式指定
sudo systemctl status warpd
sudo journalctl -u warpd -f
```

### 立刻验一下

```bash
curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
# warp=on 表示流量确实从 WARP 出口出去
```

---

## CLI 参数

`warpd --help` 的完整列表（与 `src/main.rs` 的 `Cli` 结构体一致）：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--socks <SOCKS>` | `127.0.0.1:1080` | SOCKS5 监听地址。**必须是 loopback**，否则启动即拒绝（`0.0.0.0`、`[::]`、公网地址都会被 `validate_bind` 挡住） |
| `--mark <MARK>` | `0x1` | 出站 socket 的 SO_MARK 值。支持 `0x` 十六进制与十进制（`0x1`、`1`、`0xFF`） |
| `--table <TABLE>` | `100` | 策略路由表号（与主表隔离）。rule 的 priority 取 `table.clamp(100, 32000)` |
| `--iface <IFACE>` | `warp0` | 内核 WireGuard 接口名。同名残留接口会被先删掉（幂等） |
| `--mtu <MTU>` | `1280` | 接口 MTU（WARP 常用值，避免 PMTU 黑洞） |
| `--mode <MODE>` | `consumer` | 注册模式：`consumer` \| `zerotrust` |
| `--team <TEAM>` | 无 | Zero Trust 团队名。**只用于打印取 JWT 的门户地址**，不参与注册请求 |
| `--zt-jwt <ZT_JWT>` | 无 | Zero Trust Access JWT。也可用环境变量 `WARPD_ZT_JWT`（`--mode zerotrust` 时必填） |
| `--zt-login` | 关闭 | 交互式 Zero Trust 登录：先打印认证链接，你登录后粘贴 JWT，自动完成注册并保存。**推荐用这个** |
| `--cleanup-only` | 关闭 | 只清理残留的内核状态（rule / 路由 / 接口）后退出。供 systemd `ExecStopPost=` 兜底 |
| `--handshake-timeout <N>` | 60 | SOCKS5 握手整体超时（秒）。防止半开连接长期占用 fd |
| `--max-connections <N>` | 1024 | SOCKS5 最大并发连接数 |
| `--state <STATE>` | 见下 | WARP 配置持久化路径（含私钥，落盘权限 0600） |
| `--reset` | 关 | 忽略已保存配置，强制重新注册（会消耗一次 Cloudflare 注册配额） |
| `--refresh` | 关 | 启动前先向 Cloudflare 拉一次最新设备配置（复用已存的 device_id/token，无需重新登录） |
| `--sync-interval <INT>` | `1h` | **运行时周期性同步配置**。支持 `30s`/`5m`/`1h`/`6h`/`1d`，`off` 关闭。最小 60s（防 429） |
| `--connect-timeout <N>` | `10` | 出站 TCP 连接超时（秒） |
| `--check-only` | 关 | 只做环境检查然后退出，不建接口、不改路由、不监听端口 |
| `-h`, `--help` / `-V`, `--version` | — | 帮助 / 版本 |

`--state` 的默认值规则（`src/store.rs`）：

1. 若设了环境变量 `WARPD_STATE_FILE`，用它；
2. 否则若 euid == 0 → `/var/lib/warpd/warp.json`；
3. 否则 → `$XDG_CONFIG_HOME/warpd/warp.json`，再退到 `$HOME/.config/warpd/warp.json`。

用 systemd + 专用非 root 用户运行时，**务必显式传 `--state`**（unit 里已经写好 `/var/lib/warpd/warp.json`），否则会走 `$HOME/.config`。

常用组合：

```bash
# 换个 mark 和表号，避免与机器上已有的分流规则撞车
sudo warpd --mark 0x5752 --table 200

# 换接口名与端口
sudo warpd --iface wg-warp --socks 127.0.0.1:1081 --mtu 1420

# 只体检
sudo warpd --check-only
```

---

## 两种注册模式

两种模式最终产出**同一份** `WarpConfig`（私钥、peer 公钥、endpoint、v4/v6 地址），直接喂给 netlink 层。差别只有一个 HTTP 头。

### 普通消费者模式（默认，匿名免费）

```bash
sudo warpd
# 或等价
sudo warpd --mode consumer
```

向 `https://api.cloudflareclient.com/<version>/reg` 匿名注册，自动生成 X25519 密钥对。API 版本号按 `v0a2158 → v0a2483 → v0a4000 → v0a1000` 逐个 fallback（Cloudflare 会下线旧版本，硬编码单一版本会 404）。

首次注册后配置会持久化到 state 文件，**后续启动直接复用，不再打注册接口**。只有 `--reset` 才重新注册。

**为什么需要周期同步**：WARP（尤其 Zero Trust）会由服务端重新分配 IPv6、甚至更新 peer。
本地配置一旦过期，对应地址的流量就不通。`--sync-interval` 默认每小时拉一次
`GET /reg/{id}`（复用已保存的 device_id + access_token，**不需要重新登录**），
若有变化就**原地更新内核 peer**——接口和路由不动，所以**不会断流**。

### Zero Trust（Teams）模式

Zero Trust 最顺手的用法是 `--zt-login` 向导 —— 体验和 Cloudflare 官方 WARP 客户端一致：
**它给你一个认证链接，你登录，完事**。

```bash
sudo warpd --zt-login --team yangshu114514
```

它依次做这些事：

1. 先探测 team 是否存在（`Checking Zero Trust team 'yangshu114514'... OK`）。
   team 名写错会立刻告诉你，不必白跑一趟浏览器；
2. 打印认证链接 `https://<team>.cloudflareaccess.com/warp`；
3. 你在**任意已登录 Cloudflare 的浏览器**里打开它，用组织身份登录；
4. 登录后页面跳到 `com.cloudflare.warp://...jwt=eyJ...`，把 JWT 粘回终端；
5. warpd 用该 JWT 调 WARP 注册 API，成功后存到 `/var/lib/warpd/warp.json`。

之后直接 `sudo warpd` 起隧道即可，无需再给 JWT（除非 token 过期或加 `--reset`）。

#### 如何拿到 JWT

登录后若页面没直接显示 JWT：

- 看地址栏有没有 `jwt=eyJ...` 参数，直接复制；
- 或在浏览器 Console 执行：

```js
  document.querySelector("meta[http-equiv='refresh']")?.content
```

  取等号后面那段。

warpd 对粘贴内容做了容错：裸 JWT、整条 URL、meta refresh 的 content 值，三种都能识别。

#### 非交互方式（脚本 / CI）

已经拿到 JWT 时也可以直接传：

```bash
sudo warpd --mode zerotrust --team myteam --zt-jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...."
# 或用环境变量，避免 JWT 出现在进程列表里
export WARPD_ZT_JWT='eyJ...'
sudo -E warpd --mode zerotrust --team myteam
```

#### Zero Trust 的实测事实

- Zero Trust **没有独立端点**，和消费者模式用同一个注册 URL，唯一差别是多一个请求头 `CF-Access-Jwt-Assertion`。
- **team name 不参与注册请求**，它只用于拼出取 JWT 的门户地址。
- JWT 由 Cloudflare 用私钥签名，服务端严格验签，**客户端无法伪造**（伪造得到 `code 2001 invalid claim type`）。
  因此这一步必须由你的浏览器完成登录 —— 任何第三方客户端（包括官方 WARP）都是同一流程。
- JWT 有效期很短（约 1–5 分钟），登录后请**立刻**粘贴；过期会报 `code 2004 bad device request`。
- 若报 2004，还可能是：该组织未启用 WARP（Dashboard > Settings > WARP Client），或设备注册策略拦截了本机。

---

## 验证方法

全部命令在装了 `wireguard-tools` / `iproute2` 的 Linux 上可直接跑。

### 1. 隧道接口与 peer

```bash
sudo wg show warp0
```

期望看到：

```text
interface: warp0
  public key: <本端公钥>
  private key: (hidden)
  listening port: <随机端口>

peer: <Cloudflare peer 公钥>
  endpoint: 162.159.192.x:2408
  allowed ips: 0.0.0.0/0, ::/0
  latest handshake: 3 seconds ago        ← 关键：不为空说明隧道真的通了
  transfer: 1.24 KiB received, 908 B sent
  persistent keepalive: every 25 seconds
```

`latest handshake` 一直是空 → 隧道没建立（见「故障排查」）。注意 `persistent keepalive: every 25 seconds` 是本项目设的（`persistent_keepalive = 25`），它保证 NAT 后也能持续探活。

```bash
ip -d link show warp0    # 应显示 "wireguard" 类型
ip addr show warp0       # 应有 WARP 下发的 v4/32 与 v6/128
```

### 2. 策略路由

```bash
ip rule show
```

期望看到（priority 默认等于 table 号，即 100）：

```text
100:	from all fwmark 0x1 lookup 100
32766:	from all lookup main
32767:	from all lookup default
```

> 如果末尾多出一个 `none`（`100: from all fwmark 0x1 lookup 100 none`），说明 rule 的 action 没生效——本项目显式设了 `RuleAction::ToTable` 就是为了避免这个静默失效。

```bash
ip route show table 100
```

期望：

```text
default dev warp0 scope link
```

IPv6 同理：`ip -6 rule show` / `ip -6 route show table 100`（v6 失败不致命，部分环境禁用 v6）。

### 3. 内核实际选路（最直接的一条）

```bash
ip route get 1.1.1.1 mark 0x1
```

期望输出里出现 `dev warp0`：

```text
1.1.1.1 dev warp0 table 100 src <warp0 的地址> mark 0x1 uid 0
```

对照：不带 mark 应走主表（`ip route get 1.1.1.1` → `dev eth0 ...`）。这两条一对比就证明了「只有 mark 流量进隧道，主表没被污染」。

```bash
# 反向路径校验开关（WireGuard + fwmark 策略路由的标准要求）
cat /proc/sys/net/ipv4/conf/all/src_valid_mark    # 应为 1
```

### 4. 端到端（走 SOCKS5）

```bash
# 域名形式（--socks5-hostname 让域名交给代理解析 → 走 marked DNS，不泄漏）
curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

期望输出里 `warp=on`：

```text
fl=...
h=www.cloudflare.com
ip=104.28.x.x
ts=...
warp=on
```

其他常用动作：

```bash
# IP 直连形式也支持
curl --socks5 127.0.0.1:1080 -sS http://1.1.1.1/cdn-cgi/trace

# 出口 IP 对比：直连 vs 走代理
curl -s https://www.cloudflare.com/cdn-cgi/trace | grep '^ip='
curl -s --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace | grep '^ip='
```

### 5. 清理是否干净

```bash
sudo systemctl stop warpd
ip link show warp0 || echo "warp0 已删除"
ip rule show | grep fwmark || echo "rule 已删除"
ip route show table 100     # 应为空
```

如果 stop 之后还有残留，说明进程是被 SIGKILL 杀的（没走清理路径），见「故障排查」。

---

## 工作原理

### SO_MARK + 策略路由怎么配合

三块拼图，缺一不可：

1. **业务 socket 打标**：SOCKS5 的每个出站连接都由 `socket2` 建 socket 后 `setsockopt(SOL_SOCKET, SO_MARK, mark)`，再交给 tokio。DNS 的 UDP socket 同样打标。
2. **rule 按 mark 选表**：`ip rule: from all fwmark 0x1 lookup 100`（priority 100）。内核路由查找时，先看 mark，命中就只查 table 100。
3. **table 100 的 default 指向 warp0**：`default dev warp0`。于是这条连接被交给 warp0，内核 WireGuard 加密后从 eth0 发出。

为什么这么设计，而不是直接改主路由表：

- **主表不动** → 机器上其他进程、SSH、apt、公司内网路由完全不受影响；warpd 崩溃或被 kill，最坏结果是「代理不可用」，而不是「整机断网」。
- **按进程/按 socket 精确控制** → 只有 warpd 代理出去的连接进隧道，其他流量照旧。这是「代理」而不是「全局 VPN」的语义。
- **可与其他分流共存** → 用独立的 mark 和 table 号就能和机器上已有的规则并存。切换/回滚就是删一条 rule + 一条路由。

为什么**不能给 warp0 设 fwmark**（这是本项目最关键的一个设计约束，代码里 `device.fwmark = Some(0)` 有注释）：

WireGuard 设备自身的 `fwmark` 是「它自己发加密包时给这些 UDP 包打的 mark」。如果设成 `0x1`，流程就变成：

```text
加密后的 UDP 包（mark 0x1）
   → ip rule fwmark 0x1 → lookup 100
   → table 100 default dev warp0
   → 又送回 warp0 再加密一次
   → 再打 0x1 → 再进 warp0 → ...（环路 / 全部丢包）
```

设 `fwmark = 0` 之后，加密包不带 mark，走 `32766: from all lookup main` → eth0 → 直连 Cloudflare 的 2408/UDP。**策略路由只捕获「业务流量」，绝不捕获「承载隧道本身的流量」**，这是内核 WireGuard + 策略路由的标准做法。

（另一条常见路线是给 device 设一个**不同于业务 mark** 的 mark，再加 `ip rule not fwmark <that> ...` 豁免；本项目选了更简单的 fwmark=0。两种做法目的一致：**隧道自己的加密包必须逃避策略路由**。）

### 为什么 marked DNS 是必要的

SOCKS5 的 `ATYP=DOMAIN` 请求里，域名是**由代理解析**的。如果直接用 `getaddrinfo`：

- 它走系统 resolver，socket 不打 mark → 查询包不满足 `fwmark 0x1` → 走主路由表 → 从 eth0 明文发出去；
- 结果：**域名解析泄漏**（谁在看什么网站，DNS 层面全暴露），而且解析结果可能被污染。

所以 `src/dialer.rs` 自己实现了最小 DNS 客户端：`socket2` 建 UDP socket → `SO_MARK` → 手工构造 A / AAAA 查询报文 → 发给 `1.1.1.1:53`（备选 `1.0.0.1:53`）→ 自己解析响应（支持压缩指针）。查询包带 mark → 进 table 100 → warp0 → **DNS 也走隧道**，不泄漏。IPv4 结果优先。

### 幂等与清理

- 建接口前先 `delete_if_exists`（dump 全部 link 按名字过滤，避开 `match_name` 在接口不存在时返回 ENODEV 的坑），等内核真正回收再创建，避免 EEXIST。
- 装路由前先 `cleanup` 一遍旧的 rule/route。
- peer 配置用 `ReplacePeers` + `ReplaceAllowedIps`，重复运行是覆盖而不是追加。
- 任一步失败都回滚已做的事：路由安装失败 → 删接口；SOCKS 端口绑定失败 → 删路由 + 删接口。
- 收到 SIGTERM / SIGINT → 按 `rule/route → 接口` 的顺序删除（`CleanupCtx::cleanup`）。

---

## 故障排查

### `latest handshake` 一直为空 / curl 走代理超时

隧道没建立。按顺序查：

1. `sudo wg show warp0` 里 `endpoint` 是否有值、`allowed ips` 是否为 `0.0.0.0/0, ::/0`。
2. **本机能不能直连 Cloudflare 的 2408/UDP**？加密包走主路由表，所以必须先能出去：
   ```bash
   sudo wg show warp0 endpoints
   ip route get <endpoint的IP>            # 应该 dev eth0
   nc -uzv <endpoint的IP> 2408            # 或 ss/nmap 查 UDP 可达性
   ```
   公司网/校园网常封 UDP 2408 或只允许 443。此时换网络环境再试。
3. `sysctl net.ipv4.conf.all.src_valid_mark` 是 1 吗？（不是 1 会让带 mark 的回包被 rp_filter 当 martian 丢掉）
4. 是不是 `--reset` 反复注册导致 key 被 Cloudflare 拉黑、或触发 429？看日志里有没有 `rate-limited` / `public key already registered`。
5. 用 `--check-only` 先把环境层面的问题排掉。

### curl 报 `Could not resolve host` / SOCKS 返回 host unreachable

marked DNS 挂了。查：

- 隧道是否通（上一条）。DNS 查询走隧道，隧道不通 DNS 必然不通 —— 这是设计使然，不是 bug。
- 日志里有没有 `A query for ... failed` / `AAAA query ... failed` / `all DNS servers failed`。
- 环境是否禁止 UDP 53 出网？可换一台 WARP 可达的网络验证。
- 注意 `--socks5`（本地解析域名）与 `--socks5-hostname`（代理解析）的区别：用 `--socks5` 时域名由 curl 自己解析，泄漏与否就是 curl 的事了。

### `insufficient privileges`

```text
insufficient privileges: warpd needs root or CAP_NET_ADMIN to create
a kernel WireGuard interface and to set SO_MARK on outbound sockets.
```

- 直接跑：`sudo warpd ...`
- systemd：用 `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`（`deploy/warpd.service` 已经写好）
- 注意预检要求 `CAP_NET_ADMIN` **和** `CAP_NET_RAW` 同时在 `CapEff` 里。

### `kernel WireGuard support is not available`

```bash
sudo modprobe wireguard && ls /sys/module/wireguard
# Debian/Ubuntu（老内核才需要单独装）
sudo apt install wireguard-modules
# 永久加载
echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf
```

若内核根本没编 wireguard（`CONFIG_WIREGUARD` 未开），只能换内核 —— 本项目不支持用户态替代实现。

**容器环境特别注意**：OpenVZ / LXC 这类共享宿主内核的容器，`uname -r` 显示的是**宿主**内核版本，容器内既没有 `/lib/modules/` 下的模块文件，也不允许 `insmod`。宿主机内核 < 5.6 时（WireGuard 进主线是 5.6）这条路彻底走不通，换发行版、装 `wireguard-dkms`、mknod 造设备都无效 —— 必须换 KVM 全虚拟化机器。已在此类环境验证过：`modprobe wireguard` 报 `Module wireguard not found`，`ip link add type wireguard` 报 `Operation not supported`，`/lib/modules/$(uname -r)/` 内无任何 `.ko` 文件。

如果目标只是「拿到能用的 WARP 出口」而不苛求内核态数据面，用户态 MASQUE 实现（如 [usque](https://github.com/Diniboy1123/usque)）在容器里更省事，且 QUIC 流量特征比裸 UDP WireGuard 更难被干扰。本项目存在的意义是**确定需要内核态 WireGuard 数据面**的场景。

### 非 root 下启动失败，报 modprobe 失败

`src/preflight.rs` 在模块未加载时会尝试 `modprobe wireguard`；非 root 时 modprobe 必然失败，预检就报错退出。所以用 systemd 降权运行时，**要先把模块加载好**（install.sh 会写 `/etc/modules-load.d/`）。

### SOCKS 端口被占用 / 启动后立刻退出

```text
cannot bind SOCKS5 listener on 127.0.0.1:1080: Address already in use
```

换端口：`--socks 127.0.0.1:1081`。程序会在删除已建好的隧道与路由后退出，不会留半残状态。查占用：

```bash
ss -lntp | grep 1080
```

### `refusing to listen on ...`（SOCKS 地址被拒）

`--socks` 必须是 loopback（`127.0.0.0/8` 或 `::1`）。这是硬性安全约束：绝不把无认证代理暴露到网络。

### 反复注册被 429 限流

```text
WARP registration is rate-limited (HTTP 429) by Cloudflare. Wait 1-2 minutes ...
```

等 1–2 分钟；平时**不要每次都加 `--reset`**，state 文件会复用配置。`--reset` 只在真的需要换设备身份时用。

### stop 之后 `warp0` / 规则还在

说明进程没走清理路径（被 SIGKILL）。systemd 下要保证 `KillSignal=SIGTERM` 且 `TimeoutStopSec` 足够（unit 里是 15s）。手动收拾：

```bash
sudo ip rule del fwmark 0x1 lookup 100
sudo ip route del default dev warp0 table 100
sudo ip link del warp0
```

### 想看更多日志

```bash
sudo RUST_LOG=debug warpd --check-only
sudo journalctl -u warpd -f
```

---

## 已知限制

- **只做 SOCKS5 CONNECT**。BIND 与 UDP ASSOCIATE 明确不支持（返回 `command not supported`）。HTTPS/TCP 完全够用；基于 UDP 的协议（QUIC、普通 DNS over UDP 应用直连）不通过本代理。
- **只支持 Linux**。依赖 netlink、`SO_MARK`、fwmark 策略路由、内核 wireguard 模块，这些在其他平台的语义/可用性都不同。预检里直接拒。
- **必须有内核 wireguard 模块**（`CONFIG_WIREGUARD=m` 或 `=y`）。不提供 boringtun / wireguard-go 等用户态回落。
- **需要 root 或 CAP_NET_ADMIN + CAP_NET_RAW**。SO_MARK 本身就需要特权。
- **SOCKS5 无认证**。所以只监听 loopback 是硬约束，不是可选项。要共享给别的机器，请自己在前面套 TLS/认证层，别改 `--socks`。
- **不是全局 VPN**。只有显式走 `127.0.0.1:1080` 的程序才被代理；不接管系统默认路由，也不会自动劫持其他进程。
- **WARP endpoint 需可达**。隧道自身的 UDP 2408 走真实网络，被墙/被封就无解。
- **state 文件含 WireGuard 私钥**（权限 0600）。备份/迁移时按密钥处理。
- **不提供 Docker 镜像**（项目定位就是单二进制 + systemd）。

---

## 目录结构

```text
warpd/
├── Cargo.toml
├── README.md                     ← 本文件
├── deploy/
│   ├── warpd.service             ← systemd unit
│   └── install.sh                ← 安装脚本
└── src/
    ├── main.rs       CLI、启动编排、信号、清理
    ├── lib.rs        模块导出与架构总注释
    ├── preflight.rs  平台/权限/内核 wireguard 预检
    ├── warp.rs       WARP 注册（consumer / Zero Trust）
    ├── wgkey.rs      X25519 密钥生成
    ├── wgnet.rs      netlink 建/配/删内核 WireGuard 接口
    ├── policyrt.rs   fwmark rule + 独立路由表 + src_valid_mark
    ├── dialer.rs     SO_MARK 出站 socket + marked DNS
    ├── socks5.rs     SOCKS5 服务器（只 CONNECT，仅 loopback）
    └── store.rs      WARP 配置持久化（0600）
```

## 许可

MIT
