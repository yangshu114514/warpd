#!/usr/bin/env bash
#
# warpd 安装脚本
#   1. 检查 root
#   2. 装依赖（内核 wireguard 模块 / wireguard-tools / iproute2）
#   3. 装二进制到 /usr/local/bin/warpd
#   4. 建系统用户与状态目录
#   5. 装 systemd unit 并启用服务
#
# 用法：
#   sudo ./deploy/install.sh                    # 自动在常见位置找二进制
#   sudo ./deploy/install.sh /path/to/warpd     # 显式指定二进制
#   sudo ./deploy/install.sh --no-start         # 只装不启动
#
set -euo pipefail

BIN_DEST="/usr/local/bin/warpd"
UNIT_DEST="/etc/systemd/system/warpd.service"
STATE_DIR="/var/lib/warpd"
DOC_DIR="/usr/local/share/doc/warpd"
SVC_USER="warpd"
SVC_GROUP="warpd"

START_SERVICE=1
BIN_SRC=""

# ── 参数解析 ────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --no-start) START_SERVICE=0 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "unknown option: $arg" >&2
      exit 2
      ;;
    *)
      BIN_SRC="$arg"
      ;;
  esac
done

# ── 小工具 ──────────────────────────────────────────────────────────────────
log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    warn "install.sh 失败（退出码 $rc）。检查上面的报错。"
  fi
}
trap on_exit EXIT

# ── 1. 必须 root ────────────────────────────────────────────────────────────
# 用 bash 内建的 $EUID 而不是 "$(id -u)"：外部 id 命令缺失时命令替换返回空串，
# "[ '' -ne 0 ]" 只报一句 "integer expected" 然后条件为假，检查会被静默绕过。
if [ "$EUID" -ne 0 ]; then
  die "必须以 root 运行：sudo $0"
fi

# ── 2. 平台与包管理器 ───────────────────────────────────────────────────────
if [ "$(uname -s)" != "Linux" ]; then
  die "warpd 只支持 Linux（需要 netlink / SO_MARK / fwmark 策略路由 / 内核 wireguard）"
fi

PKG=""
if command -v apt-get >/dev/null 2>&1; then
  PKG="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG="dnf"
elif command -v yum >/dev/null 2>&1; then
  PKG="yum"
elif command -v pacman >/dev/null 2>&1; then
  PKG="pacman"
elif command -v apk >/dev/null 2>&1; then
  PKG="apk"
elif command -v zypper >/dev/null 2>&1; then
  PKG="zypper"
else
  warn "未识别到支持的包管理器，跳过依赖安装（请自行确认内核 wireguard 可用）"
fi

install_deps() {
  [ -n "$PKG" ] || return 0
  log "安装依赖（$PKG）"

  case "$PKG" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      # wireguard-tools 只是给运维验证用（wg show）；warpd 本身不调用 wg。
      # 内核模块在较新内核里已内置，wireguard-modules 在部分版本不存在，故容错。
      apt-get install -y --no-install-recommends wireguard-tools iproute2 kmod ca-certificates || true
      apt-get install -y --no-install-recommends wireguard-modules 2>/dev/null \
        || log "wireguard-modules 包不可用（内核应已内置 CONFIG_WIREGUARD）"
      ;;
    dnf|yum)
      "$PKG" install -y wireguard-tools iproute kmod ca-certificates || true
      ;;
    pacman)
      pacman -Sy --noconfirm --needed wireguard-tools iproute2 kmod ca-certificates || true
      ;;
    apk)
      apk add --no-cache wireguard-tools iproute2 kmod ca-certificates || true
      ;;
    zypper)
      zypper --non-interactive install wireguard-tools iproute2 kmod ca-certificates || true
      ;;
  esac
}

# ── 3. 加载内核 wireguard 模块 ──────────────────────────────────────────────
ensure_wireguard_module() {
  if [ -d /sys/module/wireguard ]; then
    log "内核 wireguard 模块已加载"
  else
    if command -v modprobe >/dev/null 2>&1 && modprobe wireguard 2>/dev/null; then
      log "已加载内核 wireguard 模块"
    elif [ -d /sys/module/wireguard ]; then
      :
    else
      warn "未能加载 wireguard 模块。若内核已编译进 CONFIG_WIREGUARD=y 可忽略；"
      warn "否则 warpd 启动时预检会失败（它需要内核态 WireGuard，不支持用户态实现）。"
    fi
  fi

  # 开机自动加载：非 root 用户运行的 warpd 自己没法 modprobe，
  # 必须由 systemd-modules-load 在服务启动前加载好（unit 里 After= 了它）。
  if [ -d /etc/modules-load.d ]; then
    echo "wireguard" > /etc/modules-load.d/wireguard.conf
    log "写入 /etc/modules-load.d/wireguard.conf"
  fi
}

install_deps
ensure_wireguard_module

# ── 4. 定位二进制 ───────────────────────────────────────────────────────────
if [ -z "$BIN_SRC" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  for cand in \
    "$SCRIPT_DIR/../target/x86_64-unknown-linux-musl/release/warpd" \
    "$SCRIPT_DIR/../target/release/warpd" \
    "$SCRIPT_DIR/warpd" \
    "$PWD/target/x86_64-unknown-linux-musl/release/warpd" \
    "$PWD/target/release/warpd"
  do
    if [ -f "$cand" ]; then
      BIN_SRC="$cand"
      break
    fi
  done
fi

[ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ] \
  || die "找不到 warpd 二进制。先编译（cargo build --release 或 cargo zigbuild --release --target x86_64-unknown-linux-musl），或显式传入路径：sudo $0 /path/to/warpd"

case "$(basename "$BIN_SRC")" in
  warpd|warpd.exe) ;;
  *) warn "二进制文件名不是 warpd（$(basename "$BIN_SRC")），仍继续安装" ;;
esac

log "使用二进制：$BIN_SRC"

# ── 5. 建系统用户 ───────────────────────────────────────────────────────────
# nologin 路径各发行版不同（Debian: /usr/sbin，RHEL: /sbin，BusyBox: /sbin），探测一下。
NOLOGIN="/usr/sbin/nologin"
for p in /usr/sbin/nologin /sbin/nologin /bin/false; do
  [ -x "$p" ] && NOLOGIN="$p" && break
done

group_exists() {
  getent group "$1" >/dev/null 2>&1 && return 0
  grep -q "^$1:" /etc/group 2>/dev/null
}
user_exists() {
  getent passwd "$1" >/dev/null 2>&1 && return 0
  grep -q "^$1:" /etc/passwd 2>/dev/null
}

if group_exists "$SVC_GROUP"; then
  log "用户组 $SVC_GROUP 已存在"
elif command -v groupadd >/dev/null 2>&1; then
  groupadd --system "$SVC_GROUP"
  log "创建用户组 $SVC_GROUP"
elif command -v addgroup >/dev/null 2>&1; then
  addgroup -S "$SVC_GROUP"          # Alpine / BusyBox
  log "创建用户组 $SVC_GROUP（addgroup）"
else
  die "无法创建用户组 $SVC_GROUP（既没有 groupadd 也没有 addgroup）"
fi

if user_exists "$SVC_USER"; then
  log "用户 $SVC_USER 已存在"
elif command -v useradd >/dev/null 2>&1; then
  # --no-create-home：不需要登录 shell / home；状态目录用 /var/lib/warpd
  useradd --system --gid "$SVC_GROUP" --no-create-home \
    --home-dir "$STATE_DIR" --shell "$NOLOGIN" "$SVC_USER"
  log "创建系统用户 $SVC_USER"
elif command -v adduser >/dev/null 2>&1; then
  adduser -S -D -H -G "$SVC_GROUP" -h "$STATE_DIR" -s "$NOLOGIN" "$SVC_USER"
  log "创建系统用户 $SVC_USER（adduser）"
else
  die "无法创建用户 $SVC_USER（既没有 useradd 也没有 adduser）"
fi

# ── 6. 装二进制 ─────────────────────────────────────────────────────────────
install -d -m 0755 "$(dirname "$BIN_DEST")"
# 0755 而不是 4755：提权靠 systemd 的 AmbientCapabilities，不用 setuid。
install -m 0755 -o root -g root "$BIN_SRC" "$BIN_DEST"
log "二进制已安装到 $BIN_DEST"

install -d -m 0700 -o "$SVC_USER" -g "$SVC_GROUP" "$STATE_DIR"
log "状态目录 $STATE_DIR（0700，含 WireGuard 私钥）"

# ── 7. 装文档（unit 里的 Documentation= 指到这里）────────────────────────────
SCRIPT_DIR_FOR_DOC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR_FOR_DOC/../README.md" ] || [ -f "$SCRIPT_DIR_FOR_DOC/../docs/ARCHITECTURE.md" ]; then
  install -d -m 0755 "$DOC_DIR"
  # 注意：这里必须用 if 而不是 "[ -f x ] && install ..."。
  # set -e 下一条以 && 结尾的复合命令返回 1 会直接终止脚本，
  # 而"某个文档不存在"是完全正常的（比如只拷了 deploy/ 目录）。
  if [ -f "$SCRIPT_DIR_FOR_DOC/../README.md" ]; then
    install -m 0644 "$SCRIPT_DIR_FOR_DOC/../README.md" "$DOC_DIR/README.md"
  fi
  if [ -f "$SCRIPT_DIR_FOR_DOC/../docs/ARCHITECTURE.md" ]; then
    install -m 0644 "$SCRIPT_DIR_FOR_DOC/../docs/ARCHITECTURE.md" "$DOC_DIR/ARCHITECTURE.md"
  fi
  log "文档已安装到 $DOC_DIR"
fi

# ── 8. 装 systemd unit ──────────────────────────────────────────────────────
if ! command -v systemctl >/dev/null 2>&1; then
  warn "系统没有 systemd，跳过 unit 安装。可直接运行：sudo $BIN_DEST --state $STATE_DIR/warp.json"
  exit 0
fi

SCRIPT_DIR_FOR_UNIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_SRC="$SCRIPT_DIR_FOR_UNIT/warpd.service"
[ -f "$UNIT_SRC" ] || die "找不到 $UNIT_SRC（应与本脚本同在 deploy/ 下）"

install -m 0644 -o root -g root "$UNIT_SRC" "$UNIT_DEST"
log "systemd unit 已安装到 $UNIT_DEST"

systemctl daemon-reload
log "已 daemon-reload"

# ── 9. 启用服务 ─────────────────────────────────────────────────────────────
if [ "$START_SERVICE" -eq 1 ]; then
  systemctl enable warpd >/dev/null
  log "已设置开机自启（enabled）"

  # 先跑一次预检，把环境问题在当前终端暴露出来，而不是埋在 journal 里
  log "运行环境预检：$BIN_DEST --check-only"
  if ! "$BIN_DEST" --check-only; then
    warn "预检失败，服务不会启动。修好上面的问题后再执行：systemctl start warpd"
    exit 1
  fi

  systemctl restart warpd
  sleep 1

  if systemctl is-active --quiet warpd; then
    log "warpd 已启动"
    printf '\n'
    printf '  查看状态:  systemctl status warpd\n'
    printf '  实时日志:  journalctl -u warpd -f\n'
    printf '  验证隧道:  wg show warp0\n'
    printf '  验证路由:  ip rule show && ip route show table 100\n'
    printf '  端到端:    curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace\n'
    printf '\n'
  else
    warn "warpd 未能保持运行，最近的日志："
    journalctl -u warpd -n 50 --no-pager || true
    exit 1
  fi
else
  log "--no-start 已指定：unit 已安装但未启用。手动启动：systemctl enable --now warpd"
fi
