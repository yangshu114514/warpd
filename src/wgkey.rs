//! `WireGuard` 密钥生成与转换工具
//!
//! `WireGuard` 使用 Curve25519 (X25519) 密钥对。
//! 私钥是 32 字节随机数（做 clamping），公钥 = X25519(私钥, basepoint)。
//! 两者都以标准 base64 编码存储。

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// 生成一对新的 `WireGuard` 密钥，返回 (`private_key_b64`, `public_key_b64`)
#[must_use]
pub fn generate_keypair() -> (String, String) {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let secret = StaticSecret::from(raw);
    let public = PublicKey::from(&secret);

    // WireGuard 私钥就是 clamping 后的原始字节
    let priv_b64 = B64.encode(secret.to_bytes());
    let pub_b64 = B64.encode(public.as_bytes());
    (priv_b64, pub_b64)
}

/// 从 base64 私钥推导出 base64 公钥
///
/// # Errors
///
/// 输入不是合法 base64，或解码后长度不是 32 字节。
pub fn public_key_from_private(priv_b64: &str) -> Result<String> {
    let raw = B64
        .decode(priv_b64.trim())
        .context("private key is not valid base64")?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;
    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    Ok(B64.encode(public.as_bytes()))
}

/// 校验一个字符串是否是合法的 `WireGuard` base64 密钥（32 字节）
#[must_use]
pub fn is_valid_key(s: &str) -> bool {
    match B64.decode(s.trim()) {
        Ok(v) => v.len() == 32,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_derive() {
        let (priv_k, pub_k) = generate_keypair();
        assert!(is_valid_key(&priv_k));
        assert!(is_valid_key(&pub_k));
        // 公钥必须能从私钥重新推导出来
        let derived = public_key_from_private(&priv_k).unwrap();
        assert_eq!(derived, pub_k);
    }

    #[test]
    fn test_known_vector() {
        // 用固定私钥验证推导稳定
        let priv_k = "njCoJl6z/H4VyDIctLsucR7PbFNsBisDWu/Y92sPeHg=";
        let pub_k = public_key_from_private(priv_k).unwrap();
        assert!(is_valid_key(&pub_k));
        // 幂等
        assert_eq!(public_key_from_private(priv_k).unwrap(), pub_k);
    }

    #[test]
    fn test_invalid_key() {
        assert!(!is_valid_key("not-base64!!!"));
        assert!(!is_valid_key("aGVsbG8=")); // 5 字节，长度不对
    }
}
