use anyhow::{anyhow, bail, Context, Result};
use ed25519_compact::{KeyPair, Noise, PublicKey, SecretKey, Seed, Signature};
use serde::{Deserialize, Serialize};
use std::{env, fs};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureBlock {
    pub scheme: String,
    pub key_id: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustKey {
    pub scheme: String,
    pub public_key: String,
}

/// Serialize `value` to a canonical JSON byte string: object keys sorted, no
/// insignificant whitespace. Signatures are computed over this form, so the
/// result must be stable across runs and independent of struct field order or
/// map backing (e.g. a future `HashMap` field would otherwise serialize in a
/// nondeterministic order and break verification).
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    let mut out = Vec::new();
    write_canonical(&value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key)?;
                out.push(b':');
                write_canonical(&map[key], out)?;
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        scalar => serde_json::to_writer(&mut *out, scalar)?,
    }
    Ok(())
}

pub fn sign_body<T: Serialize>(body: &T, key_id: &str, key_spec: &str) -> Result<SignatureBlock> {
    let key_hex = resolve_secret_spec(key_spec)?;
    let sk = secret_key_from_hex(&key_hex)?;
    let bytes = canonical_json(body)?;
    let sig = sk.sign(&bytes, Some(Noise::default()));
    Ok(SignatureBlock {
        scheme: "ed25519".to_string(),
        key_id: key_id.to_string(),
        sig: hex::encode(sig.as_ref()),
    })
}

pub fn verify_body<T: Serialize>(
    body: &T,
    signature: &SignatureBlock,
    public_key_hex: &str,
) -> Result<()> {
    if signature.scheme != "ed25519" {
        bail!("unsupported signature scheme {}", signature.scheme);
    }
    let pk_bytes = hex::decode(public_key_hex).context("decode public key hex")?;
    let sig_bytes = hex::decode(&signature.sig).context("decode signature hex")?;
    let pk = PublicKey::from_slice(&pk_bytes).map_err(|_| anyhow!("invalid public key"))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| anyhow!("invalid signature"))?;
    let bytes = canonical_json(body)?;
    pk.verify(&bytes, &sig)
        .map_err(|_| anyhow!("signature verification failed"))
}

#[allow(dead_code)]
pub fn public_key_from_secret_spec(key_spec: &str) -> Result<String> {
    let key_hex = resolve_secret_spec(key_spec)?;
    let sk = secret_key_from_hex(&key_hex)?;
    Ok(hex::encode(sk.public_key().as_ref()))
}

pub fn resolve_secret_spec(spec: &str) -> Result<String> {
    if let Some(name) = spec.strip_prefix("env:") {
        env::var(name).with_context(|| format!("read signing key env var {name}"))
    } else if let Some(path) = spec.strip_prefix("file:") {
        Ok(fs::read_to_string(path)
            .with_context(|| format!("read signing key file {path}"))?
            .trim()
            .to_string())
    } else {
        Ok(spec.trim().to_string())
    }
}

fn secret_key_from_hex(key_hex: &str) -> Result<SecretKey> {
    let bytes = hex::decode(key_hex.trim()).context("decode secret key hex")?;
    match bytes.len() {
        32 => {
            let seed = Seed::from_slice(&bytes).map_err(|_| anyhow!("invalid ed25519 seed"))?;
            Ok(KeyPair::from_seed(seed).sk)
        }
        64 => SecretKey::from_slice(&bytes).map_err(|_| anyhow!("invalid ed25519 secret key")),
        n => bail!("ed25519 signing key must be 32-byte seed or 64-byte secret key, got {n} bytes"),
    }
}
