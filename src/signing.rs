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

/// Serialize `value` to the byte string signatures are computed over.
///
/// This is `serde_json`'s default serialization, which is deterministic for the
/// signed bodies because they are composed only of scalars and ordered `Vec`s
/// (serde emits struct fields in declaration order). It is deliberately NOT a
/// re-sorting canonicalizer: changing the byte representation would invalidate
/// every already-signed v1 manifest and pointer without a format version bump.
///
/// Invariant: signed bodies must not contain a `HashMap`/`BTreeMap` or
/// `#[serde(flatten)]`ed map, whose serialization order is not guaranteed. The
/// current bodies satisfy this; `signed_body_serializes_in_declaration_order`
/// guards the representation against an accidental re-sort or reorder.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
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
