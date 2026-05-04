use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    pub size: u64,
    pub sha256: String,
    pub blake3: String,
}

pub fn hash_file(path: &Path) -> Result<Hashes> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut sha = Sha256::new();
    let mut b3 = blake3::Hasher::new();
    let mut size = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        sha.update(&buf[..n]);
        b3.update(&buf[..n]);
    }
    Ok(Hashes {
        size,
        sha256: hex::encode(sha.finalize()),
        blake3: b3.finalize().to_hex().to_string(),
    })
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut sha = Sha256::new();
    sha.update(bytes);
    hex::encode(sha.finalize())
}
