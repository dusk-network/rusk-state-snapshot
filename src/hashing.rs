use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    pub size: u64,
    pub sha256: String,
    pub blake3: String,
}

/// A writer that computes the size, SHA-256, and BLAKE3 of everything written
/// through it, so an artifact can be hashed as it is produced instead of read
/// back afterwards. Wrap it around the final output file (outside any encoder)
/// so the hashes cover the bytes that land on disk.
pub struct HashingWriter<W> {
    inner: W,
    sha: Sha256,
    b3: blake3::Hasher,
    size: u64,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            sha: Sha256::new(),
            b3: blake3::Hasher::new(),
            size: 0,
        }
    }

    /// Consume the writer, returning the wrapped writer and the hashes of all
    /// bytes written through it.
    pub fn finish(self) -> (W, Hashes) {
        let hashes = Hashes {
            size: self.size,
            sha256: hex::encode(self.sha.finalize()),
            blake3: self.b3.finalize().to_hex().to_string(),
        };
        (self.inner, hashes)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sha.update(&buf[..n]);
        self.b3.update(&buf[..n]);
        self.size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
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
