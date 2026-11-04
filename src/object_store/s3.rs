use super::{require_secure_url, ObjectMeta, ObjectStore};
use crate::{config::Endpoint, hashing, signing};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::{header::HeaderMap, Client, Method, StatusCode};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;

type HmacSha256 = Hmac<Sha256>;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Maximum attempts (initial try + retries) for a transient S3 request failure.
const MAX_ATTEMPTS: u32 = 5;

/// Build the shared HTTP client with a connect timeout and an inactivity
/// (read) timeout, so a stalled socket during a multi-hour, multi-gigabyte
/// upload fails instead of hanging forever. The read timeout bounds silence
/// between bytes, not total transfer time, so legitimate large streams are
/// unaffected.
fn build_client() -> Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(120))
        .build()
        .context("build s3 http client")
}

/// Retry only failures that a later attempt might succeed on: transport errors
/// and 5xx / 429 / 408 responses. 4xx (auth, not-found, bad request) are not
/// retried.
fn retryable_status(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::REQUEST_TIMEOUT
}

async fn retry_backoff(attempt: u32) {
    // 200ms, 400ms, 800ms, ... capped at ~3.2s.
    let ms = 200u64.saturating_mul(1u64 << attempt.min(4));
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Decide whether a send result should be returned or retried. Transport errors
/// and retryable statuses are retried until `MAX_ATTEMPTS`; anything else
/// (including non-retryable statuses such as 403/404) is returned so the caller
/// can inspect it.
fn classify(sent: reqwest::Result<reqwest::Response>, attempt: u32) -> RetryDecision {
    let last = attempt + 1 >= MAX_ATTEMPTS;
    match sent {
        Ok(res) if retryable_status(res.status()) && !last => RetryDecision::Retry,
        Ok(res) => RetryDecision::Return(Ok(res)),
        Err(_) if !last => RetryDecision::Retry,
        Err(err) => RetryDecision::Return(Err(err.into())),
    }
}

/// Default size at which uploads transition to multipart. 64 MiB.
pub const DEFAULT_MULTIPART_THRESHOLD: u64 = 64 * 1024 * 1024;
/// Default multipart part size. 16 MiB.
pub const DEFAULT_MULTIPART_PART_SIZE: u64 = 16 * 1024 * 1024;
/// S3 minimum part size for non-final parts.
pub const S3_MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
/// S3 maximum part count.
pub const S3_MAX_PARTS: u64 = 10_000;

pub struct S3Store {
    client: Client,
    endpoint: String,
    bucket: String,
    prefix: String,
    region: String,
    access_key: String,
    secret_key: String,
    multipart_threshold: u64,
    multipart_part_size: u64,
}

enum RetryDecision {
    Return(Result<reqwest::Response>),
    Retry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadPlan {
    Single {
        size: u64,
    },
    Multipart {
        size: u64,
        part_size: u64,
        parts: u64,
    },
}

impl S3Store {
    pub fn new(endpoint: Endpoint) -> Result<Self> {
        let Endpoint::S3 {
            endpoint,
            bucket,
            prefix,
            region,
            access_key,
            secret_key,
            multipart_threshold,
            multipart_part_size,
            ..
        } = endpoint
        else {
            bail!("not an s3 endpoint");
        };
        let part_size = multipart_part_size.unwrap_or(DEFAULT_MULTIPART_PART_SIZE);
        if part_size < S3_MIN_PART_SIZE {
            bail!(
                "multipart_part_size must be at least {} bytes (S3 minimum)",
                S3_MIN_PART_SIZE
            );
        }
        require_secure_url(&endpoint)?;
        Ok(Self {
            client: build_client()?,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            bucket,
            prefix: prefix.trim_matches('/').to_string(),
            region,
            access_key: signing::resolve_secret_spec(&access_key)?,
            secret_key: signing::resolve_secret_spec(&secret_key)?,
            multipart_threshold: multipart_threshold.unwrap_or(DEFAULT_MULTIPART_THRESHOLD),
            multipart_part_size: part_size,
        })
    }

    /// Decide upload strategy for a file of given size.
    pub fn upload_plan(&self, size: u64) -> UploadPlan {
        if size < self.multipart_threshold {
            return UploadPlan::Single { size };
        }
        let part_size = if size.div_ceil(self.multipart_part_size) > S3_MAX_PARTS {
            // Recompute to fit within S3_MAX_PARTS.
            let needed = size.div_ceil(S3_MAX_PARTS);
            needed.max(S3_MIN_PART_SIZE)
        } else {
            self.multipart_part_size
        };
        let parts = size.div_ceil(part_size);
        UploadPlan::Multipart {
            size,
            part_size,
            parts,
        }
    }

    pub(crate) fn object_key(&self, path: &str) -> Result<String> {
        if path.is_empty() {
            return Ok(String::new());
        }
        validate_object_path(path)?;
        let rel = if !self.prefix.is_empty() && self.prefix == "v1" {
            path.strip_prefix("v1/").unwrap_or(path)
        } else {
            path
        };
        if self.prefix.is_empty() {
            Ok(rel.to_string())
        } else {
            Ok(format!("{}/{}", self.prefix, rel))
        }
    }

    fn url(&self, key: &str, query: Option<&str>) -> String {
        let mut url = format!("{}/{}", self.endpoint, encode_segment(&self.bucket));
        if !key.is_empty() {
            url.push('/');
            url.push_str(
                &key.split('/')
                    .map(encode_segment)
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
        if let Some(query) = query {
            url.push('?');
            url.push_str(query);
        }
        url
    }

    fn canonical_uri(&self, key: &str) -> String {
        if key.is_empty() {
            format!("/{}", encode_segment(&self.bucket))
        } else {
            format!(
                "/{}/{}",
                encode_segment(&self.bucket),
                key.split('/')
                    .map(encode_segment)
                    .collect::<Vec<_>>()
                    .join("/")
            )
        }
    }

    fn signed_headers(
        &self,
        method: &Method,
        key: &str,
        canonical_query: &str,
        payload_sha256: &str,
        extra_headers: Vec<(&str, String)>,
    ) -> Result<HeaderMap> {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let endpoint_url = reqwest::Url::parse(&self.endpoint)?;
        let mut host = endpoint_url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("s3 endpoint has no host"))?
            .to_string();
        if let Some(port) = endpoint_url.port() {
            host = format!("{host}:{port}");
        }

        let mut signed = vec![
            ("host".to_string(), host),
            (
                "x-amz-content-sha256".to_string(),
                payload_sha256.to_string(),
            ),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        for (name, value) in extra_headers {
            signed.push((name.to_ascii_lowercase(), value.trim().to_string()));
        }
        signed.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical_headers = signed
            .iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect::<String>();
        let signed_header_names = signed
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            self.canonical_uri(key),
            canonical_query,
            canonical_headers,
            signed_header_names,
            payload_sha256
        );
        let credential_scope = format!("{date}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let signing_key = self.signing_key(&date)?;
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, credential_scope, signed_header_names, signature
        );

        let mut headers = HeaderMap::new();
        for (name, value) in signed {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes())?,
                reqwest::header::HeaderValue::from_str(&value)?,
            );
        }
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&authorization)?,
        );
        Ok(headers)
    }

    fn signing_key(&self, date: &str) -> Result<Vec<u8>> {
        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        )?;
        let k_region = hmac_sha256(&k_date, self.region.as_bytes())?;
        let k_service = hmac_sha256(&k_region, b"s3")?;
        hmac_sha256(&k_service, b"aws4_request")
    }

    async fn send_empty(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        extra_headers: Vec<(&str, String)>,
    ) -> Result<reqwest::Response> {
        let key = self.object_key(path)?;
        let canonical_query = query.unwrap_or("");
        let mut attempt = 0;
        loop {
            // Re-sign every attempt: the signature covers `x-amz-date`.
            let headers = self.signed_headers(
                &method,
                &key,
                canonical_query,
                EMPTY_SHA256,
                extra_headers.clone(),
            )?;
            let sent = self
                .client
                .request(method.clone(), self.url(&key, query))
                .headers(headers)
                .send()
                .await;
            match classify(sent, attempt) {
                RetryDecision::Return(res) => return res,
                RetryDecision::Retry => {
                    retry_backoff(attempt).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn send_with_body(
        &self,
        method: Method,
        path: &str,
        bytes: Vec<u8>,
        query: Option<&str>,
        extra_headers: Vec<(&str, String)>,
    ) -> Result<reqwest::Response> {
        let key = self.object_key(path)?;
        let payload_hash = hashing::sha256_bytes(&bytes);
        let mut attempt = 0;
        loop {
            let headers = self.signed_headers(
                &method,
                &key,
                query.unwrap_or(""),
                &payload_hash,
                extra_headers.clone(),
            )?;
            let sent = self
                .client
                .request(method.clone(), self.url(&key, query))
                .headers(headers)
                .body(bytes.clone())
                .send()
                .await;
            match classify(sent, attempt) {
                RetryDecision::Return(res) => return res,
                RetryDecision::Retry => {
                    retry_backoff(attempt).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn put_file_single(&self, path: &str, source: &Path) -> Result<()> {
        let key = self.object_key(path)?;
        let payload_hash = hashing::hash_file(source)?.sha256;
        let mut attempt = 0;
        loop {
            // Reopen and re-sign on each attempt: the body is a one-shot stream
            // and the signature covers `x-amz-date`.
            let headers = self.signed_headers(&Method::PUT, &key, "", &payload_hash, Vec::new())?;
            let file = tokio::fs::File::open(source).await?;
            let size = file.metadata().await?.len();
            let body = reqwest::Body::wrap_stream(ReaderStream::new(file));
            let sent = self
                .client
                .put(self.url(&key, None))
                .headers(headers)
                .header(reqwest::header::CONTENT_LENGTH, size)
                .body(body)
                .send()
                .await;
            match classify(sent, attempt) {
                RetryDecision::Return(res) => {
                    let res = res?;
                    if !res.status().is_success() {
                        bail!("s3 put file {path} failed with {}", res.status());
                    }
                    return Ok(());
                }
                RetryDecision::Retry => {
                    retry_backoff(attempt).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn put_file_multipart(
        &self,
        path: &str,
        source: &Path,
        plan_part_size: u64,
    ) -> Result<()> {
        let upload_id = self.create_multipart_upload(path).await?;
        let result: Result<Vec<(u32, String)>> = async {
            let mut file = tokio::fs::File::open(source).await?;
            let mut etags = Vec::new();
            let mut buf = vec![0u8; plan_part_size as usize];
            let mut part_number: u32 = 1;
            loop {
                let mut filled = 0usize;
                while filled < buf.len() {
                    let n = file.read(&mut buf[filled..]).await?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                if filled == 0 {
                    break;
                }
                let chunk = buf[..filled].to_vec();
                let etag = self
                    .upload_part(path, &upload_id, part_number, chunk)
                    .await?;
                etags.push((part_number, etag));
                part_number += 1;
                if filled < buf.len() {
                    break;
                }
            }
            if etags.is_empty() {
                bail!("multipart upload of empty file is not supported");
            }
            Ok(etags)
        }
        .await;
        match result {
            Ok(etags) => {
                self.complete_multipart_upload(path, &upload_id, etags)
                    .await
            }
            Err(err) => {
                let _ = self.abort_multipart_upload(path, &upload_id).await;
                Err(err)
            }
        }
    }

    async fn create_multipart_upload(&self, path: &str) -> Result<String> {
        let res = self
            .send_with_body(Method::POST, path, Vec::new(), Some("uploads="), Vec::new())
            .await?;
        if !res.status().is_success() {
            bail!(
                "s3 create multipart upload {path} failed with {}",
                res.status()
            );
        }
        let body = res.text().await?;
        extract_xml_text(&body, "UploadId")
            .map(|v| v.to_string())
            .ok_or_else(|| anyhow::anyhow!("create multipart response missing UploadId: {body}"))
    }

    async fn upload_part(
        &self,
        path: &str,
        upload_id: &str,
        part_number: u32,
        bytes: Vec<u8>,
    ) -> Result<String> {
        let query = format!(
            "partNumber={}&uploadId={}",
            part_number,
            encode_query_value(upload_id)
        );
        let res = self
            .send_with_body(Method::PUT, path, bytes, Some(&query), Vec::new())
            .await?;
        if !res.status().is_success() {
            bail!(
                "s3 upload part {part_number} of {path} failed with {}",
                res.status()
            );
        }
        let etag = res
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("upload part response missing ETag"))?
            .to_string();
        Ok(etag)
    }

    async fn complete_multipart_upload(
        &self,
        path: &str,
        upload_id: &str,
        parts: Vec<(u32, String)>,
    ) -> Result<()> {
        let mut body = String::from("<CompleteMultipartUpload>");
        for (number, etag) in &parts {
            body.push_str(&format!(
                "<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let query = format!("uploadId={}", encode_query_value(upload_id));
        let res = self
            .send_with_body(
                Method::POST,
                path,
                body.into_bytes(),
                Some(&query),
                Vec::new(),
            )
            .await?;
        if !res.status().is_success() {
            bail!(
                "s3 complete multipart upload {path} failed with {}",
                res.status()
            );
        }
        let response = res.text().await?;
        // S3 may return 200 with an Error body; detect that.
        if response.contains("<Error>") {
            bail!("s3 complete multipart upload returned error: {response}");
        }
        Ok(())
    }

    async fn abort_multipart_upload(&self, path: &str, upload_id: &str) -> Result<()> {
        let query = format!("uploadId={}", encode_query_value(upload_id));
        let res = self
            .send_empty(Method::DELETE, path, Some(&query), Vec::new())
            .await?;
        if !res.status().is_success() && res.status() != StatusCode::NO_CONTENT {
            bail!(
                "s3 abort multipart upload {path} failed with {}",
                res.status()
            );
        }
        Ok(())
    }

    pub(crate) fn logical_path(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else if self.prefix == "v1" {
            format!("v1/{}", key.strip_prefix("v1/").unwrap_or(key))
        } else {
            key.strip_prefix(&format!("{}/", self.prefix))
                .unwrap_or(key)
                .to_string()
        }
    }
}

#[async_trait]
impl ObjectStore for S3Store {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let res = self
            .send_empty(Method::GET, path, None, Vec::new())
            .await
            .with_context(|| format!("s3 get {path}"))?;
        if !res.status().is_success() {
            bail!("s3 get {path} failed with {}", res.status());
        }
        Ok(res.bytes().await?.to_vec())
    }

    async fn get_to_file(&self, path: &str, destination: &Path) -> Result<()> {
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let res = self.send_empty(Method::GET, path, None, Vec::new()).await?;
        if !res.status().is_success() {
            bail!("s3 get {path} failed with {}", res.status());
        }
        let mut file = tokio::fs::File::create(destination).await?;
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            file.write_all(&chunk?).await?;
        }
        Ok(())
    }

    async fn put(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let res = self
            .send_with_body(Method::PUT, path, bytes.to_vec(), None, Vec::new())
            .await?;
        if !res.status().is_success() {
            bail!("s3 put {path} failed with {}", res.status());
        }
        Ok(())
    }

    async fn put_file(&self, path: &str, source: &Path) -> Result<()> {
        let size = tokio::fs::metadata(source).await?.len();
        match self.upload_plan(size) {
            UploadPlan::Single { .. } => self.put_file_single(path, source).await,
            UploadPlan::Multipart { part_size, .. } => {
                self.put_file_multipart(path, source, part_size).await
            }
        }
    }

    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        // Single-PUT server-side copy is limited to 5 GiB on AWS S3 and many
        // S3-compatible providers. Callers handling potentially large artifacts
        // should upload the artifact directly to its final key instead of
        // staging+copying. This fallback exists for small objects only.
        if let Some(meta) = self.stat(from).await? {
            const SERVER_SIDE_COPY_LIMIT: u64 = 5 * 1024 * 1024 * 1024;
            if meta.size > SERVER_SIDE_COPY_LIMIT {
                bail!(
                    "s3 server-side single copy of {from} ({} bytes) exceeds 5 GiB limit; \
                     upload directly to the destination instead",
                    meta.size
                );
            }
        }
        let from_key = self.object_key(from)?;
        let copy_source = format!("/{}/{}", self.bucket, from_key);
        let res = self
            .send_empty(
                Method::PUT,
                to,
                None,
                vec![("x-amz-copy-source", encode_copy_source(&copy_source))],
            )
            .await?;
        if !res.status().is_success() {
            bail!("s3 copy {from} to {to} failed with {}", res.status());
        }
        Ok(())
    }

    async fn stat(&self, path: &str) -> Result<Option<ObjectMeta>> {
        let res = self
            .send_empty(Method::HEAD, path, None, Vec::new())
            .await?;
        if res.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status().is_success() {
            bail!("s3 head {path} failed with {}", res.status());
        }
        let size = res
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let modified = res
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok())
            .map(DateTime::<Utc>::from);
        Ok(Some(ObjectMeta {
            path: path.to_string(),
            size,
            modified,
        }))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.stat(path).await?.is_some())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<ObjectMeta>> {
        validate_object_path(prefix)?;
        let prefix_key = self.object_key(prefix)?;
        let mut out = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            // Canonical query parameters must be sorted alphabetically by key.
            let mut params: Vec<(String, String)> =
                vec![("list-type".to_string(), "2".to_string())];
            if let Some(token) = &continuation {
                params.push(("continuation-token".to_string(), encode_query_value(token)));
            }
            params.push(("prefix".to_string(), encode_query_value(&prefix_key)));
            params.sort_by(|a, b| a.0.cmp(&b.0));
            let query = params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");
            let res = self
                .send_empty(Method::GET, "", Some(&query), Vec::new())
                .await?;
            if !res.status().is_success() {
                bail!("s3 list {prefix} failed with {}", res.status());
            }
            let text = res.text().await?;
            for object in extract_xml_blocks(&text, "Contents") {
                let key = extract_xml_text(object, "Key").unwrap_or_default();
                let size = extract_xml_text(object, "Size")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let modified = extract_xml_text(object, "LastModified")
                    .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                    .map(|v| v.with_timezone(&Utc));
                out.push(ObjectMeta {
                    path: self.logical_path(key),
                    size,
                    modified,
                });
            }
            let truncated = extract_xml_text(&text, "IsTruncated")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !truncated {
                break;
            }
            let next = extract_xml_text(&text, "NextContinuationToken")
                .map(|v| v.to_string())
                .ok_or_else(|| {
                    anyhow::anyhow!("s3 list reported truncated without NextContinuationToken")
                })?;
            continuation = Some(next);
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let res = self
            .send_empty(Method::DELETE, path, None, Vec::new())
            .await?;
        if !res.status().is_success() && res.status() != StatusCode::NOT_FOUND {
            bail!("s3 delete {path} failed with {}", res.status());
        }
        Ok(())
    }
}

pub(crate) fn validate_object_path(path: &str) -> Result<()> {
    if path.starts_with('/') || path.split('/').any(|part| part == "..") {
        bail!("unsafe object path {path}");
    }
    Ok(())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn encode_segment(input: &str) -> String {
    percent_encode(input, false)
}

fn encode_query_value(input: &str) -> String {
    percent_encode(input, true)
}

fn encode_copy_source(input: &str) -> String {
    input
        .split('/')
        .map(|part| percent_encode(part, false))
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::new();
    for byte in input.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (!encode_slash && byte == b'/');
        if keep {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub(crate) fn extract_xml_blocks<'a>(text: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        rest = &rest[start + open.len()..];
        if let Some(end) = rest.find(&close) {
            out.push(&rest[..end]);
            rest = &rest[end + close.len()..];
        } else {
            break;
        }
    }
    out
}

pub(crate) fn extract_xml_text<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(&text[start..end])
}

/// Parse one page of a ListObjectsV2 XML response. Returns the entries (raw S3
/// keys and sizes) and the `NextContinuationToken` if the response was
/// truncated.
#[allow(dead_code)]
pub fn parse_list_page(text: &str) -> (Vec<(String, u64)>, Option<String>) {
    let mut out = Vec::new();
    for object in extract_xml_blocks(text, "Contents") {
        let key = extract_xml_text(object, "Key")
            .unwrap_or_default()
            .to_string();
        let size = extract_xml_text(object, "Size")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        out.push((key, size));
    }
    let next = if extract_xml_text(text, "IsTruncated")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        extract_xml_text(text, "NextContinuationToken").map(|v| v.to_string())
    } else {
        None
    };
    (out, next)
}
