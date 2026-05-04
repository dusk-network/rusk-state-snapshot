use super::{ObjectMeta, ObjectStore};
use crate::{config::Endpoint, hashing, signing};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::{header::HeaderMap, Client, Method, StatusCode};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

type HmacSha256 = Hmac<Sha256>;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub struct S3Store {
    client: Client,
    endpoint: String,
    bucket: String,
    prefix: String,
    region: String,
    access_key: String,
    secret_key: String,
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
            ..
        } = endpoint
        else {
            bail!("not an s3 endpoint");
        };
        Ok(Self {
            client: Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            bucket,
            prefix: prefix.trim_matches('/').to_string(),
            region,
            access_key: signing::resolve_secret_spec(&access_key)?,
            secret_key: signing::resolve_secret_spec(&secret_key)?,
        })
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
        let headers =
            self.signed_headers(&method, &key, canonical_query, EMPTY_SHA256, extra_headers)?;
        Ok(self
            .client
            .request(method, self.url(&key, query))
            .headers(headers)
            .send()
            .await?)
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
        let key = self.object_key(path)?;
        let payload_hash = hashing::sha256_bytes(bytes);
        let headers = self.signed_headers(&Method::PUT, &key, "", &payload_hash, Vec::new())?;
        let res = self
            .client
            .put(self.url(&key, None))
            .headers(headers)
            .body(bytes.to_vec())
            .send()
            .await?;
        if !res.status().is_success() {
            bail!("s3 put {path} failed with {}", res.status());
        }
        Ok(())
    }

    async fn put_file(&self, path: &str, source: &Path) -> Result<()> {
        let key = self.object_key(path)?;
        let payload_hash = hashing::hash_file(source)?.sha256;
        let headers = self.signed_headers(&Method::PUT, &key, "", &payload_hash, Vec::new())?;
        let file = tokio::fs::File::open(source).await?;
        let size = file.metadata().await?.len();
        let body = reqwest::Body::wrap_stream(ReaderStream::new(file));
        let res = self
            .client
            .put(self.url(&key, None))
            .headers(headers)
            .header(reqwest::header::CONTENT_LENGTH, size)
            .body(body)
            .send()
            .await?;
        if !res.status().is_success() {
            bail!("s3 put file {path} failed with {}", res.status());
        }
        Ok(())
    }

    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        let from_key = self.object_key(from)?;
        let to_key = self.object_key(to)?;
        let copy_source = format!("/{}/{}", self.bucket, from_key);
        let headers = self.signed_headers(
            &Method::PUT,
            &to_key,
            "",
            EMPTY_SHA256,
            vec![("x-amz-copy-source", encode_copy_source(&copy_source))],
        )?;
        let res = self
            .client
            .put(self.url(&to_key, None))
            .headers(headers)
            .send()
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
        let query = format!("list-type=2&prefix={}", encode_query_value(&prefix_key));
        let res = self
            .send_empty(Method::GET, "", Some(&query), Vec::new())
            .await?;
        if !res.status().is_success() {
            bail!("s3 list {prefix} failed with {}", res.status());
        }
        let text = res.text().await?;
        let mut out = Vec::new();
        for object in extract_xml_blocks(&text, "Contents") {
            let key = extract_xml_text(object, "Key").unwrap_or_default();
            let size = extract_xml_text(object, "Size")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let modified = extract_xml_text(object, "LastModified")
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|v| v.with_timezone(&Utc));
            out.push(ObjectMeta {
                path: self.logical_path(&key),
                size,
                modified,
            });
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

impl S3Store {
    fn logical_path(&self, key: &str) -> String {
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

fn validate_object_path(path: &str) -> Result<()> {
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

fn extract_xml_blocks<'a>(text: &'a str, tag: &str) -> Vec<&'a str> {
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

fn extract_xml_text<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(&text[start..end])
}
