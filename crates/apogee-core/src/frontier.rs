//! Validation, normalization, and local caching for public display artwork.

use std::collections::HashMap;
use std::fs;
use std::io::{BufWriter, Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use apogee_fetch::{DownloadSpec, Fetcher, Priority, Validator};
use image::{ImageFormat, ImageReader};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::command::BannerData;

const BANNER_BYTES_MAX: u64 = 8 * 1024 * 1024;
const BANNER_WIDTH_MAX: u32 = 8_192;
const BANNER_HEIGHT_MAX: u32 = 4_096;
const BANNER_PIXELS_MAX: u64 = 16_777_216;
const BANNER_ALLOC_MAX: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct FrontierAssets {
    fetcher: Fetcher,
    root: PathBuf,
    links: Arc<Mutex<HashMap<String, Url>>>,
    artwork_lock: Arc<tokio::sync::Mutex<()>>,
}

impl FrontierAssets {
    pub(crate) fn new(fetcher: Fetcher, root: PathBuf) -> Self {
        Self {
            fetcher,
            root,
            links: Arc::new(Mutex::new(HashMap::new())),
            artwork_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub(crate) fn register_link(&self, raw: &str) -> Option<String> {
        let url = Url::parse(raw).ok()?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.host_str().is_none()
            || url.port().is_some_and(|port| port != 443)
        {
            return None;
        }
        let id = digest_name(b"link\0", url.as_str().as_bytes());
        self.links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.clone(), url);
        Some(id)
    }

    pub(crate) fn resolve_link(&self, id: &str) -> Option<Url> {
        self.links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    pub(crate) async fn cache_banners(
        &self,
        rows: Vec<sqex_proto::Banner>,
        cancel: &CancellationToken,
    ) -> Vec<BannerData> {
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id = self.register_link(&row.link).unwrap_or_default();
            let artwork = match self.cache_artwork(&row.lsb_banner, cancel).await {
                Ok(path) => Some(path),
                Err(detail) => {
                    tracing::warn!(%detail, "banner artwork was rejected");
                    None
                }
            };
            out.push(BannerData {
                id,
                artwork,
                order_priority: row.order_priority,
                fix_order: row.fix_order,
            });
        }
        out
    }

    async fn cache_artwork(
        &self,
        raw_url: &str,
        cancel: &CancellationToken,
    ) -> Result<PathBuf, String> {
        let url = Url::parse(raw_url).map_err(|_| "invalid artwork URL".to_owned())?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.host_str().is_none()
            || url.port().is_some_and(|port| port != 443)
        {
            return Err("artwork URL is not an ordinary HTTPS URL".to_owned());
        }

        let _guard = self.artwork_lock.lock().await;
        let key = digest_name(b"artwork\0", url.as_str().as_bytes());
        let banners = self.root.join("banners");
        let final_path = banners.join(format!("{key}.png"));
        if final_path.is_file() {
            return Ok(final_path);
        }
        let incoming = banners.join("incoming");
        fs::create_dir_all(&incoming).map_err(|error| format!("create artwork cache: {error}"))?;
        let source = incoming.join(format!("{key}.source"));
        let spec = DownloadSpec::builder(url, &source, Validator::None)
            .allow_unverified()
            .overwrite()
            .resume(false)
            .priority(Priority::Low)
            .max_len(BANNER_BYTES_MAX)
            .allowed_content_types(["image/jpeg", "image/png"])
            .build()
            .map_err(|error| format!("artwork request: {error}"))?;
        let downloaded = self
            .fetcher
            .download(&spec, None, cancel.clone())
            .await
            .map_err(|error| format!("artwork download: {error}"));
        if let Err(error) = downloaded {
            remove_download_scratch(&source);
            return Err(error);
        }
        let normalized = normalize_image(&source, &final_path);
        remove_download_scratch(&source);
        normalized?;
        Ok(final_path)
    }
}

fn remove_download_scratch(source: &Path) {
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(PathBuf::from(format!("{}.part", source.display())));
    let _ = fs::remove_file(PathBuf::from(format!("{}.apdl", source.display())));
}

fn normalize_image(source: &Path, destination: &Path) -> Result<(), String> {
    let bytes = fs::read(source).map_err(|error| format!("read artwork: {error}"))?;
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|error| format!("inspect artwork: {error}"))?;
    let format = reader
        .format()
        .filter(|format| matches!(format, ImageFormat::Jpeg | ImageFormat::Png))
        .ok_or_else(|| "artwork is not JPEG or PNG".to_owned())?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(BANNER_WIDTH_MAX);
    limits.max_image_height = Some(BANNER_HEIGHT_MAX);
    limits.max_alloc = Some(BANNER_ALLOC_MAX);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|error| format!("decode artwork: {error}"))?;
    let pixels = u64::from(image.width())
        .checked_mul(u64::from(image.height()))
        .ok_or_else(|| "artwork dimensions overflow".to_owned())?;
    if pixels > BANNER_PIXELS_MAX {
        return Err("artwork has too many pixels".to_owned());
    }
    if !matches!(format, ImageFormat::Jpeg | ImageFormat::Png) {
        return Err("artwork format changed during decode".to_owned());
    }
    let temp = destination.with_extension("png.tmp");
    let result = (|| {
        let file =
            fs::File::create(&temp).map_err(|error| format!("create artwork output: {error}"))?;
        let mut writer = BufWriter::new(file);
        image
            .write_to(&mut writer, ImageFormat::Png)
            .map_err(|error| format!("encode artwork: {error}"))?;
        writer
            .flush()
            .map_err(|error| format!("flush artwork: {error}"))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| format!("sync artwork: {error}"))?;
        fs::rename(&temp, destination).map_err(|error| format!("publish artwork: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result?;
    Ok(())
}

fn digest_name(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    let digest = digest.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ordinary_https_links_enter_the_registry() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let assets = FrontierAssets::new(Fetcher::builder().build()?, root.path().to_path_buf());
        let id = assets
            .register_link("https://example.invalid/news?id=1")
            .ok_or("valid link was refused")?;
        assert_eq!(
            assets.resolve_link(&id).map(|url| url.to_string()),
            Some("https://example.invalid/news?id=1".to_owned())
        );
        for rejected in [
            "file:///etc/passwd",
            "http://example.invalid/",
            "https://user@example.invalid/",
            "https://example.invalid:444/",
            "not a url",
        ] {
            assert!(
                assets.register_link(rejected).is_none(),
                "accepted {rejected}"
            );
        }
        Ok(())
    }

    #[test]
    fn validated_artwork_is_reencoded_as_png() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("source.jpg");
        let destination = root.path().join("normalized.png");
        image::DynamicImage::new_rgb8(8, 4).save_with_format(&source, ImageFormat::Jpeg)?;

        normalize_image(&source, &destination).map_err(std::io::Error::other)?;

        assert_eq!(
            image::ImageReader::open(destination)?
                .with_guessed_format()?
                .format(),
            Some(ImageFormat::Png)
        );
        Ok(())
    }

    #[test]
    fn corrupt_artwork_is_never_published() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("source.png");
        let destination = root.path().join("normalized.png");
        fs::write(&source, b"not an image")?;

        assert!(normalize_image(&source, &destination).is_err());
        assert!(!destination.exists());
        Ok(())
    }
}
