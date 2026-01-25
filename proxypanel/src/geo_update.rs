use anyhow::{anyhow, Result};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::{
    app::AppState,
    geo::{self, GEO_DB_FILENAME},
};

const UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);
const MIN_DB_SIZE: usize = 100_000;

const GEO_URLS: [&str; 3] = [
    "https://git.io/GeoLite2-Country.mmdb",
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/main/GeoLite2-Country.mmdb",
    "https://github.com/P3TERX/GeoLite.mmdb/raw/main/GeoLite2-Country.mmdb",
];

pub fn start_geo_updater(state: Arc<RwLock<AppState>>, data_dir: PathBuf) {
    tokio::spawn(async move {
        if let Err(err) = refresh_geo_db(&state, &data_dir).await {
            warn!("Geo DB refresh failed: {}", err);
        }
        loop {
            tokio::time::sleep(UPDATE_INTERVAL).await;
            if let Err(err) = refresh_geo_db(&state, &data_dir).await {
                warn!("Geo DB refresh failed: {}", err);
            }
        }
    });
}

async fn refresh_geo_db(state: &Arc<RwLock<AppState>>, data_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(data_dir).await?;
    let path = data_dir.join(GEO_DB_FILENAME);
    let should_download = should_download(&path)?;
    let mut downloaded = false;

    if should_download {
        match download_geo_db(&path).await {
            Ok(true) => {
                downloaded = true;
            }
            Ok(false) => {}
            Err(err) => {
                warn!("Geo DB download failed: {}", err);
            }
        }
    }

    let needs_load = downloaded || state.read().await.geo_db.is_none();
    if needs_load {
        if let Ok(Some(db)) = geo::load_geo_db(data_dir) {
            state.write().await.geo_db = Some(db);
            info!("Geo DB loaded");
        }
    }

    Ok(())
}

fn should_download(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(true);
    }
    let metadata = std::fs::metadata(path)?;
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let elapsed = modified.elapsed().unwrap_or(UPDATE_INTERVAL);
    Ok(elapsed >= UPDATE_INTERVAL)
}

async fn download_geo_db(path: &Path) -> Result<bool> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("proxy-panel/0.1")
        .build()?;

    for url in &GEO_URLS {
        let response = client.get(*url).send().await?;
        if !response.status().is_success() {
            warn!("Geo DB download failed ({}): {}", response.status(), url);
            continue;
        }
        let bytes = response.bytes().await?;
        if bytes.len() < MIN_DB_SIZE {
            return Err(anyhow!("Geo DB file too small"));
        }

        let tmp_path = path.with_extension("mmdb.tmp");
        tokio::fs::write(&tmp_path, &bytes).await?;
        let _ = tokio::fs::remove_file(path).await;
        tokio::fs::rename(&tmp_path, path).await?;
        info!("Geo DB downloaded from {}", url);
        return Ok(true);
    }

    Ok(false)
}
