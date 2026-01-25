use anyhow::{anyhow, Result};
use maxminddb::geoip2;
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::Path,
    sync::Arc,
};
use tracing::warn;

pub const GEO_DB_FILENAME: &str = "GeoLite2-Country.mmdb";

pub struct GeoDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

pub type SharedGeoDb = Arc<GeoDb>;

#[derive(Clone, Serialize, Deserialize)]
pub struct GeoPortEntry {
    pub country: String,
    pub port: u16,
}

#[derive(Clone, Serialize)]
pub struct GeoEntry {
    pub country: String,
    pub port: Option<u16>,
}

#[derive(Deserialize)]
pub struct GeoBlockRequest {
    pub country: String,
    pub port: Option<u16>,
}

#[derive(Deserialize)]
pub struct GeoBlockQuery {
    pub port: Option<u16>,
}

pub fn load_geo_db(data_dir: &Path) -> Result<Option<SharedGeoDb>> {
    let path = data_dir.join(GEO_DB_FILENAME);
    if !path.exists() {
        warn!("Geo DB not found: {}", path.display());
        return Ok(None);
    }
    let reader = maxminddb::Reader::open_readfile(&path)?;
    Ok(Some(Arc::new(GeoDb { reader })))
}

pub fn lookup_country(db: &GeoDb, ip: IpAddr) -> Option<String> {
    let result: geoip2::Country = db.reader.lookup(ip).ok()?;
    let iso = result.country?.iso_code?;
    Some(iso.to_uppercase())
}

pub fn normalize_country(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.len() != 2 {
        return Err(anyhow!("Country code must be 2 letters"));
    }
    if !trimmed.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Err(anyhow!("Country code must be letters"));
    }
    Ok(trimmed.to_uppercase())
}

pub const GEO_SECTION_HTML: &str = r#"
    <div class="section">
      <div class="section-header">
        <h3>Geo blocklist</h3>
        <button class="toggle" data-section="geo-section" onclick="toggleSection('geo-section', this)">Hide</button>
      </div>
      <div id="geo-section">
        <div class="row">
          <input id="geo-country" placeholder="Country code (RU)">
          <input id="geo-port" placeholder="Port (optional)" size="12">
          <button onclick="addGeoBlock()">Block</button>
          <span id="geo-error" class="muted"></span>
        </div>
        <div class="muted">Requires GeoLite2-Country.mmdb in data folder.</div>
        <table>
          <thead>
            <tr><th>Country</th><th>Port</th><th>Action</th></tr>
          </thead>
          <tbody id="geo-body"></tbody>
        </table>
      </div>
    </div>
"#;

pub const GEO_REFRESH_VARS: &str = ", geoBlocks";
pub const GEO_REFRESH_CALLS: &str = ", api(\"/api/geo-blocklist\")";
pub const GEO_REFRESH_RENDER: &str = "    renderGeoBlocks(geoBlocks);\n";

pub const GEO_JS_HOOKS: &str = r#"
function renderGeoBlocks(items) {
  const body = document.getElementById("geo-body");
  if (!body) return;
  body.innerHTML = "";
  items.forEach(item => {
    const port = item.port ? item.port : "";
    const label = item.port ? item.port : "*";
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.country}</td>
      <td>${label}</td>
      <td><button onclick="removeGeoBlock('${item.country}', '${port}')">Remove</button></td>
    `;
    body.appendChild(row);
  });
}

async function addGeoBlock() {
  const country = document.getElementById("geo-country").value.trim();
  const portText = document.getElementById("geo-port").value.trim();
  const errorBox = document.getElementById("geo-error");
  errorBox.textContent = "";
  let port = null;
  if (portText) {
    port = parseInt(portText, 10);
    if (Number.isNaN(port) || port < 1 || port > 65535) {
      errorBox.textContent = "Invalid port";
      return;
    }
  }
  try {
    await api("/api/geo-blocklist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ country, port })
    });
    document.getElementById("geo-country").value = "";
    document.getElementById("geo-port").value = "";
    await refresh();
  } catch (err) {
    errorBox.textContent = err.message;
  }
}

async function removeGeoBlock(country, port) {
  const query = port ? `?port=${encodeURIComponent(port)}` : "";
  await api(`/api/geo-blocklist/${encodeURIComponent(country)}${query}`, { method: "DELETE" });
  await refresh();
}
"#;
