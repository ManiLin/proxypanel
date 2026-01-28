use crate::geo;
use crate::geo_update;
use crate::port_range;
use crate::protocol::ProtocolMode;
use crate::udp_proxy;
use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, Path, Query, State},
    http::{Request, StatusCode},
    response::{Html, Response},
    routing::{delete, get, post},
    Json, Router,
    middleware::{self, Next},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path as StdPath, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

// Middleware функция для проверки IP адреса
async fn ip_filter_middleware(
    State(config): State<Arc<AppConfig>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, StatusCode> {
    // Если нет ограничений по сети, разрешаем все
    if config.allowed_networks.is_empty() {
        return Ok(next.run(request).await);
    }

    let client_ip = addr.ip();
    
    // Проверяем каждый IP/сеть в разрешенном списке
    for network in &config.allowed_networks {
        if is_ip_allowed(client_ip, network) {
            return Ok(next.run(request).await);
        }
    }

    warn!("Access denied from IP: {}", client_ip);
    Err(StatusCode::FORBIDDEN)
}

// Функция проверки IP в сети CIDR
fn is_ip_allowed(ip: IpAddr, network: &str) -> bool {
    if let Some((network_str, mask_str)) = network.split_once('/') {
        if let (Ok(network_ip), Ok(mask)) = (network_str.parse::<IpAddr>(), mask_str.parse::<u8>()) {
            return ip_in_network(ip, network_ip, mask);
        }
    } else if let Ok(network_ip) = network.parse::<IpAddr>() {
        return ip == network_ip;
    }
    false
}

// Проверка входит ли IP в сеть
fn ip_in_network(ip: IpAddr, network: IpAddr, mask: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let ip_u32 = u32::from(ip);
            let network_u32 = u32::from(network);
            let mask_u32 = if mask >= 32 { 0xFFFFFFFF } else { !0u32 >> mask };
            (ip_u32 & mask_u32) == (network_u32 & mask_u32)
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let ip_u128 = u128::from(ip);
            let network_u128 = u128::from(network);
            let mask_u128 = if mask >= 128 { 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF } else { !0u128 >> mask };
            (ip_u128 & mask_u128) == (network_u128 & mask_u128)
        }
        _ => false,
    }
}

const STATE_FILE: &str = "state.json";
const MAX_HISTORY: usize = 10_000;

#[derive(Clone)]
pub struct AppConfig {
    pub http_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub allowed_networks: Vec<String>,
}

impl AppConfig {
    pub fn new(http_addr: &str, data_dir: &str, allowed_networks: Vec<String>) -> Result<Self> {
        let http_addr: SocketAddr = http_addr
            .parse()
            .map_err(|_| anyhow!("Invalid http-addr: {}", http_addr))?;
        Ok(Self {
            http_addr,
            data_dir: PathBuf::from(data_dir),
            allowed_networks,
        })
    }
}

pub async fn run_app(config: AppConfig, shutdown: CancellationToken) -> Result<()> {
    let state = Arc::new(RwLock::new(load_state(&config.data_dir).await?));
    geo_update::start_geo_updater(state.clone(), config.data_dir.clone());

    let rules_to_start = {
        let guard = state.read().await;
        guard
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .cloned()
            .collect::<Vec<_>>()
    };

    for rule in rules_to_start {
        if let Err(err) = start_rule_listeners(&state, &rule).await {
            warn!(
                "Failed to start listener {} -> {}: {}",
                rule.listen_addr, rule.target_addr, err
            );
            disable_rule_after_start_failure(&state, rule.id).await;
        }
    }

    let app = build_router(state, Arc::new(config.clone()));
    info!("Web panel listening on {}", config.http_addr);
    axum::Server::bind(&config.http_addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown.cancelled())
        .await?;
    Ok(())
}

fn build_router(state: Arc<RwLock<AppState>>, config: Arc<AppConfig>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/rules", get(list_rules).post(create_rule))
        .route("/api/rules/:id/enable", post(enable_rule))
        .route("/api/rules/:id/disable", post(disable_rule))
        .route("/api/rules/:id", delete(remove_rule).put(update_rule))
        .route("/api/active", get(active_connections))
        .route("/api/recent", get(recent_connections))
        .route("/api/ddos", get(ddos_list))
        .route("/api/blocked", get(blocked_connections))
        .route("/api/history", get(history))
        .route("/api/blocklist", get(blocklist).post(add_block))
        .route("/api/blocklist/:ip", delete(remove_block))
        .route("/api/geo-blocklist", get(geo_blocklist).post(add_geo_block))
        .route("/api/geo-blocklist/:country", delete(remove_geo_block))
        .route("/api/allowlist", get(allowlist).post(add_allow))
        .route("/api/allowlist/:ip", delete(remove_allow))
        .route("/api/allowlist-mode", get(allowlist_mode).post(update_allowlist_mode))
        .route("/api/rate-limit", get(rate_limit).post(update_rate_limit))
        .layer(middleware::from_fn_with_state(config.clone(), ip_filter_middleware))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

#[derive(Clone, Serialize, Deserialize)]
struct ProxyRule {
    id: u64,
    listen_addr: String,
    target_addr: String,
    enabled: bool,
    created_at: String,
    #[serde(default)]
    protocol: ProtocolMode,
}

#[derive(Clone, Serialize, Deserialize)]
struct PortBlockEntry {
    ip: String,
    port: u16,
}

#[derive(Clone, Serialize, Deserialize)]
struct PortAllowEntry {
    ip: String,
    port: u16,
}

#[derive(Clone, Serialize)]
struct BlockEntry {
    ip: String,
    port: Option<u16>,
}

#[derive(Clone, Serialize)]
struct AllowEntry {
    ip: String,
    port: Option<u16>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ConnectionLog {
    id: u64,
    rule_id: u64,
    client_ip: String,
    #[serde(default)]
    listen_port: Option<u16>,
    started_at: String,
    ended_at: Option<String>,
    bytes_up: u64,
    bytes_down: u64,
    blocked: bool,
    reason: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RateLimitConfig {
    max_new_connections_per_minute: u32,
    max_concurrent_connections_per_ip: u32,
    max_concurrent_total: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_new_connections_per_minute: 120,
            max_concurrent_connections_per_ip: 50,
            max_concurrent_total: 2000,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
    rules: Vec<ProxyRule>,
    blocklist: Vec<String>,
    #[serde(default)]
    port_blocklist: Vec<PortBlockEntry>,
    #[serde(default)]
    allowlist: Vec<String>,
    #[serde(default)]
    allowlist_ports: Vec<PortAllowEntry>,
    #[serde(default)]
    allowlist_enabled: bool,
    #[serde(default)]
    geo_blocklist: Vec<String>,
    #[serde(default)]
    geo_port_blocklist: Vec<geo::GeoPortEntry>,
    history: Vec<ConnectionLog>,
    rate_limit: RateLimitConfig,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            blocklist: Vec::new(),
            port_blocklist: Vec::new(),
            allowlist: Vec::new(),
            allowlist_ports: Vec::new(),
            allowlist_enabled: false,
            geo_blocklist: Vec::new(),
            geo_port_blocklist: Vec::new(),
            history: Vec::new(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

#[derive(Clone, Serialize)]
struct ActiveConn {
    conn_id: u64,
    rule_id: u64,
    client_ip: String,
    listen_port: Option<u16>,
    started_at: String,
    bytes_transferred: u64,
    last_update: String,
}

pub(crate) struct ListenerHandle {
    pub(crate) shutdown: CancellationToken,
    pub(crate) task: JoinHandle<()>,
}

pub(crate) struct AppState {
    rules: Vec<ProxyRule>,
    blocklist: HashSet<String>,
    port_blocklist: HashMap<u16, HashSet<String>>,
    allowlist: HashSet<String>,
    allowlist_ports: HashMap<u16, HashSet<String>>,
    allowlist_enabled: bool,
    geo_blocklist: HashSet<String>,
    geo_port_blocklist: HashMap<u16, HashSet<String>>,
    pub(crate) geo_db: Option<geo::SharedGeoDb>,
    history: Vec<ConnectionLog>,
    rate_limit: RateLimitConfig,
    listeners: HashMap<u64, Vec<ListenerHandle>>,
    udp_listeners: HashMap<u64, Vec<ListenerHandle>>,
    active: HashMap<u64, ActiveConn>,
    active_by_ip: HashMap<String, usize>,
    rate_counters: HashMap<String, VecDeque<Instant>>,
    data_path: PathBuf,
    next_rule_id: u64,
    next_conn_id: u64,
}

#[derive(Serialize)]
struct StatusResponse {
    rules: usize,
    active_connections: usize,
    blocklist: usize,
    history: usize,
}

#[derive(Deserialize)]
struct CreateRuleRequest {
    listen_addr: String,
    target_addr: String,
    enabled: Option<bool>,
    protocol: Option<ProtocolMode>,
}

#[derive(Deserialize)]
struct UpdateRuleRequest {
    listen_addr: Option<String>,
    target_addr: Option<String>,
    enabled: Option<bool>,
    protocol: Option<ProtocolMode>,
}

#[derive(Deserialize)]
struct BlockRequest {
    ip: String,
    port: Option<u16>,
}

#[derive(Deserialize)]
struct BlockQuery {
    port: Option<u16>,
}

#[derive(Deserialize)]
struct AllowRequest {
    ip: String,
    port: Option<u16>,
}

#[derive(Deserialize)]
struct AllowQuery {
    port: Option<u16>,
}

#[derive(Serialize)]
struct AllowlistMode {
    enabled: bool,
}

#[derive(Deserialize)]
struct AllowlistModeRequest {
    enabled: bool,
}

#[derive(Deserialize)]
struct RateLimitRequest {
    max_new_connections_per_minute: Option<u32>,
    max_concurrent_connections_per_ip: Option<u32>,
    max_concurrent_total: Option<u32>,
}

#[derive(Deserialize)]
struct HistoryQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct RecentQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct BlockedQuery {
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct DdosEntry {
    ip: String,
    count: usize,
    last_seen: String,
    last_reason: String,
    last_port: Option<u16>,
}

async fn index() -> Html<String> {
    Html(build_index_html())
}

async fn status(State(state): State<Arc<RwLock<AppState>>>) -> Json<StatusResponse> {
    let guard = state.read().await;
    let port_blocked = guard
        .port_blocklist
        .values()
        .map(|set| set.len())
        .sum::<usize>();
    Json(StatusResponse {
        rules: guard.rules.len(),
        active_connections: guard.active.len(),
        blocklist: guard.blocklist.len() + port_blocked,
        history: guard.history.len(),
    })
}

async fn list_rules(State(state): State<Arc<RwLock<AppState>>>) -> Json<Vec<ProxyRule>> {
    let guard = state.read().await;
    Json(guard.rules.clone())
}

async fn create_rule(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(payload): Json<CreateRuleRequest>,
) -> Result<Json<ProxyRule>, (StatusCode, Json<ErrorResponse>)> {
    if payload.listen_addr.trim().is_empty() || payload.target_addr.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "listen_addr and target_addr are required".to_string(),
            }),
        ));
    }
    let enabled = payload.enabled.unwrap_or(true);
    let protocol = payload.protocol.unwrap_or_default();

    let (rule, persist_snapshot) = {
        let mut guard = state.write().await;
        let rule = ProxyRule {
            id: guard.next_rule_id,
            listen_addr: payload.listen_addr.trim().to_string(),
            target_addr: payload.target_addr.trim().to_string(),
            enabled,
            created_at: now_string(),
            protocol,
        };
        guard.next_rule_id += 1;
        guard.rules.push(rule.clone());
        (rule, snapshot_state(&guard))
    };

    persist_state(state.clone(), persist_snapshot).await;

    if rule.enabled {
        if let Err(err) = start_rule_listeners(&state, &rule).await {
            warn!(
                "Failed to start listener {} -> {}: {}",
                rule.listen_addr, rule.target_addr, err
            );
            disable_rule_after_start_failure(&state, rule.id).await;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Listener failed: {}", err),
                }),
            ));
        }
    }

    Ok(Json(rule))
}

async fn enable_rule(
    Path(id): Path<u64>,
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<ProxyRule>, (StatusCode, Json<ErrorResponse>)> {
    let rule = {
        let mut guard = state.write().await;
        let rule = guard.rules.iter_mut().find(|rule| rule.id == id);
        match rule {
            Some(rule) => {
                rule.enabled = true;
                rule.clone()
            }
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Rule not found".to_string(),
                    }),
                ))
            }
        }
    };

    if let Err(err) = start_rule_listeners(&state, &rule).await {
        disable_rule_after_start_failure(&state, rule.id).await;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Listener failed: {}", err),
            }),
        ));
    }

    let snapshot = {
        let guard = state.read().await;
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
    Ok(Json(rule))
}

async fn disable_rule(
    Path(id): Path<u64>,
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<ProxyRule>, (StatusCode, Json<ErrorResponse>)> {
    let rule = {
        let mut guard = state.write().await;
        let rule = guard.rules.iter_mut().find(|rule| rule.id == id);
        match rule {
            Some(rule) => {
                rule.enabled = false;
                rule.clone()
            }
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Rule not found".to_string(),
                    }),
                ))
            }
        }
    };

    stop_rule_listeners(&state, id).await;
    let snapshot = {
        let guard = state.read().await;
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
    Ok(Json(rule))
}

async fn update_rule(
    Path(id): Path<u64>,
    State(state): State<Arc<RwLock<AppState>>>,
    Json(payload): Json<UpdateRuleRequest>,
) -> Result<Json<ProxyRule>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(listen_addr) = payload.listen_addr.as_ref() {
        if listen_addr.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "listen_addr cannot be empty".to_string(),
                }),
            ));
        }
    }
    if let Some(target_addr) = payload.target_addr.as_ref() {
        if target_addr.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "target_addr cannot be empty".to_string(),
                }),
            ));
        }
    }

    let (rule, was_enabled) = {
        let mut guard = state.write().await;
        let rule = guard.rules.iter_mut().find(|rule| rule.id == id);
        match rule {
            Some(rule) => {
                let was_enabled = rule.enabled;
                if let Some(listen_addr) = payload.listen_addr.as_ref() {
                    rule.listen_addr = listen_addr.trim().to_string();
                }
                if let Some(target_addr) = payload.target_addr.as_ref() {
                    rule.target_addr = target_addr.trim().to_string();
                }
                if let Some(enabled) = payload.enabled {
                    rule.enabled = enabled;
                }
                if let Some(protocol) = payload.protocol {
                    rule.protocol = protocol;
                }
                (rule.clone(), was_enabled)
            }
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Rule not found".to_string(),
                    }),
                ))
            }
        }
    };

    if was_enabled {
        stop_rule_listeners(&state, id).await;
    }

    if rule.enabled {
        if let Err(err) = start_rule_listeners(&state, &rule).await {
            disable_rule_after_start_failure(&state, rule.id).await;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Listener failed: {}", err),
                }),
            ));
        }
    }

    let snapshot = {
        let guard = state.read().await;
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
    Ok(Json(rule))
}

async fn remove_rule(
    Path(id): Path<u64>,
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<ProxyRule>, (StatusCode, Json<ErrorResponse>)> {
    stop_rule_listeners(&state, id).await;

    let (removed, snapshot) = {
        let mut guard = state.write().await;
        let idx = guard.rules.iter().position(|rule| rule.id == id);
        match idx {
            Some(index) => {
                let removed = guard.rules.remove(index);
                (removed, snapshot_state(&guard))
            }
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Rule not found".to_string(),
                    }),
                ))
            }
        }
    };

    persist_state(state.clone(), snapshot).await;
    Ok(Json(removed))
}

async fn active_connections(State(state): State<Arc<RwLock<AppState>>>) -> Json<Vec<ActiveConn>> {
    let guard = state.read().await;
    let mut items = guard.active.values().cloned().collect::<Vec<_>>();
    items.sort_by_key(|item| item.conn_id);
    Json(items)
}

async fn recent_connections(
    State(state): State<Arc<RwLock<AppState>>>,
    Query(params): Query<RecentQuery>,
) -> Json<Vec<ConnectionLog>> {
    let limit = params.limit.unwrap_or(100).min(MAX_HISTORY);
    let guard = state.read().await;
    let items = guard
        .history
        .iter()
        .rev()
        .filter(|entry| !entry.blocked)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    Json(items)
}

async fn ddos_list(State(state): State<Arc<RwLock<AppState>>>) -> Json<Vec<DdosEntry>> {
    let guard = state.read().await;
    let mut items: HashMap<String, DdosEntry> = HashMap::new();
    for entry in &guard.history {
        let reason = match entry.reason.as_deref() {
            Some(value) if is_ddos_reason(value) => value,
            _ => continue,
        };
        if !entry.blocked {
            continue;
        }
        let last_seen = entry
            .ended_at
            .clone()
            .unwrap_or_else(|| entry.started_at.clone());
        let item = items.entry(entry.client_ip.clone()).or_insert(DdosEntry {
            ip: entry.client_ip.clone(),
            count: 0,
            last_seen: last_seen.clone(),
            last_reason: reason.to_string(),
            last_port: entry.listen_port,
        });
        item.count += 1;
        item.last_seen = last_seen;
        item.last_reason = reason.to_string();
        item.last_port = entry.listen_port;
    }
    let mut entries = items.into_values().collect::<Vec<_>>();
    entries.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    Json(entries)
}

async fn blocked_connections(
    State(state): State<Arc<RwLock<AppState>>>,
    Query(params): Query<BlockedQuery>,
) -> Json<Vec<ConnectionLog>> {
    let limit = params.limit.unwrap_or(200).min(MAX_HISTORY);
    let guard = state.read().await;
    let items = guard
        .history
        .iter()
        .rev()
        .filter(|entry| entry.blocked)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    Json(items)
}

async fn history(
    State(state): State<Arc<RwLock<AppState>>>,
    Query(params): Query<HistoryQuery>,
) -> Json<Vec<ConnectionLog>> {
    let limit = params.limit.unwrap_or(200).min(MAX_HISTORY);
    let guard = state.read().await;
    let mut items = guard.history.clone();
    if items.len() > limit {
        items = items.split_off(items.len() - limit);
    }
    Json(items)
}

async fn blocklist(State(state): State<Arc<RwLock<AppState>>>) -> Json<Vec<BlockEntry>> {
    let guard = state.read().await;
    let mut items = Vec::new();
    for ip in &guard.blocklist {
        items.push(BlockEntry {
            ip: ip.clone(),
            port: None,
        });
    }
    for (port, ips) in &guard.port_blocklist {
        for ip in ips {
            items.push(BlockEntry {
                ip: ip.clone(),
                port: Some(*port),
            });
        }
    }
    items.sort_by(|a, b| {
        let port_a = a.port.unwrap_or(0);
        let port_b = b.port.unwrap_or(0);
        port_a
            .cmp(&port_b)
            .then_with(|| a.ip.cmp(&b.ip))
    });
    Json(items)
}

async fn add_block(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(payload): Json<BlockRequest>,
) -> Result<Json<Vec<BlockEntry>>, (StatusCode, Json<ErrorResponse>)> {
    if payload.ip.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "IP is required".to_string(),
            }),
        ));
    }
    if let Some(port) = payload.port {
        if port == 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Port must be between 1 and 65535".to_string(),
                }),
            ));
        }
    }

    let snapshot = {
        let mut guard = state.write().await;
        let ip = payload.ip.trim().to_string();
        match payload.port {
            Some(port) => {
                guard
                    .port_blocklist
                    .entry(port)
                    .or_insert_with(HashSet::new)
                    .insert(ip);
            }
            None => {
                guard.blocklist.insert(ip);
            }
        }
        snapshot_state(&guard)
    };

    persist_state(state.clone(), snapshot).await;
    Ok(blocklist(State(state)).await)
}

async fn remove_block(
    Path(ip): Path<String>,
    Query(query): Query<BlockQuery>,
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<Vec<BlockEntry>>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = {
        let mut guard = state.write().await;
        let ip = ip.trim();
        if let Some(port) = query.port {
            if let Some(ips) = guard.port_blocklist.get_mut(&port) {
                ips.remove(ip);
                if ips.is_empty() {
                    guard.port_blocklist.remove(&port);
                }
            }
        } else {
            guard.blocklist.remove(ip);
        }
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
    Ok(blocklist(State(state)).await)
}

async fn geo_blocklist(State(state): State<Arc<RwLock<AppState>>>) -> Json<Vec<geo::GeoEntry>> {
    let guard = state.read().await;
    let mut items = Vec::new();
    for country in &guard.geo_blocklist {
        items.push(geo::GeoEntry {
            country: country.clone(),
            port: None,
        });
    }
    for (port, countries) in &guard.geo_port_blocklist {
        for country in countries {
            items.push(geo::GeoEntry {
                country: country.clone(),
                port: Some(*port),
            });
        }
    }
    items.sort_by(|a, b| {
        let port_a = a.port.unwrap_or(0);
        let port_b = b.port.unwrap_or(0);
        port_a
            .cmp(&port_b)
            .then_with(|| a.country.cmp(&b.country))
    });
    Json(items)
}

async fn add_geo_block(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(payload): Json<geo::GeoBlockRequest>,
) -> Result<Json<Vec<geo::GeoEntry>>, (StatusCode, Json<ErrorResponse>)> {
    let country = match geo::normalize_country(&payload.country) {
        Ok(value) => value,
        Err(err) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: err.to_string(),
                }),
            ))
        }
    };
    if let Some(port) = payload.port {
        if port == 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Port must be between 1 and 65535".to_string(),
                }),
            ));
        }
    }

    let snapshot = {
        let mut guard = state.write().await;
        match payload.port {
            Some(port) => {
                guard
                    .geo_port_blocklist
                    .entry(port)
                    .or_insert_with(HashSet::new)
                    .insert(country);
            }
            None => {
                guard.geo_blocklist.insert(country);
            }
        }
        snapshot_state(&guard)
    };

    persist_state(state.clone(), snapshot).await;
    Ok(geo_blocklist(State(state)).await)
}

async fn remove_geo_block(
    Path(country): Path<String>,
    Query(query): Query<geo::GeoBlockQuery>,
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<Vec<geo::GeoEntry>>, (StatusCode, Json<ErrorResponse>)> {
    let country = match geo::normalize_country(&country) {
        Ok(value) => value,
        Err(err) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: err.to_string(),
                }),
            ))
        }
    };
    let snapshot = {
        let mut guard = state.write().await;
        if let Some(port) = query.port {
            if let Some(countries) = guard.geo_port_blocklist.get_mut(&port) {
                countries.remove(&country);
                if countries.is_empty() {
                    guard.geo_port_blocklist.remove(&port);
                }
            }
        } else {
            guard.geo_blocklist.remove(&country);
        }
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
    Ok(geo_blocklist(State(state)).await)
}

async fn allowlist(State(state): State<Arc<RwLock<AppState>>>) -> Json<Vec<AllowEntry>> {
    let guard = state.read().await;
    let mut items = Vec::new();
    for ip in &guard.allowlist {
        items.push(AllowEntry {
            ip: ip.clone(),
            port: None,
        });
    }
    for (port, ips) in &guard.allowlist_ports {
        for ip in ips {
            items.push(AllowEntry {
                ip: ip.clone(),
                port: Some(*port),
            });
        }
    }
    items.sort_by(|a, b| {
        let port_a = a.port.unwrap_or(0);
        let port_b = b.port.unwrap_or(0);
        port_a
            .cmp(&port_b)
            .then_with(|| a.ip.cmp(&b.ip))
    });
    Json(items)
}

async fn add_allow(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(payload): Json<AllowRequest>,
) -> Result<Json<Vec<AllowEntry>>, (StatusCode, Json<ErrorResponse>)> {
    if payload.ip.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "IP is required".to_string(),
            }),
        ));
    }
    if let Some(port) = payload.port {
        if port == 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Port must be between 1 and 65535".to_string(),
                }),
            ));
        }
    }

    let snapshot = {
        let mut guard = state.write().await;
        let ip = payload.ip.trim().to_string();
        match payload.port {
            Some(port) => {
                guard
                    .allowlist_ports
                    .entry(port)
                    .or_insert_with(HashSet::new)
                    .insert(ip);
            }
            None => {
                guard.allowlist.insert(ip);
            }
        }
        snapshot_state(&guard)
    };

    persist_state(state.clone(), snapshot).await;
    Ok(allowlist(State(state)).await)
}

async fn remove_allow(
    Path(ip): Path<String>,
    Query(query): Query<AllowQuery>,
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<Vec<AllowEntry>>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = {
        let mut guard = state.write().await;
        let ip = ip.trim();
        if let Some(port) = query.port {
            if let Some(ips) = guard.allowlist_ports.get_mut(&port) {
                ips.remove(ip);
                if ips.is_empty() {
                    guard.allowlist_ports.remove(&port);
                }
            }
        } else {
            guard.allowlist.remove(ip);
        }
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
    Ok(allowlist(State(state)).await)
}

async fn allowlist_mode(State(state): State<Arc<RwLock<AppState>>>) -> Json<AllowlistMode> {
    let guard = state.read().await;
    Json(AllowlistMode {
        enabled: guard.allowlist_enabled,
    })
}

async fn update_allowlist_mode(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(payload): Json<AllowlistModeRequest>,
) -> Result<Json<AllowlistMode>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = {
        let mut guard = state.write().await;
        guard.allowlist_enabled = payload.enabled;
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
    Ok(allowlist_mode(State(state)).await)
}

async fn rate_limit(State(state): State<Arc<RwLock<AppState>>>) -> Json<RateLimitConfig> {
    let guard = state.read().await;
    Json(guard.rate_limit.clone())
}

async fn update_rate_limit(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(payload): Json<RateLimitRequest>,
) -> Result<Json<RateLimitConfig>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = {
        let mut guard = state.write().await;
        if let Some(value) = payload.max_new_connections_per_minute {
            guard.rate_limit.max_new_connections_per_minute = value.max(1);
        }
        if let Some(value) = payload.max_concurrent_connections_per_ip {
            guard.rate_limit.max_concurrent_connections_per_ip = value.max(1);
        }
        if let Some(value) = payload.max_concurrent_total {
            guard.rate_limit.max_concurrent_total = value.max(1);
        }
        snapshot_state(&guard)
    };

    persist_state(state.clone(), snapshot).await;
    Ok(rate_limit(State(state)).await)
}

async fn load_state(data_dir: &StdPath) -> Result<AppState> {
    tokio::fs::create_dir_all(data_dir).await?;
    let data_path = data_dir.join(STATE_FILE);
    let persisted = if tokio::fs::try_exists(&data_path).await.unwrap_or(false) {
        let bytes = tokio::fs::read(&data_path).await?;
        serde_json::from_slice::<PersistedState>(&bytes).unwrap_or_default()
    } else {
        PersistedState::default()
    };

    let next_rule_id = persisted
        .rules
        .iter()
        .map(|rule| rule.id)
        .max()
        .unwrap_or(0)
        + 1;
    let next_conn_id = persisted
        .history
        .iter()
        .map(|log| log.id)
        .max()
        .unwrap_or(0)
        + 1;

    let mut port_blocklist: HashMap<u16, HashSet<String>> = HashMap::new();
    for entry in &persisted.port_blocklist {
        port_blocklist
            .entry(entry.port)
            .or_insert_with(HashSet::new)
            .insert(entry.ip.clone());
    }
    let allowlist = persisted.allowlist.iter().cloned().collect::<HashSet<_>>();
    let mut allowlist_ports: HashMap<u16, HashSet<String>> = HashMap::new();
    for entry in &persisted.allowlist_ports {
        allowlist_ports
            .entry(entry.port)
            .or_insert_with(HashSet::new)
            .insert(entry.ip.clone());
    }
    let allowlist_enabled = persisted.allowlist_enabled;

    let geo_blocklist = persisted
        .geo_blocklist
        .iter()
        .map(|value| value.to_uppercase())
        .collect::<HashSet<_>>();
    let mut geo_port_blocklist: HashMap<u16, HashSet<String>> = HashMap::new();
    for entry in &persisted.geo_port_blocklist {
        geo_port_blocklist
            .entry(entry.port)
            .or_insert_with(HashSet::new)
            .insert(entry.country.to_uppercase());
    }

    Ok(AppState {
        rules: persisted.rules,
        blocklist: persisted.blocklist.into_iter().collect(),
        port_blocklist,
        allowlist,
        allowlist_ports,
        allowlist_enabled,
        geo_blocklist,
        geo_port_blocklist,
        geo_db: None,
        history: persisted.history,
        rate_limit: persisted.rate_limit,
        listeners: HashMap::new(),
        udp_listeners: HashMap::new(),
        active: HashMap::new(),
        active_by_ip: HashMap::new(),
        rate_counters: HashMap::new(),
        data_path,
        next_rule_id,
        next_conn_id,
    })
}

async fn start_rule_listeners(state: &Arc<RwLock<AppState>>, rule: &ProxyRule) -> Result<()> {
    let listen_targets =
        port_range::expand_listen_targets(&rule.listen_addr, &rule.target_addr)?;

    if rule.protocol.uses_tcp() {
        for target in &listen_targets {
            if let Err(err) = start_tcp_listener(
                state,
                rule.id,
                target.listen_addr.clone(),
                target.listen_port,
                target.target_addr.clone(),
            )
            .await
            {
                stop_rule_listeners(state, rule.id).await;
                return Err(err);
            }
        }
    }

    if rule.protocol.uses_udp() {
        if let Err(err) = start_udp_listener(state, rule.id, &listen_targets).await {
            stop_rule_listeners(state, rule.id).await;
            return Err(err);
        }
    }
    Ok(())
}

async fn stop_rule_listeners(state: &Arc<RwLock<AppState>>, rule_id: u64) {
    stop_tcp_listener(state, rule_id).await;
    stop_udp_listener(state, rule_id).await;
}

async fn start_tcp_listener(
    state: &Arc<RwLock<AppState>>,
    rule_id: u64,
    listen_addr: String,
    listen_port: u16,
    target_addr: String,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr.as_str()).await?;
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    let state_clone = state.clone();
    let target_addr = target_addr.clone();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_signal.cancelled() => {
                    break;
                }
                accept_result = listener.accept() => {
                    let (inbound, peer_addr) = match accept_result {
                        Ok(value) => value,
                        Err(err) => {
                            warn!("Listener accept error: {}", err);
                            continue;
                        }
                    };
                    let client_ip = peer_addr.ip().to_string();
                    let state_for_conn = state_clone.clone();
                    let target_addr = target_addr.clone();
                    let local_port = inbound
                        .local_addr()
                        .map(|addr| addr.port())
                        .unwrap_or(listen_port);
                    tokio::spawn(async move {
                        handle_connection(
                            state_for_conn,
                            inbound,
                            target_addr,
                            rule_id,
                            local_port,
                            client_ip,
                        )
                        .await;
                    });
                }
            }
        }
    });

    let mut guard = state.write().await;
    guard
        .listeners
        .entry(rule_id)
        .or_insert_with(Vec::new)
        .push(ListenerHandle { shutdown, task });
    Ok(())
}

async fn stop_tcp_listener(state: &Arc<RwLock<AppState>>, rule_id: u64) {
    let handle = {
        let mut guard = state.write().await;
        guard.listeners.remove(&rule_id)
    };
    if let Some(handles) = handle {
        for handle in handles {
            handle.shutdown.cancel();
            handle.task.abort();
        }
    }
}

async fn start_udp_listener(
    state: &Arc<RwLock<AppState>>,
    rule_id: u64,
    listen_targets: &[port_range::ListenTarget],
) -> Result<()> {
    for target in listen_targets {
        let handle = udp_proxy::start_udp_listener(
            state.clone(),
            rule_id,
            target.listen_addr.clone(),
            Some(target.listen_port),
            target.target_addr.clone(),
        )
        .await?;
        let mut guard = state.write().await;
        guard
            .udp_listeners
            .entry(rule_id)
            .or_insert_with(Vec::new)
            .push(handle);
    }
    Ok(())
}

async fn stop_udp_listener(state: &Arc<RwLock<AppState>>, rule_id: u64) {
    let handle = {
        let mut guard = state.write().await;
        guard.udp_listeners.remove(&rule_id)
    };
    if let Some(handles) = handle {
        for handle in handles {
            handle.shutdown.cancel();
            handle.task.abort();
        }
    }
}

async fn disable_rule_after_start_failure(state: &Arc<RwLock<AppState>>, rule_id: u64) {
    let snapshot = {
        let mut guard = state.write().await;
        if let Some(rule) = guard.rules.iter_mut().find(|rule| rule.id == rule_id) {
            rule.enabled = false;
        }
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
}

async fn handle_connection(
    state: Arc<RwLock<AppState>>,
    inbound: TcpStream,
    target_addr: String,
    rule_id: u64,
    listen_port: u16,
    client_ip: String,
) {
    let listen_port = Some(listen_port);
    let conn_id = match register_connection(&state, rule_id, &client_ip, listen_port).await {
        Ok(value) => value,
        Err(reason) => {
            record_blocked(&state, rule_id, listen_port, client_ip, reason).await;
            return;
        }
    };

    let outbound = match TcpStream::connect(target_addr.as_str()).await {
        Ok(stream) => stream,
        Err(err) => {
            record_connection_end(
                &state,
                conn_id,
                0,
                0,
                Some(format!("Target connect failed: {}", err)),
            )
            .await;
            return;
        }
    };

    let transfer_result = copy_bidirectional_with_tracking(inbound, outbound, &state, conn_id).await;
    match transfer_result {
        Ok((bytes_up, bytes_down)) => {
            record_connection_end(&state, conn_id, bytes_up, bytes_down, None).await;
        }
        Err(err) => {
            record_connection_end(
                &state,
                conn_id,
                0,
                0,
                Some(format!("Proxy error: {}", err)),
            )
            .await;
        }
    }

}

pub(crate) async fn register_connection(
    state: &Arc<RwLock<AppState>>,
    rule_id: u64,
    client_ip: &str,
    listen_port: Option<u16>,
) -> Result<u64, String> {
    let mut guard = state.write().await;
    if let Err(reason) = check_allow(&mut guard, client_ip, listen_port) {
        return Err(reason);
    }

    let conn_id = guard.next_conn_id;
    guard.next_conn_id += 1;
    let started_at = now_string();
    guard.active.insert(
        conn_id,
        ActiveConn {
            conn_id,
            rule_id,
            client_ip: client_ip.to_string(),
            listen_port,
            started_at: started_at.clone(),
            bytes_transferred: 0,
            last_update: started_at.clone(),
        },
    );
    *guard
        .active_by_ip
        .entry(client_ip.to_string())
        .or_insert(0) += 1;

    Ok(conn_id)
}

fn check_allow(
    state: &mut AppState,
    client_ip: &str,
    listen_port: Option<u16>,
) -> Result<(), String> {
    if state.allowlist_enabled && !state.allowlist.contains(client_ip) {
        return Err("Not in allowlist".to_string());
    }

    if let Some(port) = listen_port {
        if let Some(ips) = state.allowlist_ports.get(&port) {
            if !ips.contains(client_ip) {
                return Err(format!("Not in allowlist for port {}", port));
            }
        }
    }

    if let Some(db) = state.geo_db.as_ref() {
        if let Ok(ip) = client_ip.parse() {
            if let Some(country) = geo::lookup_country(db, ip) {
                if let Some(port) = listen_port {
                    if let Some(countries) = state.geo_port_blocklist.get(&port) {
                        if countries.contains(&country) {
                            return Err(format!("Geo blocked for port {}: {}", port, country));
                        }
                    }
                }
                if state.geo_blocklist.contains(&country) {
                    return Err(format!("Geo blocked: {}", country));
                }
            }
        }
    }

    if state.blocklist.contains(client_ip) {
        return Err("Blocked by rule".to_string());
    }

    if let Some(port) = listen_port {
        if let Some(ips) = state.port_blocklist.get(&port) {
            if ips.contains(client_ip) {
                return Err(format!("Blocked for port {}", port));
            }
        }
    }

    if state.active.len() as u32 >= state.rate_limit.max_concurrent_total {
        return Err("Too many total connections".to_string());
    }

    let active_for_ip = state.active_by_ip.get(client_ip).copied().unwrap_or(0) as u32;
    if active_for_ip >= state.rate_limit.max_concurrent_connections_per_ip {
        return Err("Too many active connections for IP".to_string());
    }

    let now = Instant::now();
    let window = state
        .rate_counters
        .entry(client_ip.to_string())
        .or_insert_with(VecDeque::new);
    while let Some(front) = window.front().copied() {
        if now.duration_since(front) > Duration::from_secs(60) {
            window.pop_front();
        } else {
            break;
        }
    }
    if window.len() as u32 >= state.rate_limit.max_new_connections_per_minute {
        return Err("Rate limit exceeded".to_string());
    }
    window.push_back(now);
    Ok(())
}

fn is_ddos_reason(reason: &str) -> bool {
    reason.contains("Rate limit") || reason.contains("Too many")
}

pub(crate) async fn record_blocked(
    state: &Arc<RwLock<AppState>>,
    rule_id: u64,
    listen_port: Option<u16>,
    client_ip: String,
    reason: String,
) {
    let snapshot = {
        let mut guard = state.write().await;
        let conn_id = guard.next_conn_id;
        guard.next_conn_id += 1;
        guard.history.push(ConnectionLog {
            id: conn_id,
            rule_id,
            client_ip,
            listen_port,
            started_at: now_string(),
            ended_at: Some(now_string()),
            bytes_up: 0,
            bytes_down: 0,
            blocked: true,
            reason: Some(reason),
        });
        trim_history(&mut guard.history);
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
}

pub(crate) async fn record_connection_end(
    state: &Arc<RwLock<AppState>>,
    conn_id: u64,
    bytes_up: u64,
    bytes_down: u64,
    reason: Option<String>,
) {
    let snapshot = {
        let mut guard = state.write().await;
        let active = guard.active.remove(&conn_id);
        if let Some(active) = active {
            if let Some(counter) = guard.active_by_ip.get_mut(&active.client_ip) {
                *counter = counter.saturating_sub(1);
                if *counter == 0 {
                    guard.active_by_ip.remove(&active.client_ip);
                }
            }
            guard.history.push(ConnectionLog {
                id: conn_id,
                rule_id: active.rule_id,
                client_ip: active.client_ip,
                listen_port: active.listen_port,
                started_at: active.started_at,
                ended_at: Some(now_string()),
                bytes_up,
                bytes_down,
                blocked: false,
                reason,
            });
            trim_history(&mut guard.history);
        }
        snapshot_state(&guard)
    };
    persist_state(state.clone(), snapshot).await;
}

pub(crate) async fn update_connection_bytes(
    state: &Arc<RwLock<AppState>>,
    conn_id: u64,
    bytes_transferred: u64,
) {
    let mut guard = state.write().await;
    if let Some(conn) = guard.active.get_mut(&conn_id) {
        conn.bytes_transferred = bytes_transferred;
        conn.last_update = now_string();
    }
}

fn trim_history(history: &mut Vec<ConnectionLog>) {
    if history.len() > MAX_HISTORY {
        let over = history.len() - MAX_HISTORY;
        history.drain(0..over);
    }
}

async fn copy_bidirectional_with_tracking(
    mut inbound: TcpStream,
    mut outbound: TcpStream,
    state: &Arc<RwLock<AppState>>,
    conn_id: u64,
) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();
    
    let state_clone = state.clone();
    let conn_id_clone = conn_id;
    
    // Task to read from inbound and write to outbound
    let client_to_server = async move {
        let mut buffer = [0; 8192];
        let mut total_bytes = 0u64;
        let mut last_update = std::time::Instant::now();
        
        loop {
            match ri.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    total_bytes += n as u64;
                    if wo.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                    
                    // Update bytes every 100ms or every 1MB
                    if last_update.elapsed().as_millis() >= 100 || total_bytes % (1024 * 1024) == 0 {
                        update_connection_bytes(&state_clone, conn_id_clone, total_bytes).await;
                        last_update = std::time::Instant::now();
                    }
                }
                Err(_) => break,
            }
        }
        total_bytes
    };
    
    let state_clone = state.clone();
    let conn_id_clone = conn_id;
    
    // Task to read from outbound and write to inbound
    let server_to_client = async move {
        let mut buffer = [0; 8192];
        let mut total_bytes = 0u64;
        let mut last_update = std::time::Instant::now();
        
        loop {
            match ro.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    total_bytes += n as u64;
                    if wi.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                    
                    // Update bytes every 100ms or every 1MB
                    if last_update.elapsed().as_millis() >= 100 || total_bytes % (1024 * 1024) == 0 {
                        update_connection_bytes(&state_clone, conn_id_clone, total_bytes).await;
                        last_update = std::time::Instant::now();
                    }
                }
                Err(_) => break,
            }
        }
        total_bytes
    };
    
    // Run both tasks concurrently
    let (bytes_up, bytes_down) = tokio::join!(client_to_server, server_to_client);
    Ok((bytes_up, bytes_down))
}

fn snapshot_state(state: &AppState) -> PersistedState {
    let mut port_blocklist = Vec::new();
    for (port, ips) in &state.port_blocklist {
        for ip in ips {
            port_blocklist.push(PortBlockEntry {
                ip: ip.clone(),
                port: *port,
            });
        }
    }
    port_blocklist.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.ip.cmp(&b.ip)));

    let mut allowlist_ports = Vec::new();
    for (port, ips) in &state.allowlist_ports {
        for ip in ips {
            allowlist_ports.push(PortAllowEntry {
                ip: ip.clone(),
                port: *port,
            });
        }
    }
    allowlist_ports.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.ip.cmp(&b.ip)));

    let mut geo_port_blocklist = Vec::new();
    for (port, countries) in &state.geo_port_blocklist {
        for country in countries {
            geo_port_blocklist.push(geo::GeoPortEntry {
                country: country.clone(),
                port: *port,
            });
        }
    }
    geo_port_blocklist.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.country.cmp(&b.country))
    });

    PersistedState {
        rules: state.rules.clone(),
        blocklist: state.blocklist.iter().cloned().collect(),
        port_blocklist,
        allowlist: state.allowlist.iter().cloned().collect(),
        allowlist_ports,
        allowlist_enabled: state.allowlist_enabled,
        geo_blocklist: state.geo_blocklist.iter().cloned().collect(),
        geo_port_blocklist,
        history: state.history.clone(),
        rate_limit: state.rate_limit.clone(),
    }
}

async fn persist_state(state: Arc<RwLock<AppState>>, snapshot: PersistedState) {
    let data_path = { state.read().await.data_path.clone() };
    tokio::spawn(async move {
        if let Err(err) = save_snapshot(data_path, snapshot).await {
            error!("Failed to save state: {}", err);
        }
    });
}

async fn save_snapshot(path: PathBuf, snapshot: PersistedState) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(&snapshot)?;
    tokio::fs::write(path, bytes).await?;
    Ok(())
}

fn now_string() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn build_index_html() -> String {
    INDEX_HTML
        .replace("{{PROTOCOL_RULE_FIELD}}", crate::protocol::RULE_FIELD_HTML)
        .replace("{{PROTOCOL_RULE_HEADER}}", crate::protocol::RULE_HEADER_HTML)
        .replace("{{PROTOCOL_JSON_FIELDS}}", crate::protocol::RULE_JSON_FIELDS)
        .replace("{{PROTOCOL_JS_HOOKS}}", crate::protocol::RULE_JS_HOOKS)
        .replace("{{GEO_BLOCK_SECTION}}", geo::GEO_SECTION_HTML)
        .replace("{{GEO_JS_HOOKS}}", geo::GEO_JS_HOOKS)
        .replace("{{GEO_REFRESH_VARS}}", geo::GEO_REFRESH_VARS)
        .replace("{{GEO_REFRESH_CALLS}}", geo::GEO_REFRESH_CALLS)
        .replace("{{GEO_REFRESH_RENDER}}", geo::GEO_REFRESH_RENDER)
}

const INDEX_HTML: &str = r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Proxy Panel</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { margin-bottom: 8px; }
    .section { border: 1px solid #ddd; padding: 12px; margin-bottom: 16px; }
    .section-header { display: flex; align-items: center; justify-content: space-between; }
    .toggle { padding: 4px 8px; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { border: 1px solid #ddd; padding: 6px; text-align: left; font-size: 13px; }
    input, button, select, textarea { padding: 6px; margin-right: 8px; }
    textarea { width: 100%; height: 160px; font-family: monospace; }
    .muted { color: #666; font-size: 12px; }
    .tabs { display: flex; gap: 8px; margin: 12px 0; }
    .tab-button { padding: 8px 12px; border: 1px solid #ccc; background: #f6f6f6; cursor: pointer; }
    .tab-button.active { background: #e0e0e0; font-weight: bold; }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    .row { margin: 6px 0; }
    .row label { margin-right: 6px; }
  </style>
</head>
<body>
  <h1>Proxy Panel</h1>
  <div class="muted">TCP proxy manager with IP logging, allowlist, blocklist, and rate limits.</div>

  <div class="tabs">
    <button class="tab-button active" data-tab="connections" onclick="selectTab('connections')">Connections</button>
    <button class="tab-button" data-tab="rules" onclick="selectTab('rules')">Rules</button>
  </div>

  <div class="tab-content active" id="tab-connections">
    <div class="section">
      <div class="section-header">
        <h3>Recent connections</h3>
        <button class="toggle" data-section="recent-section" onclick="toggleSection('recent-section', this)">Hide</button>
      </div>
      <div id="recent-section">
        <table>
          <thead>
            <tr><th>ID</th><th>Rule</th><th>Port</th><th>Client IP</th><th>Started</th><th>Ended</th><th>Up</th><th>Down</th></tr>
          </thead>
          <tbody id="recent-body"></tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <h3>Blocked connections</h3>
        <button class="toggle" data-section="blocked-section" onclick="toggleSection('blocked-section', this)">Hide</button>
      </div>
      <div id="blocked-section">
        <table>
          <thead>
            <tr><th>ID</th><th>Rule</th><th>Port</th><th>Client IP</th><th>Started</th><th>Ended</th><th>Reason</th></tr>
          </thead>
          <tbody id="blocked-body"></tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <h3>DDoS list (rate-limit blocks)</h3>
        <button class="toggle" data-section="ddos-section" onclick="toggleSection('ddos-section', this)">Hide</button>
      </div>
      <div id="ddos-section">
        <table>
          <thead>
            <tr><th>IP</th><th>Count</th><th>Last seen</th><th>Port</th><th>Reason</th></tr>
          </thead>
          <tbody id="ddos-body"></tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <h3>Active connections</h3>
        <button class="toggle" data-section="active-section" onclick="toggleSection('active-section', this)">Hide</button>
      </div>
      <div id="active-section">
        <table>
          <thead>
            <tr><th>Conn ID</th><th>Rule</th><th>Port</th><th>Client IP</th><th>Started</th><th>Speed</th></tr>
          </thead>
          <tbody id="active-body"></tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <h3>Blocklist (global or per port)</h3>
        <button class="toggle" data-section="blocklist-section" onclick="toggleSection('blocklist-section', this)">Hide</button>
      </div>
      <div id="blocklist-section">
        <div class="row">
          <input id="block-ip" placeholder="IP to block">
          <input id="block-port" placeholder="Port (optional)" size="12">
          <button onclick="addBlock()">Block</button>
          <span id="block-error" class="muted"></span>
        </div>
        <table>
          <thead>
            <tr><th>IP</th><th>Port</th><th>Action</th></tr>
          </thead>
          <tbody id="block-body"></tbody>
        </table>
      </div>
    </div>

{{GEO_BLOCK_SECTION}}

    <div class="section">
      <div class="section-header">
        <h3>Allowlist</h3>
        <button class="toggle" data-section="allowlist-section" onclick="toggleSection('allowlist-section', this)">Hide</button>
      </div>
      <div id="allowlist-section">
        <div class="row">
          <label>
            <input id="allowlist-enabled" type="checkbox" onchange="toggleAllowlistMode()">
            Allow only listed IPs (global)
          </label>
          <span class="muted">If enabled, all other IPs are blocked globally.</span>
        </div>
        <div class="row">
          <input id="allow-ip" placeholder="IP to allow">
          <input id="allow-port" placeholder="Port (optional)" size="12">
          <button onclick="addAllow()">Allow</button>
          <span id="allow-error" class="muted"></span>
        </div>
        <div class="muted">If a port has allowlist entries, only those IPs can access that port.</div>
        <table>
          <thead>
            <tr><th>IP</th><th>Port</th><th>Action</th></tr>
          </thead>
          <tbody id="allow-body"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="tab-content" id="tab-rules">
    <div class="section">
      <h3>Rule editor</h3>
      <div class="row">
        <label>Template</label>
        <select id="template-select"></select>
        <button onclick="applyTemplate()">Apply</button>
      </div>
      <div class="row">
        <label>Listen</label>
        <input id="listen" placeholder="0.0.0.0:443" size="24" oninput="syncJsonFromForm()">
        <label>Target</label>
        <input id="target" placeholder="10.250.2.7:443" size="24" oninput="syncJsonFromForm()">
{{PROTOCOL_RULE_FIELD}}
        <label>
          <input id="rule-enabled" type="checkbox" checked onchange="syncJsonFromForm()">
          Enabled
        </label>
      </div>
      <div class="row">
        <button id="save-button" onclick="saveRule()">Add rule</button>
        <button onclick="resetEditor()">Reset</button>
        <button onclick="toggleJsonMode()">JSON editor</button>
        <span id="editor-mode" class="muted">Form mode</span>
      </div>
      <div id="json-editor" style="display:none;">
        <textarea id="rule-json"></textarea>
      <div class="muted">JSON fields: listen_addr, target_addr, enabled{{PROTOCOL_JSON_FIELDS}}</div>
      </div>
      <div id="rule-error" class="muted"></div>
    </div>

    <div class="section">
      <div class="section-header">
        <h3>Rules</h3>
        <button class="toggle" data-section="rules-section" onclick="toggleSection('rules-section', this)">Hide</button>
      </div>
      <div id="rules-section">
        <table>
          <thead>
            <tr><th>ID</th><th>Listen</th><th>Target</th>{{PROTOCOL_RULE_HEADER}}<th>Enabled</th><th>Actions</th></tr>
          </thead>
          <tbody id="rules-body"></tbody>
        </table>
      </div>
    </div>
  </div>

<script>
let currentRuleId = null;
let jsonMode = false;
let cachedRules = [];

const templates = [
  { name: "HTTPS 443 -> 10.250.2.7:443 (TCP)", listen_addr: "0.0.0.0:443", target_addr: "10.250.2.7:443", enabled: true, protocol: "tcp" },
  { name: "HTTP 80 -> 10.250.2.7:80 (TCP)", listen_addr: "0.0.0.0:80", target_addr: "10.250.2.7:80", enabled: true, protocol: "tcp" },
  { name: "OpenVPN 1194 -> 10.250.2.7:1194 (UDP)", listen_addr: "0.0.0.0:1194", target_addr: "10.250.2.7:1194", enabled: true, protocol: "udp" },
  { name: "Custom 443 -> 10.250.2.7:443 (TCP)", listen_addr: "0.0.0.0:443", target_addr: "10.250.2.7:443", enabled: true, protocol: "tcp" }
];

{{PROTOCOL_JS_HOOKS}}

{{GEO_JS_HOOKS}}

function selectTab(tab) {
  document.querySelectorAll(".tab-button").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  });
  document.querySelectorAll(".tab-content").forEach(panel => {
    panel.classList.toggle("active", panel.id === "tab-" + tab);
  });
}

const SECTION_KEY_PREFIX = "section:";

function toggleSection(sectionId, button) {
  const section = document.getElementById(sectionId);
  if (!section) return;
  const hidden = section.style.display === "none";
  section.style.display = hidden ? "block" : "none";
  if (button) {
    button.textContent = hidden ? "Hide" : "Show";
    try {
      localStorage.setItem(SECTION_KEY_PREFIX + sectionId, hidden ? "shown" : "hidden");
    } catch (err) {
      console.warn(err);
    }
  }
}

function applySectionState() {
  document.querySelectorAll(".toggle").forEach(button => {
    const sectionId = button.dataset.section;
    if (!sectionId) return;
    let state = null;
    try {
      state = localStorage.getItem(SECTION_KEY_PREFIX + sectionId);
    } catch (err) {
      console.warn(err);
    }
    if (state === "hidden") {
      const section = document.getElementById(sectionId);
      if (section) {
        section.style.display = "none";
        button.textContent = "Show";
      }
    }
  });
}

async function api(path, options) {
  const res = await fetch(path, options);
  const text = await res.text();
  if (!res.ok) {
    let message = "Request failed";
    if (text) {
      try {
        const data = JSON.parse(text);
        if (data && data.error) {
          message = data.error;
        } else {
          message = text;
        }
      } catch {
        message = text;
      }
    }
    throw new Error(message);
  }
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function loadTemplates() {
  const select = document.getElementById("template-select");
  select.innerHTML = "";
  templates.forEach((tpl, index) => {
    const opt = document.createElement("option");
    opt.value = index;
    opt.textContent = tpl.name;
    select.appendChild(opt);
  });
}

function applyTemplate() {
  const index = parseInt(document.getElementById("template-select").value, 10);
  const tpl = templates[index];
  if (!tpl) {
    return;
  }
  document.getElementById("listen").value = tpl.listen_addr;
  document.getElementById("target").value = tpl.target_addr;
  document.getElementById("rule-enabled").checked = !!tpl.enabled;
  if (typeof protocolApplyTemplate === "function") {
    protocolApplyTemplate(tpl);
  }
  syncJsonFromForm();
}

function setEditorMode(mode) {
  jsonMode = mode === "json";
  document.getElementById("json-editor").style.display = jsonMode ? "block" : "none";
  document.getElementById("editor-mode").textContent = jsonMode ? "JSON mode" : "Form mode";
}

function syncJsonFromForm() {
  if (jsonMode) return;
  const payload = {
    listen_addr: document.getElementById("listen").value,
    target_addr: document.getElementById("target").value,
    enabled: document.getElementById("rule-enabled").checked
  };
  if (typeof protocolSyncJson === "function") {
    protocolSyncJson(payload);
  }
  document.getElementById("rule-json").value = JSON.stringify(payload, null, 2);
}

function syncFormFromJson() {
  const text = document.getElementById("rule-json").value;
  const payload = JSON.parse(text);
  if (payload.listen_addr !== undefined) {
    document.getElementById("listen").value = payload.listen_addr;
  }
  if (payload.target_addr !== undefined) {
    document.getElementById("target").value = payload.target_addr;
  }
  if (payload.enabled !== undefined) {
    document.getElementById("rule-enabled").checked = !!payload.enabled;
  }
  if (typeof protocolSyncForm === "function") {
    protocolSyncForm(payload);
  }
}

function toggleJsonMode() {
  try {
    if (!jsonMode) {
      syncJsonFromForm();
      setEditorMode("json");
    } else {
      syncFormFromJson();
      setEditorMode("form");
    }
  } catch (err) {
    document.getElementById("rule-error").textContent = err.message;
  }
}

function setEditing(rule) {
  currentRuleId = rule ? rule.id : null;
  document.getElementById("save-button").textContent = rule ? "Update rule" : "Add rule";
}

function resetEditor() {
  currentRuleId = null;
  document.getElementById("listen").value = "";
  document.getElementById("target").value = "";
  document.getElementById("rule-enabled").checked = true;
  if (typeof protocolReset === "function") {
    protocolReset();
  }
  document.getElementById("rule-error").textContent = "";
  setEditorMode("form");
  syncJsonFromForm();
  setEditing(null);
}

function getPayloadFromEditor() {
  if (jsonMode) {
    const payload = JSON.parse(document.getElementById("rule-json").value);
    if (typeof protocolNormalizePayload === "function") {
      protocolNormalizePayload(payload);
    }
    return payload;
  }
  const payload = {
    listen_addr: document.getElementById("listen").value,
    target_addr: document.getElementById("target").value,
    enabled: document.getElementById("rule-enabled").checked
  };
  if (typeof protocolSyncJson === "function") {
    protocolSyncJson(payload);
  }
  return payload;
}

async function saveRule() {
  const errorBox = document.getElementById("rule-error");
  errorBox.textContent = "";
  try {
    const payload = getPayloadFromEditor();
    if (!payload.listen_addr || !payload.target_addr) {
      throw new Error("listen_addr and target_addr are required");
    }
    if (currentRuleId) {
      await api(`/api/rules/${currentRuleId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
    } else {
      await api("/api/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
    }
    resetEditor();
    await refresh();
  } catch (err) {
    errorBox.textContent = err.message;
  }
}

async function refresh() {
  try {
    const [
      rules,
      active,
      recent,
      blocked,
      ddos,
      blocks{{GEO_REFRESH_VARS}},
      allows,
      allowMode
    ] = await Promise.all([
      api("/api/rules"),
      api("/api/active"),
      api("/api/recent?limit=100"),
      api("/api/blocked?limit=100"),
      api("/api/ddos"),
      api("/api/blocklist"){{GEO_REFRESH_CALLS}},
      api("/api/allowlist"),
      api("/api/allowlist-mode")
    ]);
    cachedRules = rules;
    renderRules(rules);
    renderActive(active);
    renderRecent(recent);
    renderBlocked(blocked);
    renderDdos(ddos);
    renderBlocks(blocks);
{{GEO_REFRESH_RENDER}}
    renderAllowlist(allows);
    setAllowlistMode(allowMode.enabled);
  } catch (err) {
    console.warn(err);
  }
}

function renderRules(items) {
  const body = document.getElementById("rules-body");
  body.innerHTML = "";
  items.forEach(rule => {
    const extraColumns = typeof protocolRenderRuleColumns === "function"
      ? protocolRenderRuleColumns(rule)
      : "";
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${rule.id}</td>
      <td>${rule.listen_addr}</td>
      <td>${rule.target_addr}</td>
      ${extraColumns}
      <td>${rule.enabled}</td>
      <td>
        <button onclick="toggleRule(${rule.id}, ${rule.enabled})">${rule.enabled ? "Disable" : "Enable"}</button>
        <button onclick="editRuleById(${rule.id})">Edit</button>
        <button onclick="deleteRule(${rule.id})">Delete</button>
      </td>
    `;
    body.appendChild(row);
  });
}

function renderActive(items) {
  const body = document.getElementById("active-body");
  body.innerHTML = "";
  items.forEach(conn => {
    const row = document.createElement("tr");
    // Calculate speed (bytes per second) based on bytes_transferred and time elapsed
    const speed = calculateSpeed(conn.bytes_transferred, conn.last_update, conn.started_at);
    row.innerHTML = `
      <td>${conn.conn_id}</td>
      <td>${conn.rule_id}</td>
      <td>${conn.listen_port || ""}</td>
      <td>${conn.client_ip}</td>
      <td>${conn.started_at}</td>
      <td>${speed}</td>
    `;
    body.appendChild(row);
  });
}

function calculateSpeed(bytesTransferred, lastUpdate, startedAt) {
  if (bytesTransferred === 0) return "0 B/s";
  
  const now = new Date();
  const lastUpdateDate = new Date(lastUpdate);
  const startedDate = new Date(startedAt);
  
  // Use the more recent time for calculation
  const timeDiff = Math.max((now - lastUpdateDate) / 1000, 1); // seconds, at least 1
  
  const bytesPerSecond = bytesTransferred / timeDiff;
  
  // Format the speed
  if (bytesPerSecond < 1024) {
    return `${bytesPerSecond.toFixed(1)} B/s`;
  } else if (bytesPerSecond < 1024 * 1024) {
    return `${(bytesPerSecond / 1024).toFixed(1)} KB/s`;
  } else if (bytesPerSecond < 1024 * 1024 * 1024) {
    return `${(bytesPerSecond / (1024 * 1024)).toFixed(1)} MB/s`;
  } else {
    return `${(bytesPerSecond / (1024 * 1024 * 1024)).toFixed(1)} GB/s`;
  }
}

function renderRecent(items) {
  const body = document.getElementById("recent-body");
  body.innerHTML = "";
  items.forEach(entry => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${entry.id}</td>
      <td>${entry.rule_id}</td>
      <td>${entry.listen_port || ""}</td>
      <td>${entry.client_ip}</td>
      <td>${entry.started_at}</td>
      <td>${entry.ended_at || ""}</td>
      <td>${entry.bytes_up}</td>
      <td>${entry.bytes_down}</td>
    `;
    body.appendChild(row);
  });
}

function renderBlocked(items) {
  const body = document.getElementById("blocked-body");
  body.innerHTML = "";
  items.forEach(entry => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${entry.id}</td>
      <td>${entry.rule_id}</td>
      <td>${entry.listen_port || ""}</td>
      <td>${entry.client_ip}</td>
      <td>${entry.started_at}</td>
      <td>${entry.ended_at || ""}</td>
      <td>${entry.reason || ""}</td>
    `;
    body.appendChild(row);
  });
}

function renderDdos(items) {
  const body = document.getElementById("ddos-body");
  body.innerHTML = "";
  items.forEach(entry => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${entry.ip}</td>
      <td>${entry.count}</td>
      <td>${entry.last_seen}</td>
      <td>${entry.last_port || ""}</td>
      <td>${entry.last_reason}</td>
    `;
    body.appendChild(row);
  });
}

function renderBlocks(items) {
  const body = document.getElementById("block-body");
  body.innerHTML = "";
  items.forEach(item => {
    const port = item.port ? item.port : "";
    const label = item.port ? item.port : "*";
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.ip}</td>
      <td>${label}</td>
      <td><button onclick="removeBlock('${item.ip}', '${port}')">Remove</button></td>
    `;
    body.appendChild(row);
  });
}

function renderAllowlist(items) {
  const body = document.getElementById("allow-body");
  body.innerHTML = "";
  items.forEach(item => {
    const port = item.port ? item.port : "";
    const label = item.port ? item.port : "*";
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.ip}</td>
      <td>${label}</td>
      <td><button onclick="removeAllow('${item.ip}', '${port}')">Remove</button></td>
    `;
    body.appendChild(row);
  });
}

function setAllowlistMode(enabled) {
  const checkbox = document.getElementById("allowlist-enabled");
  checkbox.checked = !!enabled;
}

async function toggleRule(id, enabled) {
  const path = enabled ? `/api/rules/${id}/disable` : `/api/rules/${id}/enable`;
  await api(path, { method: "POST" });
  await refresh();
}

function editRuleById(id) {
  const rule = cachedRules.find(item => item.id === id);
  if (!rule) return;
  document.getElementById("listen").value = rule.listen_addr;
  document.getElementById("target").value = rule.target_addr;
  document.getElementById("rule-enabled").checked = !!rule.enabled;
  if (typeof protocolSyncForm === "function") {
    protocolSyncForm(rule);
  }
  setEditing(rule);
  setEditorMode("form");
  syncJsonFromForm();
  selectTab("rules");
}

async function deleteRule(id) {
  await api(`/api/rules/${id}`, { method: "DELETE" });
  await refresh();
}

async function addBlock() {
  const ip = document.getElementById("block-ip").value.trim();
  const portText = document.getElementById("block-port").value.trim();
  const errorBox = document.getElementById("block-error");
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
    await api("/api/blocklist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, port })
    });
    document.getElementById("block-ip").value = "";
    document.getElementById("block-port").value = "";
    await refresh();
  } catch (err) {
    errorBox.textContent = err.message;
  }
}

async function removeBlock(ip, port) {
  const query = port ? `?port=${encodeURIComponent(port)}` : "";
  await api(`/api/blocklist/${encodeURIComponent(ip)}${query}`, { method: "DELETE" });
  await refresh();
}

async function addAllow() {
  const ip = document.getElementById("allow-ip").value.trim();
  const portText = document.getElementById("allow-port").value.trim();
  const errorBox = document.getElementById("allow-error");
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
    await api("/api/allowlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, port })
    });
    document.getElementById("allow-ip").value = "";
    document.getElementById("allow-port").value = "";
    await refresh();
  } catch (err) {
    errorBox.textContent = err.message;
  }
}

async function removeAllow(ip, port) {
  const query = port ? `?port=${encodeURIComponent(port)}` : "";
  await api(`/api/allowlist/${encodeURIComponent(ip)}${query}`, { method: "DELETE" });
  await refresh();
}

async function toggleAllowlistMode() {
  const enabled = document.getElementById("allowlist-enabled").checked;
  await api("/api/allowlist-mode", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled })
  });
  await refresh();
}

loadTemplates();
resetEditor();
applySectionState();
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"#;
