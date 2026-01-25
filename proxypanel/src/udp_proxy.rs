use anyhow::Result;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::app::{record_blocked, record_connection_end, register_connection, AppState, ListenerHandle};

const UDP_BUFFER_SIZE: usize = 65_507;
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_IDLE_TICK: Duration = Duration::from_secs(5);

struct ClientEntry {
    conn_id: u64,
    upstream: Arc<UdpSocket>,
    last_seen: Instant,
    bytes_up: u64,
    bytes_down: u64,
}

pub(crate) async fn start_udp_listener(
    state: Arc<RwLock<AppState>>,
    rule_id: u64,
    listen_addr: String,
    listen_port: Option<u16>,
    target_addr: String,
) -> Result<ListenerHandle> {
    let listener = Arc::new(UdpSocket::bind(listen_addr.as_str()).await?);
    let shutdown = CancellationToken::new();
    let shutdown_task = shutdown.clone();
    let clients: Arc<Mutex<HashMap<SocketAddr, ClientEntry>>> = Arc::new(Mutex::new(HashMap::new()));

    let task = tokio::spawn({
        let listener = listener.clone();
        let state = state.clone();
        let clients = clients.clone();
        let shutdown = shutdown_task.clone();
        async move {
            let mut buf = vec![0u8; UDP_BUFFER_SIZE];
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        break;
                    }
                    recv = listener.recv_from(&mut buf) => {
                        let (len, client_addr) = match recv {
                            Ok(value) => value,
                            Err(err) => {
                                warn!("UDP recv error: {}", err);
                                continue;
                            }
                        };

                        let client_ip = client_addr.ip().to_string();
                        let mut needs_session = false;
                        {
                            let guard = clients.lock().await;
                            if !guard.contains_key(&client_addr) {
                                needs_session = true;
                            }
                        }

                        if needs_session {
                            let conn_id = match register_connection(&state, rule_id, &client_ip, listen_port).await {
                                Ok(value) => value,
                                Err(reason) => {
                                    record_blocked(&state, rule_id, listen_port, client_ip, reason).await;
                                    continue;
                                }
                            };

                            let upstream = match UdpSocket::bind("0.0.0.0:0").await {
                                Ok(socket) => socket,
                                Err(err) => {
                                    let _ = record_connection_end(&state, conn_id, 0, 0, Some(format!("UDP bind failed: {}", err))).await;
                                    continue;
                                }
                            };

                            if let Err(err) = upstream.connect(target_addr.as_str()).await {
                                let _ = record_connection_end(&state, conn_id, 0, 0, Some(format!("UDP connect failed: {}", err))).await;
                                continue;
                            }

                            let upstream = Arc::new(upstream);
                            let entry = ClientEntry {
                                conn_id,
                                upstream: upstream.clone(),
                                last_seen: Instant::now(),
                                bytes_up: 0,
                                bytes_down: 0,
                            };

                            {
                                let mut guard = clients.lock().await;
                                if guard.contains_key(&client_addr) {
                                    continue;
                                }
                                guard.insert(client_addr, entry);
                            }

                            spawn_upstream_task(
                                state.clone(),
                                listener.clone(),
                                clients.clone(),
                                client_addr,
                                upstream,
                                shutdown.clone(),
                            );
                        }

                        let upstream = {
                            let mut guard = clients.lock().await;
                            if let Some(entry) = guard.get_mut(&client_addr) {
                                entry.bytes_up = entry.bytes_up.saturating_add(len as u64);
                                entry.last_seen = Instant::now();
                                entry.upstream.clone()
                            } else {
                                continue;
                            }
                        };

                        if let Err(err) = upstream.send(&buf[..len]).await {
                            warn!("UDP send error: {}", err);
                        }
                    }
                }
            }
            info!("UDP listener stopped for rule {}", rule_id);
        }
    });

    Ok(ListenerHandle { shutdown, task })
}

fn spawn_upstream_task(
    state: Arc<RwLock<AppState>>,
    listener: Arc<UdpSocket>,
    clients: Arc<Mutex<HashMap<SocketAddr, ClientEntry>>>,
    client_addr: SocketAddr,
    upstream: Arc<UdpSocket>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUFFER_SIZE];
        let mut tick = tokio::time::interval(UDP_IDLE_TICK);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    break;
                }
                recv = upstream.recv(&mut buf) => {
                    let len = match recv {
                        Ok(value) => value,
                        Err(err) => {
                            warn!("UDP upstream recv error: {}", err);
                            break;
                        }
                    };
                    if let Err(err) = listener.send_to(&buf[..len], client_addr).await {
                        warn!("UDP send_to error: {}", err);
                        break;
                    }
                    let mut guard = clients.lock().await;
                    if let Some(entry) = guard.get_mut(&client_addr) {
                        entry.bytes_down = entry.bytes_down.saturating_add(len as u64);
                        entry.last_seen = Instant::now();
                    }
                }
                _ = tick.tick() => {
                    let idle = {
                        let guard = clients.lock().await;
                        match guard.get(&client_addr) {
                            Some(entry) => entry.last_seen.elapsed() > UDP_IDLE_TIMEOUT,
                            None => true,
                        }
                    };
                    if idle {
                        break;
                    }
                }
            }
        }

        let entry = {
            let mut guard = clients.lock().await;
            guard.remove(&client_addr)
        };
        if let Some(entry) = entry {
            let _ = record_connection_end(&state, entry.conn_id, entry.bytes_up, entry.bytes_down, None).await;
        }
    });
}
