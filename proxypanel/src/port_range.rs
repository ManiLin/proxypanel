use anyhow::{anyhow, Result};

const MAX_PORT_RANGE: usize = 1024;

#[derive(Debug, Clone)]
pub struct ListenTarget {
    pub listen_addr: String,
    pub listen_port: u16,
    pub target_addr: String,
}

pub fn expand_listen_targets(listen_addr: &str, target_addr: &str) -> Result<Vec<ListenTarget>> {
    let (listen_host, listen_port_raw) = split_host_port(listen_addr)?;
    let listen_ports = parse_ports(&listen_port_raw)?;

    let (target_host, target_port_raw) = split_host_port(target_addr)?;
    let target_ports = parse_ports(&target_port_raw)?;

    let targets = if target_ports.len() == 1 {
        listen_ports
            .into_iter()
            .map(|listen_port| ListenTarget {
                listen_addr: format!("{}:{}", listen_host, listen_port),
                listen_port,
                target_addr: format!("{}:{}", target_host, target_ports[0]),
            })
            .collect::<Vec<_>>()
    } else if target_ports.len() == listen_ports.len() {
        listen_ports
            .into_iter()
            .enumerate()
            .map(|(idx, listen_port)| ListenTarget {
                listen_addr: format!("{}:{}", listen_host, listen_port),
                listen_port,
                target_addr: format!("{}:{}", target_host, target_ports[idx]),
            })
            .collect::<Vec<_>>()
    } else {
        return Err(anyhow!(
            "Port range mismatch: listen has {} ports, target has {} ports",
            listen_ports.len(),
            target_ports.len()
        ));
    };

    Ok(targets)
}

fn split_host_port(addr: &str) -> Result<(String, String)> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(anyhow!("Address is empty"));
    }

    if addr.starts_with('[') {
        let end = addr
            .find(']')
            .ok_or_else(|| anyhow!("Invalid IPv6 address"))?;
        let host = addr[..=end].to_string();
        let rest = addr[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("Missing port in address"))?;
        if rest.is_empty() {
            return Err(anyhow!("Missing port in address"));
        }
        return Ok((host, rest.to_string()));
    }

    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("Missing port in address"))?;
    if host.is_empty() || port.is_empty() {
        return Err(anyhow!("Missing host or port in address"));
    }
    Ok((host.to_string(), port.to_string()))
}

fn parse_ports(raw: &str) -> Result<Vec<u16>> {
    if let Some((start_raw, end_raw)) = raw.split_once('-') {
        let start = parse_port_value(start_raw)?;
        let end = parse_port_value(end_raw)?;
        if start == 0 || end == 0 {
            return Err(anyhow!("Port range cannot include 0"));
        }
        if start > end {
            return Err(anyhow!("Port range start is greater than end"));
        }
        let len = (end - start) as usize + 1;
        if len > MAX_PORT_RANGE {
            return Err(anyhow!("Port range too large (max {})", MAX_PORT_RANGE));
        }
        return Ok((start..=end).collect());
    }

    let port = parse_port_value(raw)?;
    Ok(vec![port])
}

fn parse_port_value(raw: &str) -> Result<u16> {
    let value = raw.trim().parse::<u16>()?;
    Ok(value)
}
