use std::net::IpAddr;

pub async fn is_metered(_target: IpAddr) -> anyhow::Result<bool> {
    Ok(false)
}