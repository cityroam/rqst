use anyhow::Context;
use std::net::IpAddr;
use windows::core::GUID;
use windows::Networking::Connectivity::{
    ConnectionProfile, ConnectionProfileFilter, NetworkCostType, NetworkInformation,
};
use windows::Networking::HostNameType;

pub async fn is_metered(target: IpAddr) -> anyhow::Result<bool> {
    let mut ipaddrs = Vec::new();

    for hostname in NetworkInformation::GetHostNames()
        .context("GetHostNames")?
    {
        match hostname.Type()
            .context("hostname::Type()")?
        {
            HostNameType::Ipv4 | HostNameType::Ipv6 => {
                ipaddrs.push(hostname);
            }
            _ => {}
        }
    }

    for ipaddr in &ipaddrs {
        let addr = ipaddr.ToString()
            .with_context(|| format!("call ToString() for {:?}", ipaddr))?
            .to_string();
        let addr: IpAddr = addr
            .parse()
            .with_context(|| format!("parse for {:?}", addr))?;
        if addr != target {
            continue;
        }
        let adapter = ipaddr.IPInformation()
            .context("IPInformation()")?
            .NetworkAdapter()
            .context("NetworkAdapter()")?;
        let profile = find_connected_profile(
            adapter.NetworkAdapterId()
                .context("NetworkAdapterId")?
            ).await
            .context("find_connected_profile")?;
        if let Some(profile) = profile {
            let cost_type = profile.GetConnectionCost()
                .context("GetConnectionCost")?
                .NetworkCostType()
                .context("NetworkCostType")?;
            
            if cost_type == NetworkCostType::Fixed || cost_type == NetworkCostType::Variable {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

async fn find_connected_profile(guid: GUID) -> anyhow::Result<Option<ConnectionProfile>> {
    let filter = ConnectionProfileFilter::new()
        .context("ConnectionProfileFilter::new()")?;
    filter.SetIsConnected(true)
        .context("SetIsConnected")?;
    let async_op = NetworkInformation::FindConnectionProfilesAsync(&filter)
        .context("FindConnectionProfilesAsync")?;
    for profile in async_op.await.context("async_op")?  {
        
        if let Ok(adapter) = profile.NetworkAdapter() {
            if adapter.NetworkAdapterId()
                .context("NetworkAdapterId")? == guid
            {
                return Ok(Some(profile));
            }
        }
    }
    Ok(None)
}
