#[cfg(unix)]
mod unix;
#[cfg(unix)]
use self::unix::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use self::windows::*;

use anyhow::{anyhow, Context};
use if_addrs::{get_if_addrs};
use if_watch::{tokio::IfWatcher, IfEvent};
use ipnet::IpNet;
use std::collections::{HashSet, HashMap};
use tokio_stream::StreamExt;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IfEventExt {
    Up((IpNet, bool)),
    Down(IpNet),
}

#[derive(Debug)]
pub enum IfNameFilter {
    Exclusive {
        ifnames: HashSet<String>,
    },

    Inclusive {
        ifnames: HashSet<String>,
    }
}

pub struct IfWatcherExt {
    inner: IfWatcher,
    exclude_ipnets: Vec<IpNet>,
    include_ipnets: Vec<IpNet>,
    exclude_metered: bool,
    exclude_not_metered: bool,
    ifname_filter: Option<IfNameFilter>,
    included: HashMap<IpNet, bool>,
    excluded: HashSet<IpNet>,
}

impl IfWatcherExt {
    pub async fn new(
        exclude_ipnets: Vec<IpNet>,
        include_ipnets: Vec<IpNet>,
        exclude_metered: bool,
        exclude_not_metered: bool,
        ifname_filter: Option<IfNameFilter>,
    ) -> anyhow::Result<Self> {
        let ifwatcher = IfWatcher::new().context("initialize IfWatcher")?;
        Ok(IfWatcherExt {
            inner: ifwatcher,
            exclude_ipnets,
            include_ipnets,
            exclude_metered,
            exclude_not_metered,
            ifname_filter,
            included: HashMap::new(),
            excluded: HashSet::new(),
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IpNet, &bool)> {
        self.included.iter()
    }

    // Not cancel-safe
    pub async fn pop(&mut self) -> anyhow::Result<IfEventExt> {
        loop {
            let event = self
                .inner
                .next()
                .await
                .ok_or(anyhow!("unknown error"))
                .context("IfWatcher::next()")?
                .context("IfWatcher::next()")?;
            match event {
                IfEvent::Up(ipnet) => {
                    let excluded = self
                        .exclude_ipnets
                        .iter()
                        .find(|exclude| exclude.contains(&ipnet.addr()));
                    let included = self
                        .include_ipnets
                        .iter()
                        .find(|include| include.contains(&ipnet.addr()));

                    if excluded.is_some() && included.is_none() {
                        self.excluded.insert(ipnet);
                        continue;
                    }

                    let ifname = get_if_addrs()?
                        .iter()
                        .find(|v| {
                            v.ip() == ipnet.addr()
                        })
                        .map(|v| v.name.clone());
                    let filtered = match (&self.ifname_filter, ifname) {
                        (Some(IfNameFilter::Exclusive { ifnames }), Some(ifname)) => {
                            ifnames.contains(&ifname)
                        },
                        (Some(IfNameFilter::Inclusive { ifnames }), Some(ifname)) => {
                            !ifnames.contains(&ifname)
                        },
                        (None, Some(_)) => {
                            false
                        },
                        (_, None) => {
                            // IpAddr of Down I/F
                            true
                        },
                    };

                    if filtered {
                        self.excluded.insert(ipnet);
                        continue;
                    }

                    let metered = is_metered(ipnet.addr()).await.context("is_metered()");
                    let metered = metered?;
                    if (metered && !self.exclude_metered)
                        || (!metered && !self.exclude_not_metered)
                    {
                        self.included.insert(ipnet, metered);
                        return Ok(IfEventExt::Up((ipnet, metered)));
                    } else {
                        self.excluded.insert(ipnet);
                    }
                }
                IfEvent::Down(ipnet) => {
                    if self.excluded.contains(&ipnet) {
                        self.excluded.remove(&ipnet);
                        continue;
                    }
                    if self.included.contains_key(&ipnet) {
                        self.included.remove(&ipnet);
                    }
                    return Ok(IfEventExt::Down(ipnet));
                }
            }
        }
    }
}
