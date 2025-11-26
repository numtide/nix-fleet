use std::str::FromStr;

use anyhow::Context;
use better_commands::CmdOutput;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Facts {
    pub os: platforms::OS,
    pub os_info: os_info::Info,
    pub mid: Option<mid::MidData>,
    pub maybe_facter: Option<String>,
    pub maybe_nixos_facter: Option<String>,
}

const MID_SEED: &str = "changing this will cause the hashes to be different";

impl Facts {
    /// Gathers various facts from the environment.
    pub async fn try_from_environment() -> anyhow::Result<Facts> {
        let os = platforms::OS::from_str(std::env::consts::OS).context("determining OS")?;

        let os_info = os_info::get();
        let mid_data = mid::data(MID_SEED)
            .map_err(|e| tracing::warn!("couldn't get machine machine data: {e}"))
            .ok();

        let filter_output_fn = |output: CmdOutput| -> Option<String> {
            match output.clone().status_code() {
                Some(i) if i.is_negative() => return None,
                Some(_) | None => (),
            };

            output.stdout().and_then(|lines| {
                let non_empty_lines = lines
                    .into_iter()
                    .map(|l| l.content.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>();

                if !non_empty_lines.is_empty() {
                    Some(non_empty_lines.join("\n"))
                } else {
                    None
                }
            })
        };

        let maybe_facter = tokio::task::spawn_blocking(|| {
            better_commands::run(
                std::process::Command::new("facter")
                    .arg("--json")
                    .arg("--no-ruby")
                    .arg("--no-color"),
            )
        })
        .await
        .context("running `facter` from PATH")
        .map(filter_output_fn)
        .inspect_err(|e| tracing::error!("{e}"))
        .ok()
        .flatten();

        let maybe_nixos_facter = tokio::task::spawn_blocking(|| {
            better_commands::run(&mut std::process::Command::new("nixos-facter"))
        })
        .await
        .context("running `nixos-facter` from PATH")
        .map(filter_output_fn)
        .inspect_err(|e| tracing::error!("{e}"))
        .ok()
        .flatten();

        let facts = Facts {
            os,
            os_info,
            mid: mid_data,
            maybe_facter,
            maybe_nixos_facter,
        };

        Ok(facts)
    }
}
