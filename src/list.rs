use crate::{models::Preference, utils};
use color_eyre::Result;
use rayon::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{stdout, BufWriter, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub fn print_ips<const PRINT_ONLY_EXPLOITABLE: bool>(input: PathBuf) -> Result<()> {
    let files = utils::NessusFiles::new(input)?;

    let ips_ports = Arc::new(Mutex::new(BTreeMap::<_, BTreeSet<_>>::new()));

    files.par_bridge().try_for_each(|file_name| -> Result<()> {
        let nessus_str = fs::read_to_string(file_name?)?;

        let nessus_data = utils::get_nessus_data(&nessus_str)?;

        // Print name, target and whoami
        {
            let mut stdout_buf = BufWriter::new(stdout().lock());

            writeln!(&mut stdout_buf, "Report: {}", nessus_data.report.name)?;

            for (name, value) in nessus_data
                .preferences()
                .iter()
                .filter_map(Preference::as_relevant_preference)
            {
                writeln!(&mut stdout_buf, "{name}: {value}")?;
            }

            stdout_buf.write_all(b"\n")?;
        }

        nessus_data.report.report_hosts.par_iter().for_each(|host| {
            let mut ports: BTreeSet<_> = host
                .report_items
                .iter()
                .filter_map(|report| {
                    (if PRINT_ONLY_EXPLOITABLE {
                        report.exploit_available == Some(true)
                    } else {
                        report.port != 0
                    })
                    .then_some(report.port)
                })
                .collect();

            if !ports.is_empty() {
                ips_ports
                    .lock()
                    .unwrap()
                    .entry(host.ip_addr)
                    .and_modify(|p| p.append(&mut ports))
                    .or_insert(ports);
            }
        });

        Ok(())
    })?;

    let mut stdout_buf = BufWriter::new(stdout().lock());

    let ips_ports = Arc::try_unwrap(ips_ports).unwrap().into_inner().unwrap();
    let num_ips = ips_ports.len();

    writeln!(&mut stdout_buf, "{:<16} Ports", "IP")?;

    for (ip, ports) in &ips_ports {
        writeln!(&mut stdout_buf, "{ip:<16} {ports:?}")?;
    }

    writeln!(&mut stdout_buf, "Num IPs: {num_ips}")?;

    Ok(())
}
