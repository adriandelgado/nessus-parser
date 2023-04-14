use crate::{
    models::{RiskFactor, Summary, VulnerabilityNoPort},
    utils,
};
use color_eyre::{Report, Result};
use rayon::prelude::*;
use std::{
    collections::BTreeSet,
    fs,
    io::{stdout, BufWriter, Write},
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tabled::{
    settings::{
        object::Columns,
        style::{HorizontalLine, Line},
        width::Truncate,
        Alignment, Modify, Style,
    },
    Table,
};

pub fn print_summary(input: PathBuf, host: Option<IpAddr>) -> Result<()> {
    let files = utils::NessusFiles::new(input)?;
    if let Some(host) = host {
        single_host(files, host)?;
    } else {
        all_hosts(files)?;
    }
    Ok(())
}

fn all_hosts(files: utils::NessusFiles) -> Result<()> {
    let vulnerabilities = Arc::new(Mutex::new(BTreeSet::<VulnerabilityNoPort>::new()));

    files.par_bridge().try_for_each(|file_name| -> Result<()> {
        let file_name = file_name?;
        let nessus_str = fs::read_to_string(file_name)?;

        let nessus_data = utils::get_nessus_data(&nessus_str)?;

        nessus_data
            .report
            .report_hosts
            .par_iter()
            .for_each(|report| {
                let mut vulns = report
                    .report_items
                    .iter()
                    .filter(|report| report.risk_factor != RiskFactor::None)
                    .map(VulnerabilityNoPort::from)
                    .collect();

                vulnerabilities.lock().unwrap().append(&mut vulns);
            });

        Ok(())
    })?;

    let vulnerabilities = Arc::try_unwrap(vulnerabilities)
        .unwrap()
        .into_inner()
        .unwrap();

    let width: usize = terminal_size::terminal_size()
        .map_or(80, |(w, _)| w.0 - 37)
        .into();

    println!(
        "{}",
        Table::new(vulnerabilities)
            .with(Style::blank().horizontals([HorizontalLine::new(
                1,
                Line::new(Some('─'), Some(' '), None, None)
            )]))
            .with(Modify::list(
                Columns::single(2),
                Truncate::new(width).suffix("...")
            ))
            .with(Modify::list(Columns::single(3), Alignment::center()))
    );

    Ok(())
}

fn single_host(files: utils::NessusFiles, host: IpAddr) -> Result<()> {
    let vulns = files
        .par_bridge()
        .filter_map(|file_name| {
            let file_name = try_wrap_option!(file_name);
            let nessus_str = try_wrap_option!(fs::read_to_string(file_name));

            let nessus_data = try_wrap_option!(utils::get_nessus_data(&nessus_str));

            let Some(report) = nessus_data
                .report
                .report_hosts
                .par_iter()
                .find_any(|r| r.ip_addr == host) else { return None; };

            let Summary {
                macs,
                os,
                vulns,
                traceroute,
            } = report.summary();

            {
                let mut stdout_buf = BufWriter::new(stdout().lock());
                if let Some(os) = os {
                    writeln!(&mut stdout_buf, "OS: {:?}", os).unwrap()
                }
                if let Some(macs) = macs {
                    writeln!(&mut stdout_buf, "MACs: {:?}", macs).unwrap()
                }

                stdout_buf.write_all(b"Traceroute:\n").unwrap();
                for (i, ip) in traceroute.into_iter().enumerate() {
                    if let Some(ip) = ip {
                        writeln!(&mut stdout_buf, "-> {i:02}: {ip}").unwrap()
                    } else {
                        writeln!(&mut stdout_buf, "-> {i:02}: ???").unwrap()
                    }
                }
            }

            Some(Ok::<_, Report>(vulns))
        })
        .try_reduce(
            || BTreeSet::new(),
            |mut a, mut b| {
                a.append(&mut b);
                Ok(a)
            },
        )?;

    let width: usize = terminal_size::terminal_size()
        .map_or(80, |(w, _)| w.0 - 44)
        .into();

    println!(
        "{}",
        Table::new(vulns)
            .with(Style::blank().horizontals([HorizontalLine::new(
                1,
                Line::new(Some('─'), Some(' '), None, None)
            )]))
            .with(Modify::list(
                Columns::single(2),
                Truncate::new(width).suffix("...")
            ))
            .with(Modify::list(Columns::single(3), Alignment::right()))
            .with(Modify::list(Columns::single(4), Alignment::center()))
    );

    Ok(())
}
