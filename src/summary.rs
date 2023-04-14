use crate::utils;
use color_eyre::Result;
use rayon::prelude::*;
use std::{fs, net::IpAddr, path::PathBuf};
use tabled::{
    settings::{
        object::Columns,
        style::{HorizontalLine, Line},
        Alignment, Modify, Style,
    },
    Table,
};

pub fn print_summary(input: PathBuf, host: IpAddr) -> Result<()> {
    let files = utils::NessusFiles::new(input)?;

    files.par_bridge().try_for_each(|file_name| -> Result<()> {
        let nessus_str = fs::read_to_string(file_name?)?;

        let nessus_data = utils::get_nessus_data(&nessus_str)?;

        // TODO: join summaries
        if let Some(report) = nessus_data
            .report
            .report_hosts
            .par_iter()
            .find_any(|r| r.ip_addr == host)
        {
            let summary = report.summary();

            println!(
                "{}",
                Table::new(summary.vulns)
                    .with(Style::blank().horizontals([HorizontalLine::new(
                        1,
                        Line::new(Some('─'), Some(' '), None, None)
                    )]))
                    .with(Modify::list(Columns::single(3), Alignment::right()))
                    .with(Modify::list(Columns::single(4), Alignment::center()))
            );
        };

        Ok(())
    })?;

    Ok(())
}
