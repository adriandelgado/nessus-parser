use clap::Parser;
use color_eyre::{
    eyre::{bail, ensure, Context},
    Result,
};
use hard_xml::{XmlRead, XmlReader};
use models::NessusClientDataV2;
use rayon::prelude::*;
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{stdout, BufWriter, Write},
    net::IpAddr,
};

pub mod cmd;
pub mod models;

fn main() -> Result<()> {
    color_eyre::install()?;

    let args = cmd::Args::parse();

    let files: Vec<_> = if args.input.is_dir() {
        for file in args.input.read_dir()? {
            let file = file?;
            if file.file_type()?.is_file() {}
        }

        args.input
            .read_dir()?
            .filter_map(|f| {
                let dir_entry = f.ok()?;

                let path = dir_entry.path();

                (dir_entry.file_type().ok()?.is_file()
                    && path.extension() == Some("nessus".as_ref()))
                .then_some(path)
            })
            .collect()
    } else if args.input.is_file() && args.input.extension() == Some("nessus".as_ref()) {
        vec![args.input]
    } else {
        bail!("input must be a `.nessus` file or a directory containing said files");
    };

    ensure!(
        !files.is_empty(),
        "directory must have at least one `.nessus` file"
    );

    let ips = files
        .par_iter()
        .map(|file_name| {
            let nessus_str = fs::read_to_string(file_name)?;

            let mut reader = XmlReader::new(&nessus_str);

            let mut nessus_data = NessusClientDataV2::from_reader(&mut reader)?;

            nessus_data.remove_plugin_set();

            let (r1, r2) = rayon::join(
                || -> Result<Vec<IpAddr>> {
                    let relevant_preferences = nessus_data.relevant_preferences();

                    {
                        let mut stdout_buf = BufWriter::new(stdout().lock());

                        for (name, value) in relevant_preferences {
                            writeln!(&mut stdout_buf, "{name}: {value}")?;
                        }
                    }

                    let mut ips: Vec<_> = nessus_data
                        .report_host()
                        .par_iter()
                        .filter_map(|host| {
                            host.report_item()
                                .par_iter()
                                .any(|report| report.port() != "0")
                                .then_some(host.name())
                        })
                        .collect();

                    ips.par_sort_unstable();

                    Ok(ips)
                },
                || -> Result<()> {
                    if args.json {
                        let mut json_filename = file_name.clone();
                        if json_filename.set_extension("json") {
                            let out_buf = BufWriter::new(
                                OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open(&json_filename)
                                    .wrap_err_with(|| {
                                        format!("file: {json_filename:?} already exists")
                                    })?,
                            );
                            serde_json::to_writer_pretty(out_buf, &nessus_data)?;
                        }
                    }

                    Ok(())
                },
            );
            let ips = r1?;
            r2?;

            Ok(ips)
        })
        .collect::<Result<Vec<Vec<IpAddr>>>>()?;

    let ips: BTreeSet<IpAddr> = ips.into_iter().flatten().collect();

    let mut stdout_buf = BufWriter::new(stdout().lock());

    for ip in &ips {
        writeln!(&mut stdout_buf, "{ip}")?;
    }

    writeln!(&mut stdout_buf, "Num IPs: {}", ips.len())?;

    Ok(())
}
