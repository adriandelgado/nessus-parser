# Nessus Parser

[![Crates.io](https://img.shields.io/crates/v/nessus_parser.svg)](https://crates.io/crates/nessus_parser)
[![Docs.rs](https://docs.rs/nessus_parser/badge.svg)](https://docs.rs/nessus_parser)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

A parser for `.nessus` (v2) XML reports.

This library provides strongly-typed data structures to represent the data from a Nessus vulnerability scan, allowing for safe and efficient analysis of scan results. It is designed to be fast by avoiding most allocations and string copies, borrowing directly from the input XML string.

This has been tested on a large sample of Nessus files, however [the documentation](https://static.tenable.com/documentation/nessus_v2_file_format.pdf) is full of typos and contradictions, so this may not work on all possible Nessus files. Please report any issues with minimal examples of files that aren't properly parsed.

## Features

- **Comprehensive Parsing**: Models the `NessusClientData_v2` format, including `Policy`, `Report`, `Host`, `HostProperties`, and `ReportItem` elements.
- **Strongly-Typed**: Maps Nessus data to expressive Rust structs and enums, preventing common errors and making the data easy to work with.
- **Structured Data**: Intelligently parses complex string-based fields, like the output of the "Ping the remote host" plugin, into a structured `PingOutcome` enum.
- **Robust**: Built on top of the `roxmltree` crate for fast and correct XML processing.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for bugs, feature requests, or suggestions.

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
