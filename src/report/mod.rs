use std::{borrow::Cow, collections::HashMap, net::IpAddr};

use jiff::Timestamp;
use roxmltree::{Node, StringStorage};

use crate::{
    MacAddress, StringStorageExt, assert_empty_text,
    error::FormatError,
    ping::PingOutcome,
    report::item::{Item, PluginType, Protocol},
};

pub mod item;

/// Represents the `<Report>` element, which contains the main body of the
/// scan results.
///
/// This struct holds the report's name and a collection of `Host` structs,
/// each detailing the findings for a single scanned target.
#[derive(Debug)]
pub struct Report<'input> {
    /// The name of the report
    pub name: Cow<'input, str>,
    /// A vector of hosts that were scanned and included in the report.
    pub hosts: Vec<Host<'input>>,
}

impl<'input> Report<'input> {
    pub(crate) fn from_xml_node(node: Node<'_, 'input>) -> Result<Self, FormatError> {
        let name = node
            .attributes()
            .find(|a| a.name() == "name")
            .ok_or(FormatError::MissingAttribute("name"))?
            .value_storage()
            .to_cow();

        let mut hosts = Vec::new();

        for child in node.children() {
            match child.tag_name().name() {
                "ReportHost" => {
                    hosts.push(Host::from_xml_node(child)?);
                }
                _ => assert_empty_text(child)?,
            }
        }

        Ok(Self { name, hosts })
    }
}

/// Represents a `<ReportHost>` element, containing all information gathered
/// for a single host.
#[derive(Debug)]
pub struct Host<'input> {
    /// The name of the host, typically its IP address or FQDN.
    pub name: Cow<'input, str>,
    /// A collection of metadata and properties discovered about the host.
    pub properties: HostProperties<'input>,
    /// A vector of `ReportItem` findings for this host, representing vulnerabilities,
    /// information gathered, etc.
    pub items: Vec<Item<'input>>,
    /// The parsed outcome of the "Ping the remote host" plugin (ID 10180),
    /// indicating the host's reachability status.
    pub ping_outcome: Option<PingOutcome>,
    /// The IP address of the scanner that performed the scan on this host,
    /// extracted from the "Nessus Scan Information" plugin (ID 19506).
    pub scanner_ip: Option<IpAddr>,
    /// A sorted list of ports found to be open on the host.
    pub open_ports: Vec<(u16, Protocol)>,
}

impl<'input> Host<'input> {
    fn from_xml_node(node: Node<'_, 'input>) -> Result<Self, FormatError> {
        const PING_THE_REMOTE_HOST_ID: u32 = 10180;
        const NESSUS_SCAN_INFORMATION_ID: u32 = 19506;

        let name = node
            .attributes()
            .find(|a| a.name() == "name")
            .ok_or(FormatError::MissingAttribute("name"))?
            .value_storage()
            .to_cow();

        let mut host_properties = None;
        let mut items = Vec::new();

        let mut ping_outcome = None;
        let mut scanner_ip = None;

        let mut open_ports = vec![];

        for child in node.children() {
            match child.tag_name().name() {
                "HostProperties" => {
                    if host_properties.is_some() {
                        return Err(FormatError::RepeatedTag("HostProperties"));
                    }
                    host_properties = Some(HostProperties::from_xml_node(child)?);
                }
                "ReportItem" => {
                    let item = Item::from_xml_node(child)?;
                    match item.plugin_id {
                        PING_THE_REMOTE_HOST_ID => {
                            let plugin_output = item
                                .plugin_output
                                .as_ref()
                                .ok_or(FormatError::MissingPluginOutput)?;
                            if ping_outcome.is_some() {
                                return Err(FormatError::RepeatedTag("Ping the remote host"));
                            }
                            ping_outcome = Some(PingOutcome::from_plugin_output(plugin_output)?);
                        }
                        NESSUS_SCAN_INFORMATION_ID => {
                            let plugin_output = item
                                .plugin_output
                                .as_ref()
                                .ok_or(FormatError::MissingPluginOutput)?;
                            if scanner_ip.is_some() {
                                return Err(FormatError::RepeatedTag("Nessus Scan Information"));
                            }
                            scanner_ip = Some(parse_scanner_ip(plugin_output)?);
                        }
                        // plugins that don't verify ports
                        10736 | 11111 | 14272 | 14274 => {}
                        _ => {
                            if item.port != 0 && item.plugin_type != PluginType::Local {
                                open_ports.push((item.port, item.protocol));
                            }
                        }
                    }

                    items.push(item);
                }
                _ => assert_empty_text(child)?,
            }
        }

        open_ports.sort_unstable();
        open_ports.dedup();

        Ok(Self {
            name,
            properties: host_properties.ok_or(FormatError::MissingTag("HostProperties"))?,
            items,
            ping_outcome,
            scanner_ip,
            open_ports,
        })
    }
}

fn parse_scanner_ip(plugin_output: &str) -> Result<IpAddr, FormatError> {
    let (_, rest) = plugin_output
        .split_once("Scanner IP : ")
        .ok_or(FormatError::MissingAttribute("Scanner IP"))?;
    let (ip, _) = rest
        .split_once('\n')
        .ok_or(FormatError::MissingAttribute("Scanner IP"))?;
    Ok(ip.parse()?)
}

/// Represents the `<HostProperties>` element, a collection of key-value tags
/// containing detailed metadata about a scanned host.
#[derive(Debug)]
pub struct HostProperties<'input> {
    /// The primary IP address of the host (`host-ip`).
    pub host_ip: IpAddr,
    /// A timestamp string indicating when the scan of this host began (`HOST_START`).
    pub host_start: &'input str,
    /// A timestamp indicating when the scan of this host began (`HOST_START_TIMESTAMP`).
    pub host_start_timestamp: Timestamp,
    /// A timestamp string indicating when the scan of this host ended (`HOST_END`).
    pub host_end: Option<&'input str>,
    /// A timestamp indicating when the scan of this host ended (`HOST_END_TIMESTAMP`).
    pub host_end_timestamp: Option<Timestamp>,

    // Apache_sites
    pub apache_sites: Option<Cow<'input, str>>,
    // bios-uuid
    pub bios_uuid: Option<&'input str>,
    // Credentialed_Scan
    pub credentialed_scan: Option<bool>,
    // DDI_Dir_Scanner_Global_Duration
    pub ddi_dir_scanner_global_duration: Option<u32>,
    // DDI_Dir_Scanner_Global_Init
    pub ddi_dir_scanner_global_init: Option<Timestamp>,
    // dead_host: "1"
    pub dead_host: Option<bool>,
    // host-ad-config
    pub host_ad_config: Option<Cow<'input, str>>,
    /// The fully qualified domain name of the host (`host-fqdn`).
    pub host_fqdn: Option<Cow<'input, str>>,
    // host-fqdns
    pub host_fqdns: Option<Cow<'input, str>>,
    // host-rdns
    pub host_rdns: Option<Cow<'input, str>>,
    // hostname
    pub hostname: Option<&'input str>,
    // ignore_printer: "1"
    pub ignore_printer: Option<bool>,
    // IIS_sites
    pub iis_sites: Option<Cow<'input, str>>,
    // LastAuthenticatedResults
    pub last_authenticated_results: Option<Timestamp>,
    // LastUnauthenticatedResults
    pub last_unauthenticated_results: Option<Timestamp>,
    // local-checks-proto
    pub local_checks_proto: Option<&'input str>,
    // netbios-name
    pub netbios_name: Option<Cow<'input, str>>,
    /// The operating system identified on the host (`operating-system`).
    pub operating_system: Option<&'input str>,
    // operating-system-conf
    pub operating_system_conf: Option<i32>,
    // operating-system-method
    pub operating_system_method: Option<&'input str>,
    // operating-system-unsupported
    pub operating_system_unsupported: Option<bool>,
    // os: "linux" | "mac" | "other" | "windows"
    pub os: Option<&'input str>,
    // patch-summary-total-cves: Option<u32>
    pub patch_summary_total_cves: Option<u32>,
    // policy-used
    pub policy_used: Option<Cow<'input, str>>,
    // rexec-login-used
    pub rexec_login_used: Option<&'input str>,
    // rlogin-login-used
    pub rlogin_login_used: Option<&'input str>,
    // rsh-login-used
    pub rsh_login_used: Option<&'input str>,
    // smb-login-used
    pub smb_login_used: Option<&'input str>,
    // ssh-login-used
    pub ssh_login_used: Option<&'input str>,
    // telnet-login-used
    pub telnet_login_used: Option<&'input str>,
    // sinfp-ml-prediction
    pub sinfp_ml_prediction: Option<Cow<'input, str>>,
    // sinfp-signature:
    // > P1:B11113:F0x12:W8192:O0204ffff:M1460:
    // >    P2:B11113:F0x12:W8192:O0204ffff010303080402080affffffff44454144:M1460:
    // >    P3:B00000:F0x00:W0:O0:M0
    // >    P4:190400_7_p=53R
    pub sinfp_signature: Option<&'input str>,
    // ssh-fingerprint
    pub ssh_fingerprint: Option<Cow<'input, str>>,
    /// The system type, such as "general-purpose", "printer", etc. (`system-type`).
    // > "unknown" | "general-purpose" | "hypervisor" | "firewall" | "router"
    // > | "embedded" | "camera" | "switch" | "General" | "load-balancer"
    // > | "wireless-access-point" | "printer"
    pub system_type: Option<&'input str>,
    // wmi-domain
    pub wmi_domain: Option<&'input str>,
    /// A list of MAC addresses discovered on the host (`mac-address`).
    pub mac_address: Vec<MacAddress>,
    /// A list of Common Platform Enumeration (CPE) strings (`cpe`, `cpe-0`, etc.).
    // cpe-<u16?>
    // > cpe:/o:<vendor>:<product?>
    // > cpe:/o:<vendor>:<product>:<version?> -> <string?>
    // > x-cpe:/h:<vendor>:<product>:<version>
    // > x-cpe:/a:<vendor>:<product>:<version?>
    pub cpe: Vec<Cow<'input, str>>,
    /// A list of IP addresses representing the hops in a traceroute to the target.
    // traceroute-hop-<u8>
    pub traceroute: Vec<Option<IpAddr>>,
    // netstat-listen-(tcp|udp)(4|6)-<u16>
    pub netstat_listen: Vec<(&'input str, u16, &'input str)>,
    // netstat-established-(tcp|udp)(4|6)-<u16>
    pub netstat_established: Vec<(&'input str, u16, &'input str)>,
    // patch-summary-txt-<32-hex-digits>
    pub patch_summary_txt: Vec<(&'input str, Cow<'input, str>)>,
    // enumerated-ports-<u16>-tcp: "open" (ports out of range)
    pub enumerated_ports: Vec<(u16, Protocol, &'input str)>,
    // patch-summary-cve-num-<32-hex-digits>
    pub patch_summary_cve_num: Vec<(&'input str, u32)>,
    // patch-summary-cves-<32-hex-digits>
    pub patch_summary_cves: Vec<(&'input str, Vec<&'input str>)>,
    // DDI_Dir_Scanner_Port_<u16>_Init
    pub ddi_dir_scanner_port_init: Vec<(u16, Timestamp)>,
    // DDI_Dir_Scanner_Port_<u16>_Pass_Start
    pub ddi_dir_scanner_port_pass_start: Vec<(u16, Timestamp)>,
    // DDI_Dir_Scanner_Port_<u16>_Duration
    pub ddi_dir_scanner_port_duration: Vec<(u16, u32)>,
    // DDI_Dir_Scanner_Port_<u16>_Pass_Timeout
    pub ddi_dir_scanner_port_pass_timeout: Vec<(u16, Timestamp)>,
    /// A map to hold any other host properties not explicitly parsed into
    /// other fields. The key is the tag's `name` attribute.
    // "MSXX-XXX" | "pd-XXXXXX-X", | "SecurityControls-X"
    // "TAG" -> "<32 hex digits>"
    pub others: HashMap<&'input str, Vec<Cow<'input, str>>>,
}

impl<'input> HostProperties<'input> {
    #[expect(clippy::too_many_lines)]
    fn from_xml_node(node: Node<'_, 'input>) -> Result<Self, FormatError> {
        let mut host_ip = None;
        let mut host_start = None;
        let mut host_start_timestamp = None;
        let mut host_end = None;
        let mut host_end_timestamp = None;
        let mut apache_sites = None;
        let mut bios_uuid = None;
        let mut credentialed_scan = None;
        let mut ddi_dir_scanner_global_duration = None;
        let mut ddi_dir_scanner_global_init = None;
        let mut dead_host = None;
        let mut host_ad_config = None;
        let mut host_fqdn = None;
        let mut host_fqdns = None;
        let mut host_rdns = None;
        let mut hostname = None;
        let mut ignore_printer = None;
        let mut iis_sites = None;
        let mut last_authenticated_results = None;
        let mut last_unauthenticated_results = None;
        let mut local_checks_proto = None;
        let mut netbios_name = None;
        let mut operating_system = None;
        let mut operating_system_conf = None;
        let mut operating_system_method = None;
        let mut operating_system_unsupported = None;
        let mut os = None;
        let mut patch_summary_total_cves = None;
        let mut policy_used = None;
        let mut rexec_login_used = None;
        let mut rlogin_login_used = None;
        let mut rsh_login_used = None;
        let mut smb_login_used = None;
        let mut ssh_login_used = None;
        let mut telnet_login_used = None;
        let mut sinfp_ml_prediction = None;
        let mut sinfp_signature = None;
        let mut ssh_fingerprint = None;
        let mut system_type = None;
        let mut wmi_domain = None;

        let mut cpe = vec![];
        let mut traceroute = vec![];
        let mut mac_address = vec![];
        let mut netstat_listen = vec![];
        let mut netstat_established = vec![];
        let mut patch_summary_txt = vec![];
        let mut enumerated_ports = vec![];
        let mut patch_summary_cve_num = vec![];
        let mut patch_summary_cves = vec![];
        let mut ddi_dir_scanner_port_init = vec![];
        let mut ddi_dir_scanner_port_pass_start = vec![];
        let mut ddi_dir_scanner_port_duration = vec![];
        let mut ddi_dir_scanner_port_pass_timeout = vec![];

        let mut others: HashMap<_, Vec<_>> = HashMap::new();

        for child in node.children() {
            if child.tag_name().name() != "tag" {
                assert_empty_text(child)?;
                continue;
            }

            let (name, Some(value)) = get_tag_name_value(child)? else {
                continue;
            };

            match name {
                "host-ip" => parse_value(&mut host_ip, "host-ip", value)?,
                "Credentialed_Scan" => {
                    parse_value(&mut credentialed_scan, "Credentialed_Scan", value)?;
                }
                "DDI_Dir_Scanner_Global_Duration" => parse_value(
                    &mut ddi_dir_scanner_global_duration,
                    "DDI_Dir_Scanner_Global_Duration",
                    value,
                )?,
                "operating-system-conf" => {
                    parse_value(&mut operating_system_conf, "operating-system-conf", value)?;
                }
                "operating-system-unsupported" => parse_value(
                    &mut operating_system_unsupported,
                    "operating-system-unsupported",
                    value,
                )?,
                "patch-summary-total-cves" => parse_value(
                    &mut patch_summary_total_cves,
                    "patch-summary-total-cves",
                    value,
                )?,

                "HOST_START" => str_value(&mut host_start, "HOST_START", value)?,
                "HOST_END" => str_value(&mut host_end, "HOST_END", value)?,
                "bios-uuid" => str_value(&mut bios_uuid, "bios-uuid", value)?,
                "hostname" => str_value(&mut hostname, "hostname", value)?,
                "local-checks-proto" => {
                    str_value(&mut local_checks_proto, "local-checks-proto", value)?;
                }
                "operating-system" => str_value(&mut operating_system, "operating-system", value)?,
                "operating-system-method" => str_value(
                    &mut operating_system_method,
                    "operating-system-method",
                    value,
                )?,
                "os" => str_value(&mut os, "os", value)?,
                "rexec-login-used" => str_value(&mut rexec_login_used, "rexec-login-used", value)?,
                "rlogin-login-used" => {
                    str_value(&mut rlogin_login_used, "rlogin-login-used", value)?;
                }
                "rsh-login-used" => str_value(&mut rsh_login_used, "rsh-login-used", value)?,
                "smb-login-used" => str_value(&mut smb_login_used, "smb-login-used", value)?,
                "ssh-login-used" => str_value(&mut ssh_login_used, "ssh-login-used", value)?,
                "telnet-login-used" => {
                    str_value(&mut telnet_login_used, "telnet-login-used", value)?;
                }
                "sinfp-signature" => str_value(&mut sinfp_signature, "sinfp-signature", value)?,
                "system-type" => str_value(&mut system_type, "system-type", value)?,
                "wmi-domain" => str_value(&mut wmi_domain, "wmi-domain", value)?,

                "Apache_sites" => cow_value(&mut apache_sites, "Apache_sites", value)?,
                "host-ad-config" => cow_value(&mut host_ad_config, "host-ad-config", value)?,
                "host-fqdn" => cow_value(&mut host_fqdn, "host-fqdn", value)?,
                "host-fqdns" => cow_value(&mut host_fqdns, "host-fqdns", value)?,
                "host-rdns" => cow_value(&mut host_rdns, "host-rdns", value)?,
                "IIS_sites" => cow_value(&mut iis_sites, "IIS_sites", value)?,
                "netbios-name" => cow_value(&mut netbios_name, "netbios-name", value)?,
                "policy-used" => cow_value(&mut policy_used, "policy-used", value)?,
                "sinfp-ml-prediction" => {
                    cow_value(&mut sinfp_ml_prediction, "sinfp-ml-prediction", value)?;
                }
                "ssh-fingerprint" => cow_value(&mut ssh_fingerprint, "ssh-fingerprint", value)?,

                "HOST_START_TIMESTAMP" => {
                    if host_start_timestamp.is_some() {
                        return Err(FormatError::RepeatedTag("HOST_START_TIMESTAMP"));
                    }
                    host_start_timestamp = Some(Timestamp::from_second(value.parse::<i64>()?)?);
                }
                "HOST_END_TIMESTAMP" => {
                    if host_end_timestamp.is_some() {
                        return Err(FormatError::RepeatedTag("HOST_END_TIMESTAMP"));
                    }
                    host_end_timestamp = Some(Timestamp::from_second(value.parse::<i64>()?)?);
                }
                "DDI_Dir_Scanner_Global_Init" => {
                    if ddi_dir_scanner_global_init.is_some() {
                        return Err(FormatError::RepeatedTag("DDI_Dir_Scanner_Global_Init"));
                    }
                    ddi_dir_scanner_global_init =
                        Some(Timestamp::from_second(value.parse::<i64>()?)?);
                }
                "LastAuthenticatedResults" => {
                    if last_authenticated_results.is_some() {
                        return Err(FormatError::RepeatedTag("LastAuthenticatedResults"));
                    }
                    last_authenticated_results =
                        Some(Timestamp::from_second(value.parse::<i64>()?)?);
                }
                "LastUnauthenticatedResults" => {
                    if last_unauthenticated_results.is_some() {
                        return Err(FormatError::RepeatedTag("LastUnauthenticatedResults"));
                    }
                    last_unauthenticated_results =
                        Some(Timestamp::from_second(value.parse::<i64>()?)?);
                }

                "dead_host" => {
                    if dead_host.is_some() {
                        return Err(FormatError::RepeatedTag("dead_host"));
                    }
                    dead_host = Some(value.as_str() == "1");
                }
                "ignore_printer" => {
                    if ignore_printer.is_some() {
                        return Err(FormatError::RepeatedTag("ignore_printer"));
                    }
                    ignore_printer = Some(value.as_str() == "1");
                }

                "mac-address" => {
                    mac_address.reserve_exact((value.len() + 1) / 18);
                    for mac in value.split('\n') {
                        mac_address.push(mac.parse()?);
                    }
                }

                "cpe" => cpe.push((0, value.to_cow())),

                other_name => {
                    if let Some(cpe_n) = other_name.strip_prefix("cpe-") {
                        cpe.push((cpe_n.parse::<u16>()?, value.to_cow()));
                    } else if let Some(port_and_suffix) =
                        other_name.strip_prefix("DDI_Dir_Scanner_Port_")
                        && let Some((port, suffix)) = port_and_suffix.split_once('_')
                    {
                        let port = port.parse()?;
                        match suffix {
                            "Duration" => {
                                ddi_dir_scanner_port_duration.push((port, value.parse()?));
                            }
                            "Init" => ddi_dir_scanner_port_init
                                .push((port, Timestamp::from_second(value.parse::<i64>()?)?)),
                            "Pass_Start" => {
                                ddi_dir_scanner_port_pass_start
                                    .push((port, Timestamp::from_second(value.parse::<i64>()?)?));
                            }
                            "Pass_Timeout" => {
                                ddi_dir_scanner_port_pass_timeout
                                    .push((port, Timestamp::from_second(value.parse::<i64>()?)?));
                            }
                            _ => {
                                return Err(FormatError::UnexpectedText(other_name.into()));
                            }
                        }
                    } else if let Some(port_and_protocol) =
                        other_name.strip_prefix("enumerated-ports-")
                        && let Some((port, protocol)) = port_and_protocol.split_once('-')
                    {
                        enumerated_ports.push((port.parse()?, protocol.parse()?, value.to_str()?));
                    } else if let Some(hex_str) = other_name.strip_prefix("patch-summary-cve-num-")
                    {
                        patch_summary_cve_num.push((hex_str, value.parse()?));
                    } else if let Some(hex_str) = other_name.strip_prefix("patch-summary-cves-") {
                        patch_summary_cves.push((hex_str, value.to_str()?.split(", ").collect()));
                    } else if let Some(hex_str) = other_name.strip_prefix("patch-summary-txt-") {
                        patch_summary_txt.push((hex_str, value.to_cow()));
                    } else if let Some(hop_num) = other_name.strip_prefix("traceroute-hop-") {
                        traceroute.push((hop_num.parse::<u8>()?, value.parse().ok()));
                    } else if let Some(netstat_info) = other_name.strip_prefix("netstat-")
                        && let Some((mode, rest)) = netstat_info.split_once('-')
                        && let Some((protocol, num)) = rest.split_once('-')
                    {
                        let num = num.parse()?;
                        let value = value.to_str()?;
                        match mode {
                            "listen" => netstat_listen.push((protocol, num, value)),
                            "established" => netstat_established.push((protocol, num, value)),
                            _ => {
                                return Err(FormatError::UnexpectedText(other_name.into()));
                            }
                        }
                    } else {
                        others.entry(other_name).or_default().push(value.to_cow());
                    }
                }
            }
        }

        cpe.sort_unstable();
        traceroute.sort_unstable();
        netstat_listen.sort_unstable();
        netstat_established.sort_unstable();

        let cpe = cpe.into_iter().map(|(_, cpe)| cpe).collect();
        let traceroute = traceroute.into_iter().map(|(_, ip)| ip).collect();

        Ok(Self {
            host_ip: host_ip.ok_or(FormatError::MissingTag("host-ip"))?,
            host_start: host_start.ok_or(FormatError::MissingTag("HOST_START"))?,
            host_start_timestamp: host_start_timestamp
                .ok_or(FormatError::MissingTag("HOST_START_TIMESTAMP"))?,
            host_end,
            host_end_timestamp,
            apache_sites,
            bios_uuid,
            credentialed_scan,
            ddi_dir_scanner_global_duration,
            ddi_dir_scanner_global_init,
            dead_host,
            host_ad_config,
            host_fqdn,
            host_fqdns,
            host_rdns,
            hostname,
            ignore_printer,
            iis_sites,
            last_authenticated_results,
            last_unauthenticated_results,
            local_checks_proto,
            mac_address,
            netbios_name,
            operating_system,
            operating_system_conf,
            operating_system_method,
            operating_system_unsupported,
            os,
            patch_summary_total_cves,
            policy_used,
            rexec_login_used,
            rlogin_login_used,
            rsh_login_used,
            smb_login_used,
            ssh_login_used,
            telnet_login_used,
            sinfp_ml_prediction,
            sinfp_signature,
            ssh_fingerprint,
            system_type,
            wmi_domain,
            others,
            cpe,
            traceroute,
            netstat_listen,
            netstat_established,
            patch_summary_txt,
            enumerated_ports,
            patch_summary_cve_num,
            patch_summary_cves,
            ddi_dir_scanner_port_init,
            ddi_dir_scanner_port_pass_start,
            ddi_dir_scanner_port_duration,
            ddi_dir_scanner_port_pass_timeout,
        })
    }
}

fn parse_value<T>(
    output: &mut Option<T>,
    tag_name: &'static str,
    value: &StringStorage,
) -> Result<(), FormatError>
where
    T: std::str::FromStr,
    FormatError: From<T::Err>,
{
    if output.is_some() {
        return Err(FormatError::RepeatedTag(tag_name));
    }
    *output = Some(value.parse()?);

    Ok(())
}

fn str_value<'input>(
    output: &mut Option<&'input str>,
    tag_name: &'static str,
    value: &StringStorage<'input>,
) -> Result<(), FormatError> {
    if output.is_some() {
        return Err(FormatError::RepeatedTag(tag_name));
    }
    *output = Some(value.to_str()?);

    Ok(())
}

fn cow_value<'input>(
    output: &mut Option<Cow<'input, str>>,
    tag_name: &'static str,
    value: &StringStorage<'input>,
) -> Result<(), FormatError> {
    if output.is_some() {
        return Err(FormatError::RepeatedTag(tag_name));
    }
    *output = Some(value.to_cow());

    Ok(())
}

fn get_tag_name_value<'input, 'a>(
    child: Node<'a, 'input>,
) -> Result<(&'input str, Option<&'a StringStorage<'input>>), FormatError> {
    let name = child
        .attributes()
        .find(|a| a.name() == "name")
        .ok_or(FormatError::MissingAttribute("name"))?
        .value_storage()
        .to_str()?;

    let value = child.text_storage();

    Ok((name, value))
}
