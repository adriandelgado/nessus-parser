use color_eyre::eyre;
use hard_xml::XmlRead;
use macaddr::MacAddr;
use std::{borrow::Cow, net::IpAddr, str::FromStr};
use tabled::Tabled;

#[derive(XmlRead)]
#[xml(tag = "NessusClientData_v2")]
pub struct NessusClientDataV2<'a> {
    #[xml(child = "Policy")]
    policy: Policy<'a>,
    #[xml(child = "Report")]
    pub report: Report<'a>,
}

impl<'a> NessusClientDataV2<'a> {
    pub fn remove_plugin_set(&mut self) {
        self.policy
            .preferences
            .server_preferences
            .remove_plugin_set();
    }

    #[must_use]
    pub fn preferences(&self) -> &Vec<Preference> {
        &self.policy.preferences.server_preferences.preference
    }
}

#[derive(XmlRead)]
#[xml(tag = "Policy")]
struct Policy<'a> {
    #[xml(child = "Preferences")]
    preferences: Preferences<'a>,
    // #[xml(flatten_text = "policyName")]
    // policy_name: Cow<'a, str>,
}

#[derive(XmlRead)]
#[xml(tag = "Preferences")]
struct Preferences<'a> {
    #[xml(child = "ServerPreferences")]
    server_preferences: ServerPreferences<'a>,
}

#[derive(XmlRead)]
#[xml(tag = "ServerPreferences")]
struct ServerPreferences<'a> {
    #[xml(child = "preference")]
    preference: Vec<Preference<'a>>,
}

impl ServerPreferences<'_> {
    pub fn remove_plugin_set(&mut self) {
        let pos = self.preference.iter().position(|p| p.name == "plugin_set");

        if let Some(pos) = pos {
            self.preference.swap_remove(pos);
        }
    }
}

#[derive(XmlRead)]
#[xml(tag = "preference")]
pub struct Preference<'a> {
    #[xml(flatten_text = "name")]
    name: Cow<'a, str>,
    #[xml(flatten_text = "value")]
    value: Cow<'a, str>,
}

impl Preference<'_> {
    #[must_use]
    pub fn as_relevant_preference(&self) -> Option<(&'static str, &str)> {
        match self.name.as_ref() {
            "TARGET" => Some(("Target", self.value.as_ref())),
            "whoami" => Some(("whoami", self.value.as_ref())),
            _ => None,
        }
    }
}

#[derive(XmlRead)]
#[xml(tag = "Report")]
pub struct Report<'a> {
    #[xml(attr = "name")]
    pub name: Cow<'a, str>,
    #[xml(child = "ReportHost")]
    pub report_hosts: Vec<ReportHost<'a>>,
}

#[derive(XmlRead)]
#[xml(tag = "ReportHost")]
pub struct ReportHost<'a> {
    #[xml(attr = "name")]
    pub ip_addr: IpAddr,
    #[xml(child = "HostProperties")]
    host_properties: HostProperties<'a>,
    #[xml(child = "ReportItem")]
    pub report_items: Vec<ReportItem<'a>>,
}

impl<'a> ReportHost<'a> {
    #[must_use]
    pub fn summary(&self) -> Summary {
        let ((macs, os, traceroute), vulns) = rayon::join(
            || {
                let mut macs = None;
                let mut os = None;
                let mut operating_system = None;
                let mut traceroute = Vec::new();
                for tag in &self.host_properties.tags {
                    match tag.name.as_ref() {
                        "mac-address" => {
                            macs = Some(
                                tag.value
                                    .as_ref()
                                    .split('\n')
                                    .map(|value| {
                                        MacAddr::from_str(value)
                                            .expect("`mac-address` field didn't have a MAC address")
                                    })
                                    .collect(),
                            );
                        }
                        "operating-system" => {
                            operating_system = Some(tag.value.as_ref());
                        }
                        "os" => {
                            os = Some(tag.value.as_ref());
                        }
                        name if name.starts_with("traceroute-hop-") => {
                            let value = tag.value.as_ref();
                            let ip = (value != "?").then(|| {
                                IpAddr::from_str(value)
                                    .expect("`traceroute-hop-*` field didn't have an IP address")
                            });

                            traceroute.push(ip);
                        }
                        _ => {}
                    }
                }

                (macs, operating_system.or(os), traceroute)
            },
            || {
                let mut vulns: Vec<_> = self
                    .report_items
                    .iter()
                    .filter(|report| report.risk_factor != RiskFactor::None)
                    .map(Vulnerability::from)
                    .collect();

                vulns.sort_by_key(|v| v.name);

                // vulns.sort_by_key(|v| v.severity);

                vulns.sort_by(|a, b| {
                    match b
                        .score
                        .unwrap_or_default()
                        .total_cmp(&a.score.unwrap_or_default())
                    {
                        std::cmp::Ordering::Equal => {}
                        ord => return ord,
                    }

                    b.severity.cmp(&a.severity)
                });

                vulns
            },
        );

        Summary {
            macs,
            os,
            vulns,
            traceroute,
        }
    }
}

pub struct Summary<'a> {
    macs: Option<Vec<MacAddr>>,
    os: Option<&'a str>,
    pub vulns: Vec<Vulnerability<'a>>,
    traceroute: Vec<Option<IpAddr>>,
}

pub struct Vulnerability<'a> {
    score: Option<f64>,
    severity: RiskFactor,
    name: &'a str,
    port: u16,
    exploit_available: Option<bool>,
}

impl Tabled for Vulnerability<'_> {
    const LENGTH: usize = 5;

    fn fields(&self) -> Vec<Cow<str>> {
        {
            vec![
                self.score
                    .map_or(Cow::Borrowed("--"), |s| s.to_string().into()),
                Cow::Borrowed(self.severity.as_str()),
                Cow::Borrowed(self.name),
                Cow::Owned(self.port.to_string()),
                Cow::Borrowed(if self.exploit_available == Some(true) {
                    "■"
                } else {
                    ""
                }),
            ]
        }
    }

    fn headers() -> Vec<Cow<'static, str>> {
        {
            vec![
                Cow::Borrowed("Score"),
                Cow::Borrowed("Severity"),
                Cow::Borrowed("Name"),
                Cow::Borrowed("Port"),
                Cow::Borrowed("Exploit Available"),
            ]
        }
    }
}

impl<'a> From<&'a ReportItem<'_>> for Vulnerability<'a> {
    fn from(value: &'a ReportItem) -> Vulnerability<'a> {
        Vulnerability {
            port: value.port,
            name: &value.plugin_name_attr,
            severity: value.risk_factor,
            score: value.cvss3_base_score.or(value.cvss_base_score),
            exploit_available: value.exploit_available,
        }
    }
}

#[derive(XmlRead)]
#[xml(tag = "ReportItem")]
pub struct ReportItem<'a> {
    #[xml(attr = "port")]
    pub port: u16,
    // #[xml(attr = "svc_name")]
    // svc_name: Cow<'a, str>,
    // #[xml(attr = "protocol")]
    // protocol: Cow<'a, str>,
    // #[xml(attr = "severity")]
    // severity: Cow<'a, str>,
    // #[xml(attr = "pluginID")]
    // plugin_id: Cow<'a, str>,
    #[xml(attr = "pluginName")]
    plugin_name_attr: Cow<'a, str>,
    // #[xml(attr = "pluginFamily")]
    // plugin_family: Cow<'a, str>,
    //
    // #[xml(flatten_text = "description")]
    // description: Cow<'a, str>,
    // #[xml(flatten_text = "fname")]
    // fname: Cow<'a, str>,
    // #[xml(flatten_text = "plugin_modification_date")]
    // plugin_modification_date: Cow<'a, str>,
    // #[xml(flatten_text = "plugin_name")]
    // plugin_name: Cow<'a, str>,
    // #[xml(flatten_text = "plugin_publication_date")]
    // plugin_publication_date: Cow<'a, str>,
    // #[xml(flatten_text = "plugin_type")]
    // plugin_type: Cow<'a, str>,
    #[xml(flatten_text = "risk_factor")]
    risk_factor: RiskFactor,
    // #[xml(flatten_text = "script_version")]
    // script_version: Cow<'a, str>,
    // #[xml(flatten_text = "solution")]
    // solution: Cow<'a, str>,
    // #[xml(flatten_text = "synopsis")]
    // synopsis: Cow<'a, str>,
    // #[xml(flatten_text = "iavb")]
    // iavb: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "xref")]
    // xref: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "plugin_output")]
    // plugin_output: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "agent")]
    // agent: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "always_run")]
    // always_run: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "thorough_tests")]
    // thorough_tests: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "see_also")]
    // see_also: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "asset_inventory")]
    // asset_inventory: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "os_identification")]
    // os_identification: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "iavt")]
    // iavt: Option<Cow<'a, str>>,
    #[xml(flatten_text = "cvss3_base_score")]
    cvss3_base_score: Option<f64>,
    // #[xml(flatten_text = "cvss3_vector")]
    // cvss3_vector: Option<Cow<'a, str>>,
    #[xml(flatten_text = "cvss_base_score")]
    cvss_base_score: Option<f64>,
    // #[xml(flatten_text = "cvss_score_rationale")]
    // cvss_score_rationale: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cvss_score_source")]
    // cvss_score_source: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cvss_vector")]
    // cvss_vector: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "age_of_vuln")]
    // age_of_vuln: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cve")]
    // cve: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cvssV3_impactScore")]
    // cvss_v3_impact_score: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "exploit_code_maturity")]
    // exploit_code_maturity: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "in_the_news")]
    // in_the_news: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "product_coverage")]
    // product_coverage: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "threat_intensity_last_28")]
    // threat_intensity_last_28: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "threat_recency")]
    // threat_recency: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "threat_sources_last_28")]
    // threat_sources_last_28: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "vpr_score")]
    // vpr_score: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "vuln_publication_date")]
    // vuln_publication_date: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cpe")]
    // cpe: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "hardware_inventory")]
    // hardware_inventory: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "attachment")]
    // attachment: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cvss3_temporal_score")]
    // cvss3_temporal_score: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cvss3_temporal_vector")]
    // cvss3_temporal_vector: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cvss_temporal_score")]
    // cvss_temporal_score: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cvss_temporal_vector")]
    // cvss_temporal_vector: Option<Cow<'a, str>>,
    #[xml(flatten_text = "exploit_available")]
    pub exploit_available: Option<bool>,
    // #[xml(flatten_text = "exploitability_ease")]
    // exploitability_ease: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cwe")]
    // cwe: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "bid")]
    // bid: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cert")]
    // cert: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "asset_inventory_category")]
    // asset_inventory_category: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "exploited_by_nessus")]
    // exploited_by_nessus: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cea-id")]
    // cea_id: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "iava")]
    // iava: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "patch_publication_date")]
    // patch_publication_date: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "stig_severity")]
    // stig_severity: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cisa-known-exploited")]
    // cisa_known_exploited: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "unsupported_by_vendor")]
    // unsupported_by_vendor: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "exploited_by_malware")]
    // exploited_by_malware: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "canvas_package")]
    // canvas_package: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "exploit_framework_canvas")]
    // exploit_framework_canvas: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "exploit_framework_core")]
    // exploit_framework_core: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "exploit_framework_metasploit")]
    // exploit_framework_metasploit: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "metasploit_name")]
    // metasploit_name: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "msft")]
    // msft: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "mskb")]
    // mskb: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "edb-id")]
    // edb_id: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "d2_elliot_name")]
    // d2_elliot_name: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "exploit_framework_d2_elliot")]
    // exploit_framework_d2_elliot: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "secunia")]
    // secunia: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "potential_vulnerability")]
    // potential_vulnerability: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "cvss3_score_source")]
    // cvss3_score_source: Option<Cow<'a, str>>,
    // #[xml(flatten_text = "icsa")]
    // icsa: Option<Cow<'a, str>>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RiskFactor {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl FromStr for RiskFactor {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "None" => Ok(Self::None),
            "Low" => Ok(Self::Low),
            "Medium" => Ok(Self::Medium),
            "High" => Ok(Self::High),
            "Critical" => Ok(Self::Critical),
            _ => Err(eyre::eyre!("`RiskFactor` not recognized")),
        }
    }
}

impl RiskFactor {
    fn as_str(self) -> &'static str {
        match self {
            RiskFactor::None => "None",
            RiskFactor::Low => "Low",
            RiskFactor::Medium => "Medium",
            RiskFactor::High => "High",
            RiskFactor::Critical => "Critical",
        }
    }
}

#[derive(XmlRead)]
#[xml(tag = "HostProperties")]
struct HostProperties<'a> {
    #[xml(child = "tag")]
    tags: Vec<Tag<'a>>,
}

#[derive(XmlRead)]
#[xml(tag = "tag")]
struct Tag<'a> {
    #[xml(attr = "name")]
    name: Cow<'a, str>,
    #[xml(text)]
    value: Cow<'a, str>,
}
