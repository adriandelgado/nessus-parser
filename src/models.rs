use hard_xml::XmlRead;
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::Serialize;
use std::{borrow::Cow, net::IpAddr};

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "NessusClientData_v2")]
pub struct NessusClientDataV2<'a> {
    #[xml(child = "Policy")]
    policy: Policy<'a>,
    #[xml(child = "Report")]
    report: Report<'a>,
}

impl<'a> NessusClientDataV2<'a> {
    pub fn remove_plugin_set(&mut self) {
        let vec = &mut self.policy.preferences.server_preferences.preference;

        let pos = vec.par_iter().position_any(|p| p.name == "plugin_set");

        if let Some(pos) = pos {
            vec.swap_remove(pos);
        }
    }

    #[must_use]
    pub fn report_host(&self) -> &Vec<ReportHost> {
        &self.report.report_host
    }

    #[must_use]
    pub fn relevant_preferences(&self) -> Vec<(&'static str, &str)> {
        self.policy
            .preferences
            .server_preferences
            .preference
            .par_iter()
            .filter_map(|p| match p.name.as_ref() {
                "TARGET" => Some(("Target", p.value.as_ref())),
                "whoami" => Some(("whoami", p.value.as_ref())),
                _ => None,
            })
            .collect()
    }
}

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "Policy")]
struct Policy<'a> {
    #[xml(child = "Preferences")]
    preferences: Preferences<'a>,
    #[xml(flatten_text = "policyName")]
    policy_name: Cow<'a, str>,
}

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "Preferences")]
struct Preferences<'a> {
    #[xml(child = "ServerPreferences")]
    server_preferences: ServerPreferences<'a>,
}

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "ServerPreferences")]
struct ServerPreferences<'a> {
    #[xml(child = "preference")]
    preference: Vec<Preference<'a>>,
}

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "preference")]
struct Preference<'a> {
    #[xml(flatten_text = "name")]
    name: Cow<'a, str>,
    #[xml(flatten_text = "value")]
    value: Cow<'a, str>,
}

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "Report")]
struct Report<'a> {
    #[xml(attr = "name")]
    name: Cow<'a, str>,
    #[xml(child = "ReportHost")]
    report_host: Vec<ReportHost<'a>>,
}

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "ReportHost")]
pub struct ReportHost<'a> {
    #[xml(attr = "name")]
    name: IpAddr,
    // #[xml(child = "HostProperties")]
    // host_properties: HostProperties<'a>,
    #[xml(child = "ReportItem")]
    report_item: Vec<ReportItem<'a>>,
}

impl<'a> ReportHost<'a> {
    #[must_use]
    pub fn name(&self) -> IpAddr {
        self.name
    }

    #[must_use]
    pub fn report_item(&self) -> &Vec<ReportItem> {
        &self.report_item
    }
}

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "ReportItem")]
pub struct ReportItem<'a> {
    #[xml(attr = "port")]
    port: Cow<'a, str>,
    #[xml(attr = "svc_name")]
    svc_name: Cow<'a, str>,
    #[xml(attr = "protocol")]
    protocol: Cow<'a, str>,
    #[xml(attr = "severity")]
    severity: Cow<'a, str>,
    #[xml(attr = "pluginID")]
    plugin_id: Cow<'a, str>,
    #[xml(attr = "pluginName")]
    plugin_name_attr: Cow<'a, str>,
    #[xml(attr = "pluginFamily")]
    plugin_family: Cow<'a, str>,
    //
    #[xml(flatten_text = "description")]
    description: Cow<'a, str>,
    #[xml(flatten_text = "fname")]
    fname: Cow<'a, str>,
    #[xml(flatten_text = "plugin_modification_date")]
    plugin_modification_date: Cow<'a, str>,
    #[xml(flatten_text = "plugin_name")]
    plugin_name: Cow<'a, str>,
    #[xml(flatten_text = "plugin_publication_date")]
    plugin_publication_date: Cow<'a, str>,
    #[xml(flatten_text = "plugin_type")]
    plugin_type: Cow<'a, str>,
    #[xml(flatten_text = "risk_factor")]
    risk_factor: Cow<'a, str>,
    #[xml(flatten_text = "script_version")]
    script_version: Cow<'a, str>,
    #[xml(flatten_text = "solution")]
    solution: Cow<'a, str>,
    #[xml(flatten_text = "synopsis")]
    synopsis: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "iavb")]
    iavb: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "xref")]
    xref: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "plugin_output")]
    plugin_output: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "agent")]
    agent: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "always_run")]
    always_run: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "thorough_tests")]
    thorough_tests: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "see_also")]
    see_also: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "asset_inventory")]
    asset_inventory: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "os_identification")]
    os_identification: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "iavt")]
    iavt: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss3_base_score")]
    cvss3_base_score: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss3_vector")]
    cvss3_vector: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss_base_score")]
    cvss_base_score: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss_score_rationale")]
    cvss_score_rationale: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss_score_source")]
    cvss_score_source: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss_vector")]
    cvss_vector: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "age_of_vuln")]
    age_of_vuln: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cve")]
    cve: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvssV3_impactScore")]
    cvss_v3_impact_score: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "exploit_code_maturity")]
    exploit_code_maturity: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "in_the_news")]
    in_the_news: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "product_coverage")]
    product_coverage: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "threat_intensity_last_28")]
    threat_intensity_last_28: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "threat_recency")]
    threat_recency: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "threat_sources_last_28")]
    threat_sources_last_28: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "vpr_score")]
    vpr_score: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "vuln_publication_date")]
    vuln_publication_date: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cpe")]
    cpe: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "hardware_inventory")]
    hardware_inventory: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "attachment")]
    attachment: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss3_temporal_score")]
    cvss3_temporal_score: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss3_temporal_vector")]
    cvss3_temporal_vector: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss_temporal_score")]
    cvss_temporal_score: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss_temporal_vector")]
    cvss_temporal_vector: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "exploit_available")]
    exploit_available: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "exploitability_ease")]
    exploitability_ease: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cwe")]
    cwe: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "bid")]
    bid: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cert")]
    cert: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "asset_inventory_category")]
    asset_inventory_category: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "exploited_by_nessus")]
    exploited_by_nessus: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cea-id")]
    cea_id: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "iava")]
    iava: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "patch_publication_date")]
    patch_publication_date: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "stig_severity")]
    stig_severity: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cisa-known-exploited")]
    cisa_known_exploited: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "unsupported_by_vendor")]
    unsupported_by_vendor: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "exploited_by_malware")]
    exploited_by_malware: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "canvas_package")]
    canvas_package: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "exploit_framework_canvas")]
    exploit_framework_canvas: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "exploit_framework_core")]
    exploit_framework_core: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "exploit_framework_metasploit")]
    exploit_framework_metasploit: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "metasploit_name")]
    metasploit_name: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "msft")]
    msft: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "mskb")]
    mskb: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "edb-id")]
    edb_id: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "d2_elliot_name")]
    d2_elliot_name: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "exploit_framework_d2_elliot")]
    exploit_framework_d2_elliot: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "secunia")]
    secunia: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "potential_vulnerability")]
    potential_vulnerability: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "cvss3_score_source")]
    cvss3_score_source: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[xml(flatten_text = "icsa")]
    icsa: Option<Cow<'a, str>>,
}

impl<'a> ReportItem<'a> {
    #[must_use]
    pub fn fname(&self) -> &str {
        self.fname.as_ref()
    }

    #[must_use]
    pub fn port(&self) -> &str {
        self.port.as_ref()
    }
}

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "HostProperties")]
struct HostProperties<'a> {
    #[xml(child = "tag")]
    tag: Vec<Tag<'a>>,
}

#[derive(XmlRead, Debug, Serialize)]
#[xml(tag = "tag")]
struct Tag<'a> {
    #[xml(attr = "name")]
    name: Cow<'a, str>,
    #[xml(text)]
    value: Cow<'a, str>,
}
