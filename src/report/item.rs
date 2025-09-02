use std::{borrow::Cow, collections::HashMap, str::FromStr};

use jiff::civil::Date;
use roxmltree::Node;

use crate::{StringStorageExt, error::FormatError};

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

impl FromStr for Protocol {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            other => Err(FormatError::UnexpectedProtocol(other.into())),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PluginType {
    Summary,
    Remote,
    Combined,
    Local,
}

impl FromStr for PluginType {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "summary" => Ok(Self::Summary),
            "remote" => Ok(Self::Remote),
            "combined" => Ok(Self::Combined),
            "local" => Ok(Self::Local),
            other => Err(FormatError::UnexpectedPluginType(other.into())),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Level {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Level {
    fn from_int(int: &str) -> Result<Self, FormatError> {
        match int {
            "0" => Ok(Self::None),
            "1" => Ok(Self::Low),
            "2" => Ok(Self::Medium),
            "3" => Ok(Self::High),
            "4" => Ok(Self::Critical),
            other => Err(FormatError::UnexpectedLevel(other.into())),
        }
    }

    fn from_text(s: &str) -> Result<Self, FormatError> {
        match s {
            "None" => Ok(Self::None),
            "Low" => Ok(Self::Low),
            "Medium" => Ok(Self::Medium),
            "High" => Ok(Self::High),
            "Critical" => Ok(Self::Critical),
            other => Err(FormatError::UnexpectedLevel(other.into())),
        }
    }
}

/// Represents a `<ReportItem>` element, which is a single finding or piece of
/// information reported by a Nessus plugin for a specific host and port.
#[derive(Debug)]
pub struct Item<'input> {
    /// The unique identifier of the Nessus plugin that generated this item.
    pub plugin_id: u32,
    /// The name of the plugin.
    pub plugin_name: Cow<'input, str>,
    /// The port number associated with this finding.
    pub port: u16,
    /// The protocol associated with the port (TCP, UDP, ICMP).
    pub protocol: Protocol,
    /// The service name discovered on the port (e.g., "www", "general").
    pub svc_name: &'input str,
    /// The severity level of the finding.
    pub severity: Level,
    /// The family that the plugin belongs to (e.g., "Windows", "CGI abuses").
    pub plugin_family: &'input str,
    /// The raw output from the plugin, which often contains detailed evidence.
    pub plugin_output: Option<Cow<'input, str>>,

    /// The suggested solution or remediation for the finding.
    pub solution: Cow<'input, str>,
    /// The version of the plugin script.
    // $Revision: 1.234 $ | 1.234
    pub script_version: &'input str,
    /// The risk factor associated with the finding (e.g., "High", "None").
    pub risk_factor: Level,
    /// The type of the plugin (e.g., remote, local).
    pub plugin_type: PluginType,
    /// The date when the plugin was first published.
    pub plugin_publication_date: jiff::civil::Date,
    /// The date when the plugin was last modified.
    pub plugin_modification_date: jiff::civil::Date,
    /// The filename of the plugin script (e.g., "example.nasl").
    pub fname: &'input str,
    /// A detailed description of the vulnerability or finding.
    pub description: Cow<'input, str>,
    /// A boolean indicating if a known exploit for the vulnerability exists.
    pub exploit_available: bool,
    /// A boolean indicating if the vulnerability was exploited by Nessus during the scan.
    pub exploited_by_nessus: bool,
    /// A description of how easy it is to exploit the vulnerability.
    // "Exploits are available" | "No known exploits are available" | "No exploit is required"
    pub exploitability_ease: Option<&'input str>,

    /// The agent type the plugin is applicable to ("all", "unix", "windows").
    pub agent: Option<&'input str>,

    /// The CVSSv2 vector string.
    pub cvss_vector: Option<&'input str>,
    /// The CVSSv2 temporal vector string.
    pub cvss_temporal_vector: Option<&'input str>,
    /// The CVSSv3 vector string.
    pub cvss3_vector: Option<&'input str>,
    /// The CVSSv3 temporal vector string.
    pub cvss3_temporal_vector: Option<&'input str>,
    /// The CVSSv4 vector string.
    pub cvss4_vector: Option<&'input str>,
    /// The CVSSv4 threat vector string.
    pub cvss4_threat_vector: Option<&'input str>,

    /// A map to hold any other elements from the ReportItem not explicitly
    /// parsed into other fields. The key is the XML tag name.
    pub others: HashMap<&'input str, Vec<Cow<'input, str>>>,
}

impl<'input> Item<'input> {
    #[expect(clippy::too_many_lines, clippy::similar_names)]
    pub(crate) fn from_xml_node(node: Node<'_, 'input>) -> Result<Self, FormatError> {
        let mut plugin_id = None;
        let mut plugin_name = None;
        let mut port = None;
        let mut protocol = None;
        let mut svc_name = None;
        let mut severity = None;
        let mut plugin_family = None;

        for attribute in node.attributes() {
            match attribute.name() {
                "pluginID" => {
                    if plugin_id.is_some() {
                        return Err(FormatError::RepeatedTag("pluginID"));
                    }
                    plugin_id = Some(attribute.value_storage().parse()?);
                }
                "pluginName" => {
                    if plugin_name.is_some() {
                        return Err(FormatError::RepeatedTag("pluginName"));
                    }
                    plugin_name = Some(attribute.value_storage().to_cow());
                }
                "port" => {
                    if port.is_some() {
                        return Err(FormatError::RepeatedTag("port"));
                    }
                    port = Some(attribute.value().parse()?);
                }
                "protocol" => {
                    if protocol.is_some() {
                        return Err(FormatError::RepeatedTag("protocol"));
                    }
                    protocol = Some(attribute.value_storage().parse()?);
                }
                "svc_name" => {
                    if svc_name.is_some() {
                        return Err(FormatError::RepeatedTag("svc_name"));
                    }
                    svc_name = Some(attribute.value_storage().to_str()?);
                }
                "severity" => {
                    if severity.is_some() {
                        return Err(FormatError::RepeatedTag("severity"));
                    }
                    severity = Some(Level::from_int(attribute.value())?);
                }
                "pluginFamily" => {
                    if plugin_family.is_some() {
                        return Err(FormatError::RepeatedTag("pluginFamily"));
                    }
                    plugin_family = Some(attribute.value_storage().to_str()?);
                }

                other => return Err(FormatError::UnexpectedXmlAttribute(other.into())),
            }
        }

        let mut plugin_output = None;

        let mut solution = None;
        let mut script_version = None;
        let mut risk_factor = None;
        let mut plugin_type = None;
        let mut plugin_publication_date = None;
        let mut plugin_modification_date = None;
        let mut fname = None;
        let mut description = None;

        let mut agent = None;
        let mut cvss_vector = None;
        let mut cvss3_vector = None;
        let mut cvss_temporal_vector = None;
        let mut cvss3_temporal_vector = None;
        let mut cvss4_vector = None;
        let mut cvss4_threat_vector = None;
        let mut exploitability_ease = None;
        let mut exploit_available = None;
        let mut exploited_by_nessus = None;

        let mut others: HashMap<_, Vec<_>> = HashMap::new();

        for child in node.children() {
            if child.is_text() {
                if let Some(text) = child.text()
                    && !text.trim().is_empty()
                {
                    return Err(FormatError::UnexpectedText(text.into()));
                }
                continue;
            }

            let name = child.tag_name().name();
            if let Some(value) = child.text_storage() {
                match name {
                    "plugin_output" => {
                        if plugin_output.is_some() {
                            return Err(FormatError::RepeatedTag("plugin_output"));
                        }
                        plugin_output = Some(value.to_cow());
                    }
                    "solution" => {
                        if solution.is_some() {
                            return Err(FormatError::RepeatedTag("solution"));
                        }
                        solution = Some(value.to_cow());
                    }
                    "description" => {
                        if description.is_some() {
                            return Err(FormatError::RepeatedTag("description"));
                        }
                        description = Some(value.to_cow());
                    }

                    "script_version" => {
                        if script_version.is_some() {
                            return Err(FormatError::RepeatedTag("script_version"));
                        }
                        script_version = Some(value.to_str()?);
                    }
                    "risk_factor" => {
                        if risk_factor.is_some() {
                            return Err(FormatError::RepeatedTag("risk_factor"));
                        }
                        risk_factor = Some(Level::from_text(value.as_str())?);
                    }
                    "plugin_type" => {
                        if plugin_type.is_some() {
                            return Err(FormatError::RepeatedTag("plugin_type"));
                        }
                        plugin_type = Some(value.parse()?);
                    }
                    "plugin_publication_date" => {
                        if plugin_publication_date.is_some() {
                            return Err(FormatError::RepeatedTag("plugin_publication_date"));
                        }
                        plugin_publication_date = Some(Date::strptime("%Y/%m/%d", value.as_str())?);
                    }
                    "plugin_modification_date" => {
                        if plugin_modification_date.is_some() {
                            return Err(FormatError::RepeatedTag("plugin_modification_date"));
                        }
                        plugin_modification_date =
                            Some(Date::strptime("%Y/%m/%d", value.as_str())?);
                    }
                    "fname" => {
                        if fname.is_some() {
                            return Err(FormatError::RepeatedTag("fname"));
                        }
                        fname = Some(value.to_str()?);
                    }

                    "agent" => {
                        if agent.is_some() {
                            return Err(FormatError::RepeatedTag("agent"));
                        }
                        agent = Some(value.to_str()?);
                    }
                    "cvss_vector" => {
                        if cvss_vector.is_some() {
                            return Err(FormatError::RepeatedTag("cvss_vector"));
                        }
                        cvss_vector = Some(value.to_str()?);
                    }
                    "cvss3_vector" => {
                        if cvss3_vector.is_some() {
                            return Err(FormatError::RepeatedTag("cvss3_vector"));
                        }
                        cvss3_vector = Some(value.to_str()?);
                    }
                    "cvss_temporal_vector" => {
                        if cvss_temporal_vector.is_some() {
                            return Err(FormatError::RepeatedTag("cvss_temporal_vector"));
                        }
                        cvss_temporal_vector = Some(value.to_str()?);
                    }
                    "cvss3_temporal_vector" => {
                        if cvss3_temporal_vector.is_some() {
                            return Err(FormatError::RepeatedTag("cvss3_temporal_vector"));
                        }
                        cvss3_temporal_vector = Some(value.to_str()?);
                    }
                    "cvss4_vector" => {
                        if cvss4_vector.is_some() {
                            return Err(FormatError::RepeatedTag("cvss4_vector"));
                        }
                        cvss4_vector = Some(value.to_str()?);
                    }
                    "cvss4_threat_vector" => {
                        if cvss4_threat_vector.is_some() {
                            return Err(FormatError::RepeatedTag("cvss4_threat_vector"));
                        }
                        cvss4_threat_vector = Some(value.to_str()?);
                    }
                    "exploitability_ease" => {
                        if exploitability_ease.is_some() {
                            return Err(FormatError::RepeatedTag("exploitability_ease"));
                        }
                        exploitability_ease = Some(value.to_str()?);
                    }
                    "exploit_available" => {
                        if exploit_available.is_some() {
                            return Err(FormatError::RepeatedTag("exploit_available"));
                        }
                        exploit_available = Some(value.as_str() == "true");
                    }
                    "exploited_by_nessus" => {
                        if exploited_by_nessus.is_some() {
                            return Err(FormatError::RepeatedTag("exploited_by_nessus"));
                        }
                        exploited_by_nessus = Some(value.as_str() == "true");
                    }

                    _ => others.entry(name).or_default().push(value.to_cow()),
                }
            }
        }

        Ok(Self {
            plugin_id: plugin_id.ok_or(FormatError::MissingAttribute("pluginID"))?,
            plugin_name: plugin_name.ok_or(FormatError::MissingAttribute("pluginName"))?,
            port: port.ok_or(FormatError::MissingAttribute("port"))?,
            protocol: protocol.ok_or(FormatError::MissingAttribute("protocol"))?,
            svc_name: svc_name.ok_or(FormatError::MissingAttribute("svc_name"))?,
            severity: severity.ok_or(FormatError::MissingAttribute("severity"))?,
            plugin_family: plugin_family.ok_or(FormatError::MissingAttribute("pluginFamily"))?,
            solution: solution.ok_or(FormatError::MissingTag("solution"))?,
            script_version: script_version.ok_or(FormatError::MissingTag("script_version"))?,
            risk_factor: risk_factor.ok_or(FormatError::MissingTag("risk_factor"))?,
            plugin_type: plugin_type.ok_or(FormatError::MissingTag("plugin_type"))?,
            plugin_publication_date: plugin_publication_date
                .ok_or(FormatError::MissingTag("plugin_publication_date"))?,
            plugin_modification_date: plugin_modification_date
                .ok_or(FormatError::MissingTag("plugin_modification_date"))?,
            fname: fname.ok_or(FormatError::MissingTag("fname"))?,
            description: description.ok_or(FormatError::MissingTag("description"))?,
            plugin_output,
            agent,
            cvss_vector,
            cvss3_vector,
            cvss_temporal_vector,
            cvss3_temporal_vector,
            cvss4_vector,
            cvss4_threat_vector,
            exploitability_ease,
            exploit_available: exploit_available == Some(true),
            exploited_by_nessus: exploited_by_nessus == Some(true),
            others,
        })
    }
}
