use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap},
};

use jiff::Timestamp;
use roxmltree::{Node, StringStorage};

use crate::{StringStorageExt, assert_empty_text, error::FormatError};

/// Represents the `<Policy>` element within a Nessus report.
///
/// This struct holds the complete configuration of the scan policy,
/// including its name, comments, and detailed preferences for server
/// behavior and plugin selection.
#[derive(Debug)]
pub struct Policy<'input> {
    /// The name of the policy (from the `<policyName>` tag).
    pub policy_name: Cow<'input, str>,
    /// Comments associated with the policy (from `<policyComments>`).
    pub policy_comments: Option<()>,
    /// Server and plugin preferences for the scan.
    pub preferences: Preferences<'input>,
    /// The selection of plugin families to be used in the scan.
    pub family_selection: (),
    /// The selection of individual plugins to be used in the scan.
    pub individual_plugin_selection: (),
}

impl<'input> Policy<'input> {
    pub(crate) fn from_xml_node(node: Node<'_, 'input>) -> Result<Self, FormatError> {
        let mut policy_name = None;
        let mut policy_comments = None;
        let mut preferences = None;
        let mut family_selection = None;
        let mut individual_plugin_selection = None;

        for child in node.children() {
            match child.tag_name().name() {
                "policyName" => {
                    if policy_name.is_some() {
                        return Err(FormatError::RepeatedTag("policyName"));
                    }
                    policy_name = child.text_storage().map(StringStorageExt::to_cow);
                }
                "policyComments" => {
                    if policy_comments.is_some() {
                        return Err(FormatError::RepeatedTag("policyComments"));
                    }
                    policy_comments = Some(());
                }
                "Preferences" => {
                    if preferences.is_some() {
                        return Err(FormatError::RepeatedTag("Preferences"));
                    }
                    preferences = Some(Preferences::from_xml_node(child)?);
                }
                "FamilySelection" => {
                    if family_selection.is_some() {
                        return Err(FormatError::RepeatedTag("FamilySelection"));
                    }
                    family_selection = Some(());
                }
                "IndividualPluginSelection" => {
                    if individual_plugin_selection.is_some() {
                        return Err(FormatError::RepeatedTag("IndividualPluginSelection"));
                    }
                    individual_plugin_selection = Some(());
                }
                _ => assert_empty_text(child)?,
            }
        }

        Ok(Self {
            policy_name: policy_name.ok_or(FormatError::MissingTag("policyName"))?,
            policy_comments,
            preferences: preferences.ok_or(FormatError::MissingTag("Preferences"))?,
            family_selection: family_selection.ok_or(FormatError::MissingTag("FamilySelection"))?,
            individual_plugin_selection: individual_plugin_selection
                .ok_or(FormatError::MissingTag("IndividualPluginSelection"))?,
        })
    }
}

/// Represents the `<Preferences>` element within a scan policy.
///
/// This acts as a container for both server-level and plugin-specific
/// preferences that define the scan's behavior.
#[derive(Debug)]
pub struct Preferences<'a> {
    /// A collection of server-wide settings for the scan.
    pub server_preferences: ServerPreferences<'a>,
    /// A collection of preferences specific to individual plugins.
    pub plugins_preferences: (),
}

impl<'input> Preferences<'input> {
    fn from_xml_node(node: Node<'_, 'input>) -> Result<Self, FormatError> {
        let mut server_preferences = None;
        let mut plugins_preferences = None;

        for child in node.children() {
            match child.tag_name().name() {
                "ServerPreferences" => {
                    if server_preferences.is_some() {
                        return Err(FormatError::RepeatedTag("ServerPreferences"));
                    }
                    server_preferences = Some(ServerPreferences::from_xml_node(child)?);
                }
                "PluginsPreferences" => {
                    if plugins_preferences.is_some() {
                        return Err(FormatError::RepeatedTag("PluginsPreferences"));
                    }
                    plugins_preferences = Some(());
                }
                _ => assert_empty_text(child)?,
            }
        }

        Ok(Self {
            server_preferences: server_preferences
                .ok_or(FormatError::MissingTag("ServerPreferences"))?,
            plugins_preferences: plugins_preferences
                .ok_or(FormatError::MissingTag("PluginsPreferences"))?,
        })
    }
}

/// Represents the `<ServerPreferences>` element, containing detailed
/// settings for the Nessus scanner's behavior during the scan.
#[derive(Debug)]
pub struct ServerPreferences<'input> {
    /// The user who launched the scan
    pub whoami: Cow<'input, str>,
    /// The user-defined name for the scan
    pub scan_name: Option<Cow<'input, str>>,
    /// The user-defined description for the scan
    pub scan_description: Cow<'input, str>,
    /// An alternative description field for the scan
    pub description: Option<Cow<'input, str>>,
    /// A list of targets for the scan (e.g., IP addresses, CIDR ranges).
    // 1.2.3.4,192.168.0.0/24, ...
    pub target: Vec<&'input str>,
    /// The port range to be scanned (e.g., "1-65535", "default", "all").
    pub port_range: &'input str,
    /// The timestamp when the scan was initiated.
    pub scan_start_timestamp_seconds: jiff::Timestamp,
    /// The timestamp when the scan was completed.
    pub scan_end_timestamp_seconds: Option<jiff::Timestamp>,
    /// The set of all plugin IDs that were active for the scan.
    // "...;28505;28497;28507;28502;28508;..." (gigantic list)
    pub plugin_set: BTreeSet<u32>,
    /// The name of the scan policy (e.g., "Advanced Scan").
    pub name: Cow<'input, str>,
    /// The discovery mode used for the scan (e.g., "portscan_common", "custom").
    // None | Some("portscan_all") | Some("host_enumeration")
    // | Some("custom") | Some("portscan_common") | Some("log4shell_thorough")
    // | Some("identity_quick") | Some("log4shell_dc_normal")
    pub discovery_mode: Option<&'input str>,
    /// A map to hold any other server preferences not explicitly parsed into
    /// other fields. The key is the preference name.
    pub others: HashMap<&'input str, Option<Cow<'input, str>>>,
}

impl<'input> ServerPreferences<'input> {
    #[allow(clippy::too_many_lines)]
    fn from_xml_node(node: Node<'_, 'input>) -> Result<Self, FormatError> {
        let mut whoami = None;
        let mut scan_name = None;
        let mut scan_description = None;
        let mut description = None;
        let mut target = None;
        let mut port_range = None;
        let mut scan_start_timestamp_seconds = None;
        let mut scan_end_timestamp_seconds = None;
        let mut plugin_set = None;
        let mut name_name = None;
        let mut discovery_mode = None;

        let mut others = HashMap::new();

        for child in node.children() {
            if child.tag_name().name() != "preference" {
                assert_empty_text(child)?;
                continue;
            }

            let (name, value) = get_preference_name_value(child)?;

            match name {
                "whoami" => {
                    if whoami.is_some() {
                        return Err(FormatError::RepeatedTag("whoami"));
                    }
                    whoami = Some(value.to_cow());
                }
                "scan_name" => {
                    if scan_name.is_some() {
                        return Err(FormatError::RepeatedTag("scan_name"));
                    }
                    scan_name = Some(value.to_cow());
                }
                "scan_description" => {
                    if scan_description.is_some() {
                        return Err(FormatError::RepeatedTag("scan_description"));
                    }
                    scan_description = Some(value.to_cow());
                }
                "description" => {
                    if description.is_some() {
                        return Err(FormatError::RepeatedTag("description"));
                    }
                    description = Some(value.to_cow());
                }
                "TARGET" => {
                    if target.is_some() {
                        return Err(FormatError::RepeatedTag("TARGET"));
                    }
                    target = Some(value.to_str()?.split(',').collect());
                }
                "port_range" => {
                    if port_range.is_some() {
                        return Err(FormatError::RepeatedTag("port_range"));
                    }
                    port_range = Some(value.to_str()?);
                }
                "scan_start_timestamp" => {
                    if scan_start_timestamp_seconds.is_some() {
                        return Err(FormatError::RepeatedTag("scan_start_timestamp"));
                    }
                    scan_start_timestamp_seconds =
                        Some(Timestamp::from_second(value.parse::<i64>()?)?);
                }
                "scan_end_timestamp" => {
                    if scan_end_timestamp_seconds.is_some() {
                        return Err(FormatError::RepeatedTag("scan_end_timestamp"));
                    }
                    scan_end_timestamp_seconds =
                        Some(Timestamp::from_second(value.parse::<i64>()?)?);
                }
                "plugin_set" => {
                    if plugin_set.is_some() {
                        return Err(FormatError::RepeatedTag("plugin_set"));
                    }
                    plugin_set = Some(
                        value
                            .trim_end_matches(';')
                            .split(';')
                            .map(str::parse)
                            .collect::<Result<_, _>>()?,
                    );
                }
                "name" => {
                    if name_name.is_some() {
                        return Err(FormatError::RepeatedTag("name"));
                    }
                    name_name = Some(value.to_cow());
                }
                "discovery_mode" => {
                    if discovery_mode.is_some() {
                        return Err(FormatError::RepeatedTag("discovery_mode"));
                    }
                    discovery_mode = Some(value.to_str()?);
                }
                other_name => {
                    others.insert(other_name, Some(value.to_cow()));
                }
            }
        }

        Ok(Self {
            whoami: whoami.ok_or(FormatError::MissingTag("whoami"))?,
            scan_name,
            scan_description: scan_description
                .ok_or(FormatError::MissingTag("scan_description"))?,
            description,
            target: target.ok_or(FormatError::MissingTag("TARGET"))?,
            port_range: port_range.ok_or(FormatError::MissingTag("port_range"))?,
            scan_start_timestamp_seconds: scan_start_timestamp_seconds
                .ok_or(FormatError::MissingTag("scan_start_timestamp"))?,
            scan_end_timestamp_seconds,
            plugin_set: plugin_set.ok_or(FormatError::MissingTag("plugin_set"))?,
            name: name_name.ok_or(FormatError::MissingTag("name"))?,
            discovery_mode,
            others,
        })
    }
}

fn get_preference_name_value<'input, 'a>(
    child: Node<'a, 'input>,
) -> Result<(&'input str, &'a StringStorage<'input>), FormatError> {
    let mut name = None;
    let mut value = None;

    for sub_node in child.children() {
        match sub_node.tag_name().name() {
            "name" => {
                if name.is_some() {
                    return Err(FormatError::RepeatedTag("name"));
                }
                name = sub_node
                    .text_storage()
                    .map(StringStorageExt::to_str)
                    .transpose()?;
            }
            "value" => {
                if value.is_some() {
                    return Err(FormatError::RepeatedTag("value"));
                }
                value = Some(
                    sub_node
                        .text_storage()
                        .unwrap_or(&StringStorage::Borrowed("")),
                );
            }
            _ => assert_empty_text(sub_node)?,
        }
    }

    let name = name.ok_or(FormatError::MissingTag("name"))?;
    let value = value.ok_or(FormatError::MissingTag("value"))?;

    Ok((name, value))
}
