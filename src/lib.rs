pub mod error;
pub mod ping;
pub mod policy;
pub mod report;

use std::{borrow::Cow, str::FromStr};

use roxmltree::{Document, StringStorage};

use crate::{error::FormatError, policy::Policy, report::Report};

// TODO: Add unit tests
// TODO: Add example usage

/// Represents the root of a Nessus v2 XML report, corresponding to the
/// `<NessusClientData_v2>` element.
///
/// This is the main entry point for a parsed `.nessus` file. It contains the
/// scan policy that was used and the report itself, which holds the results
/// of the scan.
#[derive(Debug)]
pub struct NessusClientDataV2<'input> {
    /// The policy configuration used for the Nessus scan.
    pub policy: Policy<'input>,
    /// The results of the scan, containing all discovered hosts and their
    /// vulnerabilities.
    pub report: Option<Report<'input>>,
}

impl<'input> NessusClientDataV2<'input> {
    /// Parses a string containing a `.nessus` (v2) XML report.
    ///
    /// This function is the main entry point for the parser. It takes the entire
    /// XML content of a `.nessus` file as a string slice and attempts to parse
    /// it into a structured `NessusClientDataV2` object.
    ///
    /// # Errors
    ///
    /// Returns a `FormatError` if the input string is not a valid Nessus v2
    /// report. This can happen for several reasons, including:
    /// - The XML is malformed.
    /// - The root element is not `<NessusClientData_v2>`.
    /// - Required elements or attributes (e.g., `<Policy>`) are missing.
    /// - Elements that should be unique appear multiple times.
    /// - Data cannot be converted to the expected type (e.g., a non-integer
    ///   value for a port number).
    pub fn parse(xml: &'input str) -> Result<Self, FormatError> {
        let doc = Document::parse(xml)?;

        let root = doc.root_element();

        if root.tag_name().name() != "NessusClientData_v2" {
            return Err(FormatError::UnsupportedVersion);
        }

        let mut policy = None;
        let mut report = None;

        for child in root.children() {
            match child.tag_name().name() {
                "Policy" => {
                    if policy.is_some() {
                        return Err(FormatError::RepeatedTag("Policy"));
                    }
                    policy = Some(Policy::from_xml_node(child)?);
                }
                "Report" => {
                    if report.is_some() {
                        return Err(FormatError::RepeatedTag("Report"));
                    }
                    report = Some(Report::from_xml_node(child)?);
                }
                _ => assert_empty_text(child)?,
            }
        }

        let policy = policy.ok_or(FormatError::MissingTag("Policy"))?;

        Ok(Self { policy, report })
    }
}

fn assert_empty_text(node: roxmltree::Node<'_, '_>) -> Result<(), FormatError> {
    let Some(text) = node.text() else {
        return Err(FormatError::UnexpectedNodeKind);
    };

    if !text.trim().is_empty() {
        return Err(FormatError::UnexpectedNode(
            format!("{}: {text}", node.tag_name().name()).into_boxed_str(),
        ));
    }

    Ok(())
}

trait StringStorageExt<'input> {
    fn to_str(&self) -> Result<&'input str, FormatError>;
    fn to_cow(&self) -> Cow<'input, str>;
}

impl<'input> StringStorageExt<'input> for StringStorage<'input> {
    fn to_str(&self) -> Result<&'input str, FormatError> {
        match self {
            StringStorage::Borrowed(s) => Ok(s),
            StringStorage::Owned(s) => Err(FormatError::UnexpectedXmlAttribute(s.as_ref().into())),
        }
    }

    fn to_cow(&self) -> Cow<'input, str> {
        match self {
            StringStorage::Borrowed(s) => Cow::Borrowed(s),
            StringStorage::Owned(s) => Cow::Owned(String::from(s.as_ref())),
        }
    }
}

/// A utility struct for representing a standard 6-byte MAC address.
///
/// It provides functionality for parsing from the common colon-separated
/// hexadecimal format (e.g., "00:1A:2B:3C:4D:5E") and for displaying
/// in the same format.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MacAddress {
    bytes: [u8; 6],
}

impl MacAddress {
    #[must_use]
    pub const fn bytes(self) -> [u8; 6] {
        self.bytes
    }
}

impl FromStr for MacAddress {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = s.split(':');

        let mac_address = Self {
            bytes: [
                parse_octet(octets.next().ok_or(FormatError::MacAdressParse)?)?,
                parse_octet(octets.next().ok_or(FormatError::MacAdressParse)?)?,
                parse_octet(octets.next().ok_or(FormatError::MacAdressParse)?)?,
                parse_octet(octets.next().ok_or(FormatError::MacAdressParse)?)?,
                parse_octet(octets.next().ok_or(FormatError::MacAdressParse)?)?,
                parse_octet(octets.next().ok_or(FormatError::MacAdressParse)?)?,
            ],
        };

        if octets.next().is_some() {
            Err(FormatError::MacAdressParse)
        } else {
            Ok(mac_address)
        }
    }
}

fn parse_octet(input: &str) -> Result<u8, FormatError> {
    let &[a, b] = input.as_bytes() else {
        return Err(FormatError::MacAdressParse);
    };

    Ok((parse_hex_digit(a)? << 4) | parse_hex_digit(b)?)
}

const fn parse_hex_digit(ch: u8) -> Result<u8, FormatError> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'A'..=b'F' => Ok((ch - b'A') + 10),
        b'a'..=b'f' => Ok((ch - b'a') + 10),
        _ => Err(FormatError::MacAdressParse),
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let _ = write!(
            f,
            "{:<02X}:{:<02X}:{:<02X}:{:<02X}:{:<02X}:{:<02X}",
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5]
        );

        Ok(())
    }
}

impl std::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{self}\"")
    }
}
