#[derive(Debug, Clone)]
pub enum FormatError {
    MissingAttribute(&'static str),
    MissingTag(&'static str),
    RepeatedTag(&'static str),
    UnexpectedFormat(&'static str),
    UnexpectedNodeKind,
    UnexpectedText(Box<str>),
    UnexpectedXmlAttribute(Box<str>),
    UnsupportedVersion,
    ParseInt(std::num::ParseIntError),
    Xml(Box<roxmltree::Error>),
    Jiff(jiff::Error),
    IpAddrParse(std::net::AddrParseError),
    BoolParse(std::str::ParseBoolError),
    UnexpectedNode(Box<str>),
    UnexpectedPingMethod(Box<str>),
    UnexpectedDeadHostReason(Box<str>),
    UnexpectedPingTcpResponse(Box<str>),
    UnexpectedPingFormat(Box<str>),
    UnexpectedProtocol(Box<str>),
    MacAdressParse,
    UnexpectedPluginType(Box<str>),
    UnexpectedLevel(Box<str>),
    MissingPluginOutput,
}

impl From<std::str::ParseBoolError> for FormatError {
    fn from(err: std::str::ParseBoolError) -> Self {
        Self::BoolParse(err)
    }
}

impl From<std::net::AddrParseError> for FormatError {
    fn from(err: std::net::AddrParseError) -> Self {
        Self::IpAddrParse(err)
    }
}

impl From<std::num::ParseIntError> for FormatError {
    fn from(err: std::num::ParseIntError) -> Self {
        Self::ParseInt(err)
    }
}

impl From<roxmltree::Error> for FormatError {
    fn from(err: roxmltree::Error) -> Self {
        Self::Xml(Box::from(err))
    }
}

impl From<jiff::Error> for FormatError {
    fn from(err: jiff::Error) -> Self {
        Self::Jiff(err)
    }
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAttribute(attr) => {
                write!(f, "Missing attribute: {attr}")
            }
            Self::MissingTag(tag) => {
                write!(f, "Missing tag: {tag}")
            }
            Self::RepeatedTag(tag) => {
                write!(f, "Repeated tag: {tag}")
            }
            Self::UnexpectedFormat(s) => {
                write!(f, "Unexpected format: {s}")
            }
            Self::UnexpectedNodeKind => {
                write!(f, "Unexpected NodeKind")
            }
            Self::UnexpectedText(s) => {
                write!(f, "Unexpected text: {s}")
            }
            Self::UnexpectedNode(s) => {
                write!(f, "Unexpected node: {s}")
            }
            Self::UnexpectedXmlAttribute(s) => {
                write!(f, "Unexpected XML attributes: {s}")
            }
            Self::UnsupportedVersion => write!(f, "Unsupported version"),
            Self::UnexpectedPingMethod(s) => write!(f, "Unexpected ping method: {s}"),
            Self::UnexpectedDeadHostReason(s) => write!(f, "Unexpected dead host reason: {s}"),
            Self::UnexpectedPingTcpResponse(s) => write!(f, "Unexpected ping TCP response: {s}"),
            Self::UnexpectedPingFormat(s) => write!(f, "Unexpected ping format: {s}"),
            Self::UnexpectedProtocol(s) => write!(f, "Unexpected protocol: {s}"),
            Self::UnexpectedPluginType(s) => write!(f, "Unexpected plugin type: {s}"),
            Self::UnexpectedLevel(s) => write!(f, "Unexpected level: {s}"),
            Self::MissingPluginOutput => write!(f, "Missing plugin output"),
            Self::MacAdressParse => write!(f, "Can't parse MAC address"),
            Self::ParseInt(err) => write!(f, "{err}"),
            Self::Xml(err) => write!(f, "{err}"),
            Self::Jiff(err) => write!(f, "{err}"),
            Self::IpAddrParse(err) => write!(f, "{err}"),
            Self::BoolParse(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for FormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParseInt(err) => Some(err),
            Self::Xml(err) => Some(err),
            Self::Jiff(err) => Some(err),
            Self::IpAddrParse(err) => Some(err),
            Self::BoolParse(err) => Some(err),
            Self::MissingAttribute(_)
            | Self::MissingTag(_)
            | Self::RepeatedTag(_)
            | Self::UnexpectedFormat(_)
            | Self::UnexpectedNodeKind
            | Self::UnexpectedNode(_)
            | Self::UnexpectedText(_)
            | Self::UnexpectedXmlAttribute(_)
            | Self::UnsupportedVersion
            | Self::UnexpectedPingMethod(_)
            | Self::UnexpectedDeadHostReason(_)
            | Self::UnexpectedPingTcpResponse(_)
            | Self::UnexpectedPingFormat(_)
            | Self::UnexpectedProtocol(_)
            | Self::UnexpectedPluginType(_)
            | Self::UnexpectedLevel(_)
            | Self::MissingPluginOutput
            | Self::MacAdressParse => None,
        }
    }
}
