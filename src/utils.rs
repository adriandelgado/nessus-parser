use std::{fs, path::PathBuf};

use crate::models::NessusClientDataV2;
use color_eyre::{
    eyre::{eyre, WrapErr},
    Result,
};
use hard_xml::{XmlRead, XmlReader};

pub enum NessusFiles {
    File(Option<PathBuf>),
    Dir(fs::ReadDir),
}

impl NessusFiles {
    pub fn new(path: PathBuf) -> Result<Self> {
        let metadata = path.metadata()?;
        if metadata.is_dir() {
            Ok(Self::Dir(path.read_dir()?))
        } else if metadata.is_file() && path.extension() == Some("nessus".as_ref()) {
            Ok(Self::File(Some(path)))
        } else {
            Err(eyre!(
                "input must be a `.nessus` file or a directory containing said files"
            ))
        }
    }
}

impl Iterator for NessusFiles {
    type Item = Result<PathBuf>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            NessusFiles::File(file) => file.take().map(Ok),
            NessusFiles::Dir(dirs) => {
                for entry in dirs {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => return Some(Err(e).wrap_err("can't access `DirEntry`")),
                    };

                    let path = entry.path();

                    let file_type = match entry.file_type() {
                        Ok(file_type) => file_type,
                        Err(e) => return Some(Err(e).wrap_err("can't access `FileType`")),
                    };

                    if file_type.is_file() && path.extension() == Some("nessus".as_ref()) {
                        return Some(Ok(path));
                    }
                }
                None
            }
        }
    }
}

pub fn get_nessus_data(nessus_str: &str) -> Result<NessusClientDataV2> {
    let mut reader = XmlReader::new(nessus_str);

    let mut nessus_data = NessusClientDataV2::from_reader(&mut reader)?;

    nessus_data.remove_plugin_set();

    Ok(nessus_data)
}
