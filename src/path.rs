use std::io;
use std::fs;
use std::path::{Path, PathBuf};


pub fn visit_dirs<'a>(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut vlist = vec![];

    if dir.is_dir() {
        for entry in fs::read_dir(dir)?
            .filter_map(|e|e.ok())
        {
            let entry = entry;
            let path = entry.path();

            let path_string = path.file_name().unwrap_or_default().to_string_lossy();

            if path.is_dir() {
                let value = visit_dirs(&path)?;
                vlist.extend(value);
            } else if path_string.ends_with(".pcap") || path_string.ends_with(".cap") || path_string.ends_with(".pcapng") {
                vlist.push(entry.path());
            }
        }
    }

    Ok(vlist)
}
