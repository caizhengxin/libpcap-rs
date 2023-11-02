#[derive(Debug, thiserror::Error)]
pub enum LibPcapError<'a> {
    #[error("invalid file: {path:?}")]
    InvalidFile {
        path: &'a str
    },
    #[error("invalid dir: {path:?}")]
    InvalidDir {
        path: &'a str
    },
    #[error("file not extists: {path:?}")]
    FileNotExtists {
        path: &'a str
    },
    #[error("open mode error")]
    OpenModeError,
}
