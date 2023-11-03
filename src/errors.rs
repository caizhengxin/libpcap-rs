#[derive(Debug, thiserror::Error)]
pub enum LibPcapError {
    #[error("invalid file: {path:?}")]
    InvalidFile {
        path: String,
    },
    #[error("invalid dir: {path:?}")]
    InvalidDir {
        path: String,
    },
    #[error("file not extists: {path:?}")]
    FileNotExtists {
        path: String,
    },
    #[error("open mode error")]
    OpenModeError,
    #[error("invalid interface: {iface:?} - {msg:?}")]
    InvalidInterface {
        iface: String,
        msg: String,
    },
    #[error("invalid bpf filter")]
    InvalidBpfFilter,
}
