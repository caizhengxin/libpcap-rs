use std::path::Path;
use clap::Parser;
use libpcap_rs::{LibPcap, PResult};


/// Write pcap file command
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    /// Output pcap file path
    output: String,
    #[arg(short, long)]
    /// Byte stream
    payload: String,
    #[arg(short, long)]
    /// Write pcap mode, eg: a or w
    mode: Option<String>,
    #[arg(short, long)]
    /// Write packet timestamp
    timestamp: Option<u64>,
}


fn write_pcap(args: &Cli) -> PResult<()> {
    let mode = if let Some(mode) = &args.mode { mode } else if Path::new(&args.output).exists() { "a" } else { "w" };
    let output_pcap = LibPcap::open(&args.output, mode)?;
    
    if let Ok(payload) = hex::decode(&args.payload) {
        if let Some(timestamp) = args.timestamp {
            output_pcap.write_timestamp(&payload, timestamp as i64);
        }
        else {
            output_pcap.write(&payload);
        }
    }
    else {
        println!("payload format error.");
    }

    Ok(())
}


fn main() {
    let args = Cli::parse();

    let _ = write_pcap(&args);
}