#![feature(let_chains)]
use std::path::Path;
use clap::Parser;
use libpcap_rs::{LibPcap, PResult, ChecksumLayer};


/// Write pcap file command
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Output pcap file path
    #[arg(short, long)]
    output: String,
    /// Byte stream
    #[arg(short, long)]
    payload: String,
    /// Write pcap mode, eg: a or w
    #[arg(short, long)]
    mode: Option<String>,
    /// Write packet timestamp
    #[arg(short, long)]
    timestamp: Option<u64>,
    /// update tcp or udp checksum
    #[arg(long, default_value="true")]
    checksum: bool,
    /// update ipv4 total_length.
    #[arg(long, default_value="true")]
    total_length: bool,
}


fn write_pcap(args: &Cli) -> PResult<()> {
    let mode = if let Some(mode) = &args.mode { mode } else if Path::new(&args.output).exists() { "a" } else { "w" };
    let output_pcap = LibPcap::open(&args.output, mode)?;
    
    if let Ok(mut payload) = hex::decode(&args.payload) {
        if args.checksum {
            let (_, layer) = jppe::decode_borrow::<ChecksumLayer<'_>>(&payload).unwrap();

            let length = layer.remain.len();

            if let Some(protocol) = layer.layer3.get_protocol() && let Some(checksum) = layer.checksum() {
                let checksum_array = checksum.to_be_bytes();
    
                if protocol == 17 {
                    payload[14 + 20 + 6] = checksum_array[0];
                    payload[14 + 20 + 7] = checksum_array[1];
                }
                else if protocol == 6 {
                    payload[14 + 20 + 16] = checksum_array[0];
                    payload[14 + 20 + 17] = checksum_array[1];
                }
            }    

            if args.total_length {
                let length = length + 20;
                let length_array = length.to_be_bytes();
                payload[14 + 2] = length_array[0];
                payload[14 + 3] = length_array[1];
            }
        }

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

    let ret = write_pcap(&args);
    println!("{ret:?}");
}