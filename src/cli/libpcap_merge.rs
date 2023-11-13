use std::path::Path;
use libpcap_rs::{LibPcap, PResult, path::visit_dirs};
use clap::Parser;


/// Merge pcap file command
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// input pcap file path
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    /// Output pcap file path
    output: String,
    /// BPF filter
    bpf_filter: Vec<String>,
    /// Write pcap mode, eg: a or w
    #[arg(short, long)]
    mode: Option<String>,
}


fn merge_pcap(args: &Cli) -> PResult<()> {
    let mode = if let Some(mode) = &args.mode { mode } else if Path::new(&args.output).exists() { "a" } else { "w" };
    let output_pcap = LibPcap::open(&args.output, mode)?;

    let input_path = Path::new(&args.input);

    if input_path.is_dir() {
        if let Ok(paths) = visit_dirs(input_path) {
            for path in paths {
                let input_pcap = LibPcap::open(&path.to_string_lossy().to_string(), "r")?;

                input_pcap.with_filter(&args.bpf_filter.join(" "))?;
        
                for pkt in input_pcap.read() {
                    output_pcap.write_timestamp(pkt.buf, pkt.timestamp);
                }        
            }    
        }
    }
    else if input_path.is_file() {
        let input_pcap = LibPcap::open(&args.input, "r")?;

        input_pcap.with_filter(&args.bpf_filter.join(" "))?;

        for pkt in input_pcap.read() {
            output_pcap.write_timestamp(pkt.buf, pkt.timestamp);
        }
    }

    Ok(())
}


fn main() {
    let args = Cli::parse();

    let _ = merge_pcap(&args);
}
