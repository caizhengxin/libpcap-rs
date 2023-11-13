use std::path::Path;
use clap::Parser;
use libpcap_rs::{LibPcap, PResult, Sniff};


/// Write pcap file command
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Capture network port
    #[arg(short, long)]
    iface: String,
    /// Capture packet count
    #[arg(short, long, default_value_t = -1)]
    count: isize,
    /// Set promiscuous mode
    #[arg(long, default_value_t = true)]
    promisc: bool,
    /// Output pcap file path
    #[arg(short, long)]
    output: Option<String>,
    /// Write pcap mode, eg: a or w
    #[arg(short, long)]
    mode: Option<String>,
    /// BPF filter
    bpf_filter: Vec<String>,
    /// Show capture packet
    view: bool,
}


fn sniff_pcap(args: &Cli) -> PResult<()> {
    let bpf_filter = args.bpf_filter.join(" ");
    let output_pcap = if let Some(output) = &args.output {
        let mode = if let Some(mode) = &args.mode { mode } else if Path::new(output).exists() { "a" } else { "w" };
        Some(LibPcap::open(output, mode)?)
    }
    else {
        None
    };

    let sniff = Sniff::open(args.iface.clone())?;
    let sniff = sniff.with_promisc(if args.promisc {1} else {0})
        .with_filter(bpf_filter)?;

    for pkt in sniff.capture(args.count) {
        if args.view {
            println!("{pkt:?}");
        }

        if let Some(output_pcap) = &output_pcap {
            output_pcap.write_timestamp(pkt.buf, pkt.timestamp);
        }
    }

    Ok(())
}


fn main() {
    let args = Cli::parse();

    let _ = sniff_pcap(&args);
}
