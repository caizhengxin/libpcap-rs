use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{error::Error, thread};
use signal_hook::{consts::SIGINT, iterator::Signals};
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
    #[arg(short, long)]
    /// Show capture packet
    view: bool,
}


fn sniff_pcap<'a>(args: &Cli) -> PResult<()> {
    let mut signals = Signals::new(&[SIGINT]).unwrap();

    let bpf_filter = args.bpf_filter.join(" ");
    let output_pcap = if let Some(output) = &args.output {
        let mode = if let Some(mode) = &args.mode { mode } else if Path::new(output).exists() { "a" } else { "w" };
        Some(LibPcap::open(output, mode)?)
    }
    else {
        None
    };

    let sniff = Sniff::open(&args.iface)?;
    sniff.with_promisc(if args.promisc {1} else {0})
         .with_filter(bpf_filter)?;
    let sniff = Arc::new(sniff);
    let sniff_clone = sniff.clone();

    let capture_cnt = Arc::new(AtomicUsize::new(0));
    let capture_cnt_clone = capture_cnt.clone();

    thread::spawn(move || {
        for _sig in signals.forever() {
            let count = capture_cnt_clone.load(Ordering::Relaxed);
            if let Some(stats) = sniff_clone.stats() {
                println!("\n");
                println!("{} packets captured", count);
                println!("{} packets received by filter", stats.ps_recv);
                println!("{} packets dropped by kernel", stats.ps_drop);
                println!("{} packets dropped by iface", stats.ps_ifdrop);        
            }
            std::process::exit(1);
        }
    });

    for pkt in sniff.capture(args.count) {
        if args.view {
            println!("{pkt:?}");
        }

        capture_cnt.fetch_add(1, Ordering::Relaxed);

        if let Some(output_pcap) = &output_pcap {
            output_pcap.write_timestamp(pkt.buf, pkt.timestamp);
        }
    }

    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let ret = sniff_pcap(&args);
    println!(">>> {ret:?}");

    Ok(())
}
