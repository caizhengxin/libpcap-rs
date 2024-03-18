use clap::Parser;
use libpcap_rs::{LibPcap, PResult, Layer};


/// Read pcap file command
#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Input pcap file path
    #[arg(short, long)]
    input: String,
    #[arg(long)]
    raw: bool,
}


fn read_pcap(args: &Cli) -> PResult<()> {
    let f = LibPcap::open(&args.input, "r")?;

    for pkt in f.read() {
        if let Ok((_, layer)) = jppe::decode_borrow::<Layer<'_>>(&pkt.buf) {
            let smac = layer.layer12.smac.to_string();
            let dmac = layer.layer12.dmac.to_string();
            let r#type = layer.layer12.r#type;

            print!("{smac}");

            if let Some(src) = layer.layer3.get_src() {
                print!(" {src:?}");
            }

            if let Some(sport) = layer.layer4.get_sport() {
                print!(" {sport:?}");
            }

            print!(" -> ");

            print!("{dmac}");

            if let Some(dst) = layer.layer3.get_dst() {
                print!(" {dst:?}");
            }

            if let Some(dport) = layer.layer4.get_dport() {
                print!(" {dport:?}");
            }

            if let Some(flags) = layer.layer4.get_tcp_flags() {
                print!(" 0x{flags:2x}");
            }

            print!(" 0x{type:2x}");

            println!("");

            if args.raw {
                println!("    {:?}", layer.layer12);
                println!("    {:?}", layer.layer3);
                println!("    {:?}", layer.layer4);
            }
        }
    }        

    Ok(())
}


fn main() {
    let args = Cli::parse();

    let _ = read_pcap(&args);
}