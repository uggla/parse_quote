mod utils;

use anyhow::Context;
use clap::Parser;
use itertools::Itertools;
use parse_quote::{
    duration_to_offsetdatetime, parse_packet, parse_packet_payload, Data, PayloadParseError,
    PcapIterator,
};
use pcap_file::pcap::PcapReader;
use simple_logger::SimpleLogger;
use std::fs::File;
use time::format_description::well_known::Rfc3339;

// Port numbers for our services
pub const DEST_PORTS: [u16; 2] = [15515, 15516];

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional flag to enable reordering of the packets according to quote accept time.
    #[arg(short = 'r')]
    reordering: bool,

    /// Optional flag to enable debug. -ddd = trace, -dd = debug, -d = info, 0 = error.
    #[arg(short = 'd', action = clap::ArgAction::Count)]
    debug: u8,

    /// File argument (required)
    file: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    SimpleLogger::new()
        .with_level(match cli.debug {
            3.. => log::LevelFilter::Trace,
            2 => log::LevelFilter::Debug,
            1 => log::LevelFilter::Info,
            0 => log::LevelFilter::Error,
        })
        .with_utc_timestamps()
        .init()?;

    log::debug!("cli arguments = {:#?}", &cli);

    let pcap_file =
        File::open(&cli.file).context(format!("Unable to open '{}' pcap file", cli.file))?;
    let mut pcap_reader = PcapReader::new(pcap_file)
        .context(format!("pcap '{}' is not a valid pcap file", cli.file))?;

    log::info!("Start processing pcap file '{}'", &cli.file);

    let pcap_iterator = PcapIterator::new(&mut pcap_reader);
    let pcap_iterator = pcap_iterator.filter_map(|packet| {
        let packet = match packet {
            Ok(packet) => packet,
            Err(_) => {
                log::error!("Unable to read packet");
                return None;
            }
        };

        log::trace!(
            "Packet timestamp: {:?}",
            duration_to_offsetdatetime(&packet.0).format(&Rfc3339),
        );

        log::trace!("Packet data: {:x?}", packet.1);

        let udp_packet = match parse_packet(&packet.1, &DEST_PORTS) {
            Ok(udp_packet) => udp_packet,
            Err(error) => {
                log::warn!("{}", error);
                return None;
            }
        };

        let data = match parse_packet_payload(udp_packet.payload(), packet.0) {
            Ok(data) => Some(data),
            Err(error) => {
                match error {
                    PayloadParseError::SignatureError => {
                        log::warn!("{}", error);
                    }
                    _ => {
                        log::error!("{}", error);
                    }
                }
                return None;
            }
        };

        log::debug!("data: {:?}", data);
        data
    });

    if !cli.reordering {
        pcap_iterator.for_each(|data| {
            utils::display_data(&data).unwrap();
        });
    } else {
        pcap_iterator
            .filter(|data| {
                let pkt_time = duration_to_offsetdatetime(&data.pkt_timestamp).time();
                let accept_time = duration_to_offsetdatetime(&std::time::Duration::from_nanos(
                    data.timestamp.try_into().unwrap(),
                ))
                .time();

                if accept_time - pkt_time < time::Duration::seconds(3) {
                    log::debug!("duration: {:?}", accept_time - pkt_time);
                    return true;
                }
                false
            })
            .sorted_by_key(|data| data.timestamp)
            .for_each(|data| {
                utils::display_data(&data).unwrap();
            });
    }

    log::info!("End processing pcap file '{}'", &cli.file);
    Ok(())
}
