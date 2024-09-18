mod utils;

use anyhow::Context;
use clap::Parser;
use parse_quote::{
    duration_to_offsetdatetime, parse_packet, parse_packet_new, parse_packet_payload, Data,
    PacketParseError, PayloadParseError,
};
use pcap_file::pcap::{PcapPacket, PcapReader};
use pcap_file::PcapError;
use simple_logger::SimpleLogger;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use time::format_description::well_known::Rfc3339;

// Number of packets in a chunk to be processed
const CHUNK_SIZE: u32 = 5000;

// Port numbers for our services
pub const DEST_PORTS: [u16; 2] = [15515, 15516];

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional flag to enable reordering of the packets according to quote accept time.
    #[arg(short = 'r')]
    reordering: bool,

    /// Optional flag to enable debug.
    #[arg(short = 'd', action = clap::ArgAction::Count)]
    debug: u8,

    /// File argument (required)
    file: String,
}

// A helper structure to manage merging
#[derive(Debug)]
struct MergeEntry {
    value: i32,
    source_index: usize,
}

impl PartialEq for MergeEntry {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for MergeEntry {}

impl PartialOrd for MergeEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // We reverse the order so the BinaryHeap behaves like a min-heap
        Some(other.value.cmp(&self.value))
    }
}

impl Ord for MergeEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

fn sort_and_save_chunk(chunk: &mut [i32], chunk_index: usize) {
    chunk.sort(); // Sort the chunk in memory

    // Save the sorted chunk to a file
    let filename = format!("chunk_{}.txt", chunk_index);
    let file = File::create(filename).expect("Unable to create file");
    let mut writer = BufWriter::new(file);

    for num in chunk {
        writeln!(writer, "{}", num).expect("Unable to write to file");
    }
}

fn merge_sorted_chunks(num_chunks: usize) {
    let mut readers: Vec<_> = (0..num_chunks)
        .map(|i| {
            let filename = format!("chunk_{}.txt", i);
            let file = File::open(filename).expect("Unable to open file");
            BufReader::new(file)
                .lines()
                .map(|line| line.unwrap().parse::<i32>().unwrap())
        })
        .collect();

    let mut heap = BinaryHeap::new();

    // Initialize the heap with the first element of each chunk
    for (i, reader) in readers.iter_mut().enumerate() {
        if let Some(value) = reader.next() {
            heap.push(MergeEntry {
                value,
                source_index: i,
            });
        }
    }

    // Open a file for the final sorted output
    let output_file = File::create("final_sorted_output.txt").expect("Unable to create file");
    let mut output_writer = BufWriter::new(output_file);

    // Merge the chunks
    while let Some(MergeEntry {
        value,
        source_index,
    }) = heap.pop()
    {
        writeln!(output_writer, "{}", value).expect("Unable to write to file");

        // Insert the next element from the same source (chunk)
        if let Some(next_value) = readers[source_index].next() {
            heap.push(MergeEntry {
                value: next_value,
                source_index,
            });
        }
    }
}

fn external_merge_sort(data: impl Iterator<Item = i32>, chunk_size: usize) {
    let mut chunk = Vec::with_capacity(chunk_size);
    let mut chunk_index = 0;

    for value in data {
        chunk.push(value);

        if chunk.len() == chunk_size {
            sort_and_save_chunk(&mut chunk, chunk_index);
            chunk.clear();
            chunk_index += 1;
        }
    }

    // Don't forget to sort and save the final chunk if there are leftover elements
    if !chunk.is_empty() {
        sort_and_save_chunk(&mut chunk, chunk_index);
    }

    // Now merge all the sorted chunks
    merge_sorted_chunks(chunk_index + 1);
}

fn main() -> anyhow::Result<()> {
    // // Simulate a large stream of data with varying sizes in chunks
    // let large_dataset = vec![3, 1, 5, 7, 2, 6, 9, 4, 8, 0];
    // let chunk_size = 3; // Process the data in chunks of 3 elements
    //
    // // Perform the external merge sort
    // external_merge_sort(large_dataset.into_iter(), chunk_size);
    //
    // println!("Sorted data has been written to final_sorted_output.txt");
    //
    //

    //
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
    let mut num_packets = 0;
    let mut paquets: Vec<Data> = Vec::with_capacity(CHUNK_SIZE as usize);
    let mut chunk_index = 0;

    let pcap_iterator = PcapIterator::new(&mut pcap_reader);

    pcap_iterator
        .filter_map(|packet| {
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

            let udp_packet = match parse_packet_new(&packet.1, &DEST_PORTS) {
                Ok(udp_packet) => udp_packet,
                Err(e) => {
                    match e {
                        PacketParseError::InvalidDestinationPort { .. } => {
                            log::warn!("{}", e);
                        }
                        _ => {
                            log::error!("{}", e);
                        }
                    }
                    return None;
                }
            };

            let data = match parse_packet_payload(udp_packet.payload(), packet.0) {
                Ok(data) => Some(data),
                Err(e) => {
                    match e {
                        PayloadParseError::SignatureError => {
                            log::warn!("{}", e);
                        }
                        _ => {
                            log::error!("{}", e);
                        }
                    }
                    return None;
                }
            };

            data
        })
        .for_each(|data| {
            utils::display_data(&data).unwrap();
        });
    // while let Some(packet) = pcap_reader.next_packet() {
    //     let pkt = packet.context("Unable to read packet")?;
    //
    //     log::debug!(
    //         "Packet timestamp: {:?}",
    //         duration_to_offsetdatetime(&pkt.timestamp).format(&Rfc3339)
    //     );
    //     log::trace!("Packet data: {:x?}", pkt.data);
    //
    //     if let Ok(quote_udp_packet) = parse_packet(&pkt, &DEST_PORTS) {
    //         log::trace!("Src port: {:?}", quote_udp_packet.source_port());
    //         log::trace!("Dst port: {:?}", quote_udp_packet.destination_port());
    //         log::trace!("Payload: {:x?}", &quote_udp_packet.payload());
    //
    //         match parse_packet_payload(quote_udp_packet.payload(), pkt.timestamp) {
    //             Ok(data) => {
    //                 log::debug!("Data: {:#?}", data);
    //                 // utils::display_data(&data)?;
    //                 add_packet(
    //                     &mut paquets,
    //                     data,
    //                     &pkt.timestamp,
    //                     cli.reordering,
    //                     &mut num_packets,
    //                 );
    //                 if num_packets == CHUNK_SIZE {
    //                     write_chunk(&mut paquets, chunk_index, cli.reordering)?;
    //                     num_packets = 0;
    //                     chunk_index += 1;
    //                     // paquets.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    //                     //
    //                     //
    //                     paquets.clear();
    //                 }
    //             }
    //             Err(e) => match e {
    //                 PayloadParseError::SignatureError => {
    //                     log::warn!("{:?}", e);
    //                 }
    //                 _ => {
    //                     log::error!("{:?}", e);
    //                 }
    //             },
    //         }
    //     } else {
    //         log::warn!("Packet is not a udp packet or destination port is not valid");
    //     }
    // }
    // write_chunk(&mut paquets, chunk_index, cli.reordering)?;
    //
    // if !cli.reordering {
    //     for chunk in 0..chunk_index {
    //         let filename = format!("chunks/chunk_{}.txt", chunk);
    //         let file = File::open(filename).context("Unable to open file")?;
    //         let file = BufReader::new(file);
    //
    //         for line in file.lines() {
    //             dbg!(&line);
    //             let data: Data = bincode::deserialize(line.context("bla bla")?.as_bytes())
    //                 .context("Fail to deserialize data")?;
    //         }
    //     }
    // }

    Ok(())
}

fn add_packet(
    paquets: &mut Vec<Data>,
    data: Data,
    pkt_timestamp: &std::time::Duration,
    reordering: bool,
    num_packets: &mut u32,
) {
    if !reordering {
        paquets.push(data);
        *num_packets += 1;
    } else {
        let pkt_time = duration_to_offsetdatetime(pkt_timestamp).time();
        let accept_time = duration_to_offsetdatetime(&std::time::Duration::from_nanos(
            data.timestamp.try_into().unwrap(),
        ))
        .time();

        if accept_time - pkt_time < time::Duration::seconds(3) {
            paquets.push(data);
            *num_packets += 1;
        }

        log::debug!("duration: {:?}", accept_time - pkt_time);
    }
}

fn write_chunk(chunk: &mut [Data], chunk_index: usize, reordering: bool) -> anyhow::Result<()> {
    let filename = format!("chunks/chunk_{}.txt", chunk_index);
    let output_file = File::create(filename).context("Unable to create output file")?;
    let mut output_file = BufWriter::new(output_file);
    if reordering {
        chunk.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    }
    for data in chunk {
        let data_serialized = bincode::serialize(data).context("Unable to serialize data")?;
        writeln!(output_file, "{:?}", data_serialized).context("Unable to write chunk data")?;
        // output_file
        //     .write_all(&data_serialized)
        //     .context("Unable to write chunk data")?;
    }
    Ok(())
}

struct PcapIterator<'a> {
    reader: &'a mut PcapReader<File>,
}

impl<'a> PcapIterator<'a> {
    pub fn new(reader: &'a mut PcapReader<File>) -> Self {
        PcapIterator { reader }
    }
}

impl<'a> Iterator for PcapIterator<'a> {
    // type Item = Result<PcapPacket<'a>, PcapError>;
    // type Item = PcapPacket<'a>;
    type Item = Result<(std::time::Duration, Vec<u8>), PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_packet() {
            Some(packet) => match packet {
                Ok(packet) => Some(Ok((packet.timestamp, packet.data.to_vec()))),
                Err(e) => Some(Err(e)),
            },
            None => None,
        }
    }
}
