use anyhow::Context;
use clap::Parser;
use parse_quote::{
    display_data, duration_to_date, parse_packet, parse_packet_payload, PayloadParseError,
};
use pcap_file::pcap::PcapReader;
use simple_logger::SimpleLogger;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use time::format_description::well_known::Rfc3339;

// Number of packets in a chunk to be processed
const CHUNK_SIZE: u32 = 6000;

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

    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt.context("Unable to read packet")?;

        log::debug!(
            "Packet timestamp: {:?}",
            duration_to_date(&pkt.timestamp).format(&Rfc3339)
        );
        log::trace!("Packet data: {:x?}", pkt.data);

        if let Ok(quote_udp_packet) = parse_packet(&pkt, &DEST_PORTS) {
            log::trace!("Src port: {:?}", quote_udp_packet.source_port());
            log::trace!("Dst port: {:?}", quote_udp_packet.destination_port());
            log::trace!("Payload: {:x?}", &quote_udp_packet.payload());

            match parse_packet_payload(quote_udp_packet.payload()) {
                Ok(data) => {
                    log::debug!("Data: {:#?}", data);
                    display_data(&pkt.timestamp, data)?;
                }
                Err(e) => match e {
                    PayloadParseError::SignatureError => {
                        log::warn!("{:?}", e);
                    }
                    _ => {
                        log::error!("{:?}", e);
                    }
                },
            }
        } else {
            log::warn!("Packet is not a udp packet or destination port is not valid");
        }
    }

    Ok(())
}
