# parse_quote

This code is my response to the Tsurucapital exercise. There is relatively
little information about the performance levels to achieve. I focused more
on memory usage by employing streaming to limit consumption. As for the
runtime, the program runs in under 150ms, so I didn't aim to optimize or
use parallelism. I also tried to handle errors cleanly.

Notes:

The use of 'nom' might be a bit excessive, but I find that it helps with
maintaining the parser, and I quite like this library.

I added serde and bincode and conducted a test to ensure the data structure
could be serialized. The original idea was to use chunked files and an
external merge for handling very large files, especially if memory usage
became a concern. However, since memory consumption remained low and there
was no precise information about file sizes, I decided not to implement
this approach. Based on current performance, I believe it can handle quite
large files.

I also admit I was a bit lazy, I did a bit of TDD, but I didn't write too
many unit tests. :)
But it deserved more unit tests with packets crafted with anomalies.

https://www.tsurucapital.com/en/code-sample.html

## Rust version used to build the binary

```bash
rustc --version
rustc 1.81.0 (eeb90cda1 2024-09-04)
```

## Usage

```bash
Usage: parse_quote [OPTIONS] <FILE>

Arguments:
  <FILE>  File argument (required)

Options:
  -r             Optional flag to enable reordering of the packets according to quote accept time
  -d...          Optional flag to enable debug. -ddd = trace, -dd = debug, -d = info, 0 = error
  -h, --help     Print help
  -V, --version  Print version
```

## Performance

```bash
Command being timed: "./target/release/parse_quote pcap/mdf-kospi200.20110216-0.pcap"
User time (seconds): 0.04
System time (seconds): 0.03
Percent of CPU this job got: 53%
Elapsed (wall clock) time (h:mm:ss or m:ss): 0:00.15
Maximum resident set size (kbytes): 8248
```

```bash
Command being timed: "./target/release/parse_quote -r pcap/mdf-kospi200.20110216-0.pcap"
User time (seconds): 0.01
System time (seconds): 0.00
Percent of CPU this job got: 95%
Elapsed (wall clock) time (h:mm:ss or m:ss): 0:00.02
Maximum resident set size (kbytes): 8120
```
