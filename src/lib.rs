mod utils;

use etherparse::err::{ip, LenError};
use nom::bytes::complete::{tag, take};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
const PACKETS_SIGNATURE: &str = "B6034";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadParseError {
    #[error("This packet does not have a valid signature (\"B6034\")")]
    SignatureError,

    #[error("Cannot decode {field:?} field")]
    FieldError { field: String },

    #[error("Cannot convert {field:?} field to utf8")]
    Utf8Error { field: String },

    #[error("Cannot convert {field:?} field to decimal value")]
    DecimalError { field: String },

    #[error("Invalid end of message marker")]
    InvalidEomError,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketParseError {
    #[error("This packet does not comply with an ethernet, or udp packet")]
    EthernetPacketError(#[from] LenError),

    #[error("This packet does not comply an IP packet")]
    IpPacketError(#[from] ip::SliceError),

    #[error("This packet destination port \"{dest_port:?}\" is not part of the allowed destination ports ({allowed_ports:?})")]
    InvalidDestinationPort {
        dest_port: u16,
        allowed_ports: Vec<u16>,
    },
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packets(Vec<Data>);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Data {
    /*
    Data Type 	2 	B6
    Information Type 	2 	03
    Market Type 	1 	4
    Issue code 	12 	ISIN code
    Issue seq.-no. 	3
    Market Status Type 	2
    Total bid quote volume 	7
    Best bid price(1st) 	5 	Decimals
    Best bid quantity(1st) 	7 	Decimals
    Best bid price(2nd) 	5
    Best bid quantity(2nd) 	7
    Best bid price(3rd) 	5
    Best bid quantity(3rd) 	7
    Best bid price(4th) 	5
    Best bid quantity(4th) 	7
    Best bid price(5th) 	5
    Best bid quantity(5th) 	7
    Total ask quote volume 	7
    Best ask price(1st) 	5
    Best ask quantity(1st) 	7
    Best ask price(2nd) 	5
    Best ask quantity(2nd) 	7
    Best ask price(3rd) 	5
    Best ask quantity(3rd) 	7
    Best ask price(4th) 	5
    Best ask quantity(4th) 	7
    Best ask price(5th) 	5
    Best ask quantity(5th) 	7
    No. of best bid valid quote(total) 	5
    No. of best bid quote(1st) 	4
    No. of best bid quote(2nd) 	4
    No. of best bid quote(3rd) 	4
    No. of best bid quote(4th) 	4
    No. of best bid quote(5th) 	4
    No. of best ask valid quote(total) 	5
    No. of best ask quote(1st) 	4
    No. of best ask quote(2nd) 	4
    No. of best ask quote(3rd) 	4
    No. of best ask quote(4th) 	4
    No. of best ask quote(5th) 	4
    Quote accept time 	8 	HHMMSSuu
    End of Message 	1 	0xff
    */
    pub pkt_timestamp: std::time::Duration,
    pub isin: String,
    pub bid_price_1: i32,
    pub bid_qty_1: i32,
    pub bid_price_2: i32,
    pub bid_qty_2: i32,
    pub bid_price_3: i32,
    pub bid_qty_3: i32,
    pub bid_price_4: i32,
    pub bid_qty_4: i32,
    pub bid_price_5: i32,
    pub bid_qty_5: i32,
    pub ask_price_1: i32,
    pub ask_qty_1: i32,
    pub ask_price_2: i32,
    pub ask_qty_2: i32,
    pub ask_price_3: i32,
    pub ask_qty_3: i32,
    pub ask_price_4: i32,
    pub ask_qty_4: i32,
    pub ask_price_5: i32,
    pub ask_qty_5: i32,
    pub timestamp: i128,
}

pub fn duration_to_offsetdatetime(duration: &std::time::Duration) -> OffsetDateTime {
    let nanoseconds = duration.as_nanos();

    OffsetDateTime::from_unix_timestamp_nanos(nanoseconds.try_into().expect("Fail to get ns"))
        .expect("Invalid time components")
}

pub fn std_to_time_duration(duration: &std::time::Duration) -> time::Duration {
    time::Duration::nanoseconds(duration.as_nanos().try_into().expect("Fail to get ns"))
}

pub fn parse_packet<'a>(
    pkt: &'a pcap_file::pcap::PcapPacket<'a>,
    valid_dst_ports: &[u16],
) -> Result<etherparse::UdpSlice<'a>, PacketParseError> {
    let ethernet_layer = etherparse::Ethernet2Slice::from_slice_without_fcs(&pkt.data)?;
    let ip_layer = etherparse::IpSlice::from_slice(ethernet_layer.payload().payload)?;
    let udp_layer = etherparse::UdpSlice::from_slice(ip_layer.payload().payload)?;

    if !valid_dst_ports.contains(&udp_layer.destination_port()) {
        return Err(PacketParseError::InvalidDestinationPort {
            dest_port: udp_layer.destination_port(),
            allowed_ports: valid_dst_ports.to_vec(),
        });
    }
    Ok(udp_layer)
}

pub fn parse_packet_new<'a>(
    pkt: &'a [u8],
    valid_dst_ports: &[u16],
) -> Result<etherparse::UdpSlice<'a>, PacketParseError> {
    let ethernet_layer = etherparse::Ethernet2Slice::from_slice_without_fcs(&pkt)?;
    let ip_layer = etherparse::IpSlice::from_slice(ethernet_layer.payload().payload)?;
    let udp_layer = etherparse::UdpSlice::from_slice(ip_layer.payload().payload)?;

    if !valid_dst_ports.contains(&udp_layer.destination_port()) {
        return Err(PacketParseError::InvalidDestinationPort {
            dest_port: udp_layer.destination_port(),
            allowed_ports: valid_dst_ports.to_vec(),
        });
    }
    Ok(udp_layer)
}

pub fn parse_packet_payload(
    input: &[u8],
    pkt_timestamp: std::time::Duration,
) -> Result<Data, PayloadParseError> {
    // Try to match the signature "B6034"
    let (input, _signature) =
        match tag::<&str, &[u8], nom::error::Error<&[u8]>>(PACKETS_SIGNATURE)(input) {
            Ok((remaining_input, magic)) => (remaining_input, magic),
            Err(_) => {
                return Err(PayloadParseError::SignatureError);
            }
        };

    let (input, isin) = take(12u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        PayloadParseError::FieldError {
            field: "isin".into(),
        }
    })?;
    let isin = std::str::from_utf8(isin).map_err(|_| PayloadParseError::Utf8Error {
        field: "isin".into(),
    })?;

    let (input, _) = take(12u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        PayloadParseError::FieldError {
            field: "before bid_price_1".into(),
        }
    })?;

    let (input, bid_price_1) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_price_1".into(),
            }
        })?;
    let bid_price_1 = std::str::from_utf8(bid_price_1)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_price_1".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_price_1".into(),
        })?;

    let (input, bid_qty_1) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_qty_1".into(),
            }
        })?;
    let bid_qty_1 = std::str::from_utf8(bid_qty_1)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_qty_1".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_qty_1".into(),
        })?;

    let (input, bid_price_2) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_price_2".into(),
            }
        })?;
    let bid_price_2 = std::str::from_utf8(bid_price_2)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_price_2".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_price_2".into(),
        })?;
    let (input, bid_qty_2) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_qty_2".into(),
            }
        })?;
    let bid_qty_2 = std::str::from_utf8(bid_qty_2)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_qty_2".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_qty_2".into(),
        })?;

    let (input, bid_price_3) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_price_3".into(),
            }
        })?;
    let bid_price_3 = std::str::from_utf8(bid_price_3)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_price_3".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_price_3".into(),
        })?;
    let (input, bid_qty_3) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_qty_3".into(),
            }
        })?;
    let bid_qty_3 = std::str::from_utf8(bid_qty_3)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_qty_3".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_qty_3".into(),
        })?;

    let (input, bid_price_4) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_price_4".into(),
            }
        })?;
    let bid_price_4 = std::str::from_utf8(bid_price_4)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_price_4".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_price_4".into(),
        })?;
    let (input, bid_qty_4) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_qty_4".into(),
            }
        })?;
    let bid_qty_4 = std::str::from_utf8(bid_qty_4)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_qty_4".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_qty_4".into(),
        })?;

    let (input, bid_price_5) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_price_5".into(),
            }
        })?;
    let bid_price_5 = std::str::from_utf8(bid_price_5)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_price_5".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_price_5".into(),
        })?;
    let (input, bid_qty_5) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "bid_qty_5".into(),
            }
        })?;
    let bid_qty_5 = std::str::from_utf8(bid_qty_5)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "bid_qty_5".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "bid_qty_5".into(),
        })?;

    let (input, _) = take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        PayloadParseError::FieldError {
            field: "before ask_price_1".into(),
        }
    })?;

    let (input, ask_price_1) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_price_1".into(),
            }
        })?;
    let ask_price_1 = std::str::from_utf8(ask_price_1)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_price_1".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_price_1".into(),
        })?;
    let (input, ask_qty_1) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_qty_1".into(),
            }
        })?;
    let ask_qty_1 = std::str::from_utf8(ask_qty_1)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_qty_1".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_qty_1".into(),
        })?;

    let (input, ask_price_2) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_price_2".into(),
            }
        })?;
    let ask_price_2 = std::str::from_utf8(ask_price_2)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_price_2".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_price_2".into(),
        })?;
    let (input, ask_qty_2) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_qty_2".into(),
            }
        })?;
    let ask_qty_2 = std::str::from_utf8(ask_qty_2)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_qty_2".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_qty_2".into(),
        })?;

    let (input, ask_price_3) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_price_3".into(),
            }
        })?;
    let ask_price_3 = std::str::from_utf8(ask_price_3)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_price_3".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_price_3".into(),
        })?;
    let (input, ask_qty_3) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_qty_3".into(),
            }
        })?;
    let ask_qty_3 = std::str::from_utf8(ask_qty_3)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_qty_3".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_qty_3".into(),
        })?;

    let (input, ask_price_4) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_price_4".into(),
            }
        })?;
    let ask_price_4 = std::str::from_utf8(ask_price_4)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_price_4".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_price_4".into(),
        })?;
    let (input, ask_qty_4) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_qty_4".into(),
            }
        })?;
    let ask_qty_4 = std::str::from_utf8(ask_qty_4)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_qty_4".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_qty_4".into(),
        })?;

    let (input, ask_price_5) =
        take(5u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_price_5".into(),
            }
        })?;
    let ask_price_5 = std::str::from_utf8(ask_price_5)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_price_5".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_price_5".into(),
        })?;
    let (input, ask_qty_5) =
        take(7u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "ask_qty_5".into(),
            }
        })?;
    let ask_qty_5 = std::str::from_utf8(ask_qty_5)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "ask_qty_5".into(),
        })?
        .parse::<i32>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "ask_qty_5".into(),
        })?;

    let (input, _) = take(50u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        PayloadParseError::FieldError {
            field: "before timestamp".into(),
        }
    })?;

    let (input, hour_10) = take(1u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        PayloadParseError::FieldError {
            field: "hour_10".into(),
        }
    })?;
    let hour_10 = std::str::from_utf8(hour_10)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "hour_10".into(),
        })?
        .parse::<i64>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "hour_10".into(),
        })?;

    let (input, hour) = take(1u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        PayloadParseError::FieldError {
            field: "hour".into(),
        }
    })?;
    let hour = std::str::from_utf8(hour)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "hour".into(),
        })?
        .parse::<i64>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "hour".into(),
        })?;

    let (input, minute_10) =
        take(1u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "hour_10".into(),
            }
        })?;
    let minute_10 = std::str::from_utf8(minute_10)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "minute_10".into(),
        })?
        .parse::<i64>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "minute_10".into(),
        })?;
    let (input, minute) = take(1u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        PayloadParseError::FieldError {
            field: "minute".into(),
        }
    })?;
    let minute = std::str::from_utf8(minute)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "minute".into(),
        })?
        .parse::<i64>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "minute".into(),
        })?;

    let (input, seconde_10) =
        take(1u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "seconde_10".into(),
            }
        })?;
    let seconde_10 = std::str::from_utf8(seconde_10)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "seconde_10".into(),
        })?
        .parse::<i64>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "seconde_10".into(),
        })?;
    let (input, seconde) = take(1u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        PayloadParseError::FieldError {
            field: "seconde".into(),
        }
    })?;
    let seconde = std::str::from_utf8(seconde)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "seconde".into(),
        })?
        .parse::<i64>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "seconde".into(),
        })?;

    let (input, micro_seconde_10) =
        take(1u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "micro_seconde_10".into(),
            }
        })?;
    let micro_seconde_10 = std::str::from_utf8(micro_seconde_10)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "micro_seconde_10".into(),
        })?
        .parse::<i64>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "micro_seconde_10".into(),
        })?;
    let (input, micro_seconde) =
        take(1u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
            PayloadParseError::FieldError {
                field: "micro_seconde".into(),
            }
        })?;
    let micro_seconde = std::str::from_utf8(micro_seconde)
        .map_err(|_| PayloadParseError::Utf8Error {
            field: "micro_seconde".into(),
        })?
        .parse::<i64>()
        .map_err(|_| PayloadParseError::DecimalError {
            field: "micro_seconde".into(),
        })?;

    let (_input, eom) = take(1u8)(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        PayloadParseError::FieldError {
            field: "eom".into(),
        }
    })?;
    if eom[0] != 0xff {
        return Err(PayloadParseError::InvalidEomError);
    }

    let hour = hour_10 * 10 + hour;
    let minute = minute_10 * 10 + minute;
    let seconde = seconde_10 * 10 + seconde;
    let micro_seconde = micro_seconde_10 * 10 + micro_seconde;

    let timestamp = time::Duration::hours(hour)
        + time::Duration::minutes(minute)
        + time::Duration::seconds(seconde)
        + time::Duration::microseconds(micro_seconde);

    let data = Data {
        pkt_timestamp,
        isin: isin.to_string(),
        bid_price_1,
        bid_qty_1,
        bid_price_2,
        bid_qty_2,
        bid_price_3,
        bid_qty_3,
        bid_price_4,
        bid_qty_4,
        bid_price_5,
        bid_qty_5,
        ask_price_1,
        ask_qty_1,
        ask_price_2,
        ask_qty_2,
        ask_price_3,
        ask_qty_3,
        ask_price_4,
        ask_qty_4,
        ask_price_5,
        ask_qty_5,
        timestamp: timestamp.whole_microseconds(),
    };

    Ok(data)
}

#[cfg(test)]
mod test {

    use super::*;
    use pretty_assertions::assert_eq;
    use utils::display_data;

    const PKT_OK: &[u8] = &[
        0x42, 0x36, 0x30, 0x33, 0x34, 0x4b, 0x52, 0x34, 0x32, 0x30, 0x31, 0x46, 0x33, 0x32, 0x37,
        0x30, 0x35, 0x30, 0x30, 0x31, 0x31, 0x30, 0x30, 0x30, 0x32, 0x32, 0x36, 0x38, 0x31, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x37, 0x32, 0x32, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x39, 0x34, 0x37, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x33, 0x36, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x35, 0x39,
        0x35, 0x39, 0x39, 0x37, 0xff,
    ];

    const PKT_KO: &[u8] = &[
        0x42, 0x36, 0x30, 0x31, 0x34, 0x4b, 0x52, 0x34, 0x31, 0x30, 0x31, 0x46, 0x33, 0x30, 0x30,
        0x30, 0x38, 0x30, 0x31, 0x31, 0x30, 0x30, 0x31, 0x34, 0x37, 0x34, 0x37, 0x20, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x31,
        0x36, 0x30, 0x31, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x38, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
        0x34, 0x38, 0x38, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x35, 0x39, 0x35, 0x39, 0x39,
        0x38, 0xff,
    ];

    #[test]
    fn test_parse_quote_packet_ok() {
        let pkt = parse_packet_payload(PKT_OK, std::time::Duration::from_secs(5));
        dbg!(&pkt);
        assert!(pkt.is_ok());
        let pkt = pkt.unwrap();
        assert_eq!(
            pkt,
            Data {
                pkt_timestamp: std::time::Duration::from_secs(5),
                isin: "KR4201F32705".to_string(),
                bid_price_1: 0,
                bid_qty_1: 0,
                bid_price_2: 0,
                bid_qty_2: 0,
                bid_price_3: 0,
                bid_qty_3: 0,
                bid_price_4: 0,
                bid_qty_4: 0,
                bid_price_5: 0,
                bid_qty_5: 0,
                ask_price_1: 0,
                ask_qty_1: 0,
                ask_price_2: 0,
                ask_qty_2: 0,
                ask_price_3: 0,
                ask_qty_3: 0,
                ask_price_4: 0,
                ask_qty_4: 0,
                ask_price_5: 0,
                ask_qty_5: 0,
                timestamp: 32399000097,
            }
        );
    }

    #[test]
    fn test_serialize_deserialize_data() {
        let pkt = parse_packet_payload(PKT_OK, std::time::Duration::from_secs(5)).unwrap();

        let serialize = bincode::serialize::<Data>(&pkt).unwrap();
        let deserialize = bincode::deserialize::<Data>(&serialize).unwrap();

        assert_eq!(deserialize, pkt);
    }

    #[test]
    fn test_parse_quote_packet_ko() {
        let pkt = parse_packet_payload(PKT_KO, std::time::Duration::from_secs(5));
        assert!(pkt.is_err());
        assert_eq!(pkt.unwrap_err(), PayloadParseError::SignatureError);
    }
}
