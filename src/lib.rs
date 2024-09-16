use nom::{
    bytes::complete::{tag, take},
    error::{Error, ErrorKind, ParseError},
    IResult,
};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime, Time};

const PACKETS_SIGNATURE: &str = "B6034";

#[derive(Debug, PartialEq, Eq)]
struct Data {
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
    isin: String,
    bid_price_1: i32,
    bid_qty_1: i32,
    bid_price_2: i32,
    bid_qty_2: i32,
    bid_price_3: i32,
    bid_qty_3: i32,
    bid_price_4: i32,
    bid_qty_4: i32,
    bid_price_5: i32,
    bid_qty_5: i32,
    ask_price_1: i32,
    ask_qty_1: i32,
    ask_price_2: i32,
    ask_qty_2: i32,
    ask_price_3: i32,
    ask_qty_3: i32,
    ask_price_4: i32,
    ask_qty_4: i32,
    ask_price_5: i32,
    ask_qty_5: i32,
    timestamp: Duration,
}

// fn parse_quote_packet(input: &[u8]) -> IResult<&[u8], Data> {
//     let (input, magic) = tag("B6034")(input)?;
//     dbg!(magic);
//
//     todo!();
// }

// Custom error type to hold a message and optionally the `nom::ErrorKind`
#[derive(Debug, PartialEq, Eq)]
struct CustomError<'a> {
    input: &'a [u8],
    message: &'static str,
}

// Implement `ParseError` for `CustomError`
impl<'a> ParseError<&'a [u8]> for CustomError<'a> {
    fn from_error_kind(input: &'a [u8], _kind: ErrorKind) -> Self {
        CustomError {
            input,
            message: "Error occurred during parsing",
        }
    }

    fn append(input: &'a [u8], _kind: ErrorKind, other: Self) -> Self {
        other
    }

    fn from_char(input: &'a [u8], _: char) -> Self {
        CustomError {
            input,
            message: "Unexpected character during parsing",
        }
    }
}

// Function to parse the quote packet with a custom error
fn parse_quote_packet(input: &[u8]) -> IResult<&[u8], Data, CustomError> {
    // Try to match the magic tag "B6034"
    let (input, _signature) = match tag::<&str, &[u8], CustomError>(PACKETS_SIGNATURE)(input) {
        Ok((remaining_input, magic)) => (remaining_input, magic),
        Err(_) => {
            // Return a custom error message
            return Err(nom::Err::Error(CustomError {
                input,
                message: "Expected 'B6034' but didn't find it",
            }));
        }
    };

    let (input, isin) = take(12u8)(input)?;
    let isin = std::str::from_utf8(isin).unwrap();

    let (input, _) = take(12u8)(input)?;

    let (input, bid_price_1) = take(5u8)(input)?;
    let bid_price_1 = std::str::from_utf8(bid_price_1)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, bid_qty_1) = take(7u8)(input)?;
    let bid_qty_1 = std::str::from_utf8(bid_qty_1)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, bid_price_2) = take(5u8)(input)?;
    let bid_price_2 = std::str::from_utf8(bid_price_2)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, bid_qty_2) = take(7u8)(input)?;
    let bid_qty_2 = std::str::from_utf8(bid_qty_2)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, bid_price_3) = take(5u8)(input)?;
    let bid_price_3 = std::str::from_utf8(bid_price_3)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, bid_qty_3) = take(7u8)(input)?;
    let bid_qty_3 = std::str::from_utf8(bid_qty_3)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, bid_price_4) = take(5u8)(input)?;
    let bid_price_4 = std::str::from_utf8(bid_price_4)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, bid_qty_4) = take(7u8)(input)?;
    let bid_qty_4 = std::str::from_utf8(bid_qty_4)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, bid_price_5) = take(5u8)(input)?;
    let bid_price_5 = std::str::from_utf8(bid_price_5)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, bid_qty_5) = take(7u8)(input)?;
    let bid_qty_5 = std::str::from_utf8(bid_qty_5)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, _) = take(7u8)(input)?;

    let (input, ask_price_1) = take(5u8)(input)?;
    let ask_price_1 = std::str::from_utf8(ask_price_1)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, ask_qty_1) = take(7u8)(input)?;
    let ask_qty_1 = std::str::from_utf8(ask_qty_1)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, ask_price_2) = take(5u8)(input)?;
    let ask_price_2 = std::str::from_utf8(ask_price_2)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, ask_qty_2) = take(7u8)(input)?;
    let ask_qty_2 = std::str::from_utf8(ask_qty_2)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, ask_price_3) = take(5u8)(input)?;
    let ask_price_3 = std::str::from_utf8(ask_price_3)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, ask_qty_3) = take(7u8)(input)?;
    let ask_qty_3 = std::str::from_utf8(ask_qty_3)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, ask_price_4) = take(5u8)(input)?;
    let ask_price_4 = std::str::from_utf8(ask_price_4)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, ask_qty_4) = take(7u8)(input)?;
    let ask_qty_4 = std::str::from_utf8(ask_qty_4)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, ask_price_5) = take(5u8)(input)?;
    let ask_price_5 = std::str::from_utf8(ask_price_5)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let (input, ask_qty_5) = take(7u8)(input)?;
    let ask_qty_5 = std::str::from_utf8(ask_qty_5)
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let (input, _) = take(50u8)(input)?;

    let (input, hour_10) = take(1u8)(input)?;
    let hour_10 = std::str::from_utf8(hour_10)
        .unwrap()
        .parse::<i64>()
        .unwrap();

    let (input, hour) = take(1u8)(input)?;
    let hour = std::str::from_utf8(hour).unwrap().parse::<i64>().unwrap();

    let (input, minute_10) = take(1u8)(input)?;
    let minute_10 = std::str::from_utf8(minute_10)
        .unwrap()
        .parse::<i64>()
        .unwrap();

    let (input, minute) = take(1u8)(input)?;
    let minute = std::str::from_utf8(minute).unwrap().parse::<i64>().unwrap();

    let (input, seconde_10) = take(1u8)(input)?;
    let seconde_10 = std::str::from_utf8(seconde_10)
        .unwrap()
        .parse::<i64>()
        .unwrap();

    let (input, seconde) = take(1u8)(input)?;
    let seconde = std::str::from_utf8(seconde)
        .unwrap()
        .parse::<i64>()
        .unwrap();

    let (input, micro_seconde_10) = take(1u8)(input)?;
    let micro_seconde_10 = std::str::from_utf8(micro_seconde_10)
        .unwrap()
        .parse::<i64>()
        .unwrap();

    let (input, micro_seconde) = take(1u8)(input)?;
    let micro_seconde = std::str::from_utf8(micro_seconde)
        .unwrap()
        .parse::<i64>()
        .unwrap();

    let (input, eom) = take(1u8)(input)?;

    let hour = hour_10 * 10 + hour;
    let minute = minute_10 * 10 + minute;
    let seconde = seconde_10 * 10 + seconde;
    let micro_seconde = micro_seconde_10 * 10 + micro_seconde;

    let timestamp = Duration::hours(hour)
        + Duration::minutes(minute)
        + Duration::seconds(seconde)
        + Duration::microseconds(micro_seconde);

    let data = Data {
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
        timestamp,
    };

    dbg!(&data);
    Ok((input, data))
}

#[cfg(test)]
mod test {

    use pretty_assertions::assert_eq;
    use time::Duration;

    use crate::{CustomError, Data};

    use super::parse_quote_packet;

    #[test]
    fn test_parse_quote_packet_ok() {
        const PKT_OK: &[u8] = &[
            0x42, 0x36, 0x30, 0x33, 0x34, 0x4b, 0x52, 0x34, 0x32, 0x30, 0x31, 0x46, 0x33, 0x32,
            0x37, 0x30, 0x35, 0x30, 0x30, 0x31, 0x31, 0x30, 0x30, 0x30, 0x32, 0x32, 0x36, 0x38,
            0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x37, 0x32, 0x32, 0x34, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x39, 0x34, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x33, 0x36, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x35, 0x39,
            0x35, 0x39, 0x39, 0x37, 0xff,
        ];

        let pkt = parse_quote_packet(PKT_OK);

        assert!(pkt.is_ok());

        let pkt = pkt.unwrap();

        assert_eq!(
            pkt,
            (
                &[] as &[u8],
                Data {
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
                    timestamp: Duration::seconds(32399) + Duration::nanoseconds(97000),
                }
            )
        );
    }

    #[test]
    fn test_parse_quote_packet_ko() {
        const PKT_KO: &[u8] = &[
            0x42, 0x36, 0x30, 0x31, 0x34, 0x4b, 0x52, 0x34, 0x31, 0x30, 0x31, 0x46, 0x33, 0x30,
            0x30, 0x30, 0x38, 0x30, 0x31, 0x31, 0x30, 0x30, 0x31, 0x34, 0x37, 0x34, 0x37, 0x20,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x31, 0x31, 0x36, 0x30, 0x31, 0x20, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x32, 0x30, 0x38, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x34, 0x38,
            0x38, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x35, 0x39, 0x35, 0x39, 0x39,
            0x38, 0xff,
        ];

        let pkt = parse_quote_packet(PKT_KO);
        assert!(pkt.is_err());
        assert_eq!(
            pkt.unwrap_err(),
            nom::Err::Error(CustomError {
                input: PKT_KO,
                message: "Expected 'B6034' but didn't find it"
            })
        );
    }
}
