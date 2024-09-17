use parse_quote::{duration_to_offsetdatetime, Data};
use time::format_description::well_known::Rfc3339;

pub fn display_data(data: &Data) -> anyhow::Result<()> {
    println!(
        "{} {} {} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{}",
        duration_to_offsetdatetime(&data.pkt_timestamp).format(&Rfc3339)?,
        duration_to_offsetdatetime(&std::time::Duration::from_nanos(data.timestamp.try_into()?))
            .time(),
        data.isin,
        data.bid_qty_5,
        data.bid_price_5,
        data.bid_qty_4,
        data.bid_price_4,
        data.bid_qty_3,
        data.bid_price_3,
        data.bid_qty_2,
        data.bid_price_2,
        data.bid_qty_1,
        data.bid_price_1,
        data.ask_qty_1,
        data.ask_price_1,
        data.ask_qty_2,
        data.ask_price_2,
        data.ask_qty_3,
        data.ask_price_3,
        data.ask_qty_4,
        data.ask_price_4,
        data.ask_qty_5,
        data.ask_price_5,
    );

    Ok(())
}
