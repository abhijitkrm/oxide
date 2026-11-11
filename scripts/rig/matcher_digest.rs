// Matcher-side half of the corpus differential used by scripts/rig-bench.sh.
// Replays a vectorgen corpus through matcher-rust's OrderBook and prints the
// same order-sensitive digests `corpus --digest` prints for the Oxide engine:
// an FNV-1a over every trade's (price, qty), and over the final book as
// (side, tick, qty) with FIFO preserved within a level.
use matcher::jsonflat::{parse_command, parse_header};
use matcher::*;

struct Dig {
    d: u64,
    trades: u64,
}
impl Sink for Dig {
    fn on_event(&mut self, _seq: u64, ev: &Event) {
        if let Event::Trade { price, qty, .. } = ev {
            for w in [*price as u64, *qty] {
                self.d = (self.d ^ w).wrapping_mul(0x0100_0000_01B3);
            }
            self.trades += 1;
        }
    }
}

fn main() {
    let prefix = std::env::args().nth(1).expect("usage: matcher-digest <corpus-prefix>");
    let mut book = None;
    let mut sink = Dig { d: 0xCBF2_9CE4_8422_2325, trades: 0 };
    for part in ["setup", "run"] {
        let text = std::fs::read_to_string(format!("{prefix}.{part}.cmd.jsonl")).unwrap();
        let mut lines = text.lines();
        let (pmin, pmax, max_orders, index) = parse_header(lines.next().unwrap());
        let b = book.get_or_insert_with(|| {
            OrderBook::new(BookConfig { price_min: pmin, price_max: pmax, max_orders, index })
        });
        for l in lines.filter(|l| !l.trim().is_empty()) {
            b.apply(parse_command(l).unwrap(), &mut sink);
        }
    }
    let b = book.unwrap();
    let mut v: Vec<(u8, u64, u64)> = b
        .resting_orders()
        .iter()
        .map(|r| (u8::from(r.side == Side::Ask), r.price as u64, r.qty))
        .collect();
    v.sort_by_key(|&(s, t, _)| (s, t));
    let mut bd = 0xCBF2_9CE4_8422_2325u64;
    for (s, t, q) in &v {
        for w in [*s as u64, *t, *q] {
            bd = (bd ^ w).wrapping_mul(0x0100_0000_01B3);
        }
    }
    println!(
        "trades={} trade_digest={:016x} resting={} book_digest={bd:016x}",
        sink.trades, sink.d, v.len()
    );
}
