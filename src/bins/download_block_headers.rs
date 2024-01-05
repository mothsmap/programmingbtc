use std::io::Cursor;
use programmingbtc::{
    block::Block,
    network::{NetworkEnvelope, SimpleNode},
    utils::{calculate_new_bits, encode_hex},
};

fn main() {
    // genesis block on mainnet
    let mut previous = Block::genesis_block(false);
    let mut first_epoch_timestamp = previous.timestamp;
    let mut expected_bits = Block::lowest_bits();
    let mut count = 1;
    let mut node = SimpleNode::new("mainnet.programmingbtc.com".into(), 8333, false);
    
    if !node.handshake() {
        return;
    }

    for _ in 0..19 {
        let msg = NetworkEnvelope::new(
            NetworkEnvelope::encode_command("getheaders".into()),
            NetworkEnvelope::get_headers_payload(None, 1, previous.hash(), None),
            false,
        );

        node.send(msg);

        let msg = node.wait_for(vec!["headers".into()]);
        let mut buffer = Cursor::new(msg.payload);
        let headers = NetworkEnvelope::parse_headers_message(&mut buffer);
        for header in headers {
            if !header.check_pow() {
                panic!("bad PoW at block {}", count);
            }

            if header.prev_block != previous.hash() {
                panic!("discontinuous block at {}", count);
            }

            if count % 2016 == 0 {
                let time_diff = previous.timestamp - first_epoch_timestamp;
                expected_bits = calculate_new_bits(&previous.bits, time_diff);
                println!("expected bits: {}", encode_hex(&expected_bits));
                first_epoch_timestamp = header.timestamp;
            }

            if header.bits != expected_bits {
                panic!("bad bits at block: {}", count);
            }

            previous = header;
            count += 1;
        }
    }
}
