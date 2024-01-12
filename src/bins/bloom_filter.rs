use std::io::Cursor;

use num::BigInt;
use programmingbtc::{
    bloom_filter::BloomFilter,
    merkle_block::MerkleBlock,
    network::{BloomFilterDataTyle, NetworkCommand, NetworkEnvelope, SimpleNode},
    private_key::PrivateKey,
    script::Script,
    tx::{Tx, TxIn, TxOut},
    utils::{decode_base58, decode_hex, encode_hex, hash256},
};

pub fn main() {
    let testnet = true;
    let last_block_hex = "00000000000538d5c2246336644f9a4956551afb44ba47278759ec55ea912e19";
    let secrect = BigInt::from_bytes_le(num::bigint::Sign::Plus, &hash256(b"Jimmy Song"));
    let private_key = PrivateKey::new(secrect, true, testnet);
    let addr = private_key
        .point
        .address(private_key.compressed, private_key.testnet);
    let h160 = decode_base58(&addr);

    let mut node = SimpleNode::new("localhost".to_owned(), 8333, false);

    // <1> create bloom-filter of 30 bytes, using 5 hashing functions
    let mut bf = BloomFilter::new(30, 5, 90210);
    // <2> filter for address
    bf.add(&h160);

    node.handshake();

    // <3> send filterload
    node.send(NetworkEnvelope::new(
        NetworkCommand::Filterload,
        bf.filterload_payload(1),
        testnet,
    ));

    let start_block = decode_hex(last_block_hex).unwrap();
    // <4> get the block headers after `last_block_hex`
    node.send(NetworkEnvelope::new(
        NetworkCommand::Getheaders,
        NetworkEnvelope::get_headers_payload(None, 1, start_block, None),
        testnet,
    ));

    // <5> for Merkle blocks that may have transactions of interest
    let mut get_data: Vec<(BloomFilterDataTyle, Vec<u8>)> = vec![];

    let msg = node.wait_for(vec![NetworkCommand::Headers]);
    let headers = NetworkEnvelope::parse_headers_message(&mut Cursor::new(msg.payload));
    for b in headers {
        if !b.check_pow() {
            panic!("proof of work is invalid")
        }
        // <6> we request a merkle block proving transactions of interest to us are included
        // most blocks will probably be complte misses
        get_data.push((BloomFilterDataTyle::FilteredBlockDataType, b.hash()));
    }
    // <7> the getdata message asks for 2000 merkle blocks after the block defined by `last_block_hex`
    node.send(NetworkEnvelope::new(
        NetworkCommand::Getdata,
        NetworkEnvelope::get_data_payload(&get_data),
        testnet,
    ));

    //
    let mut found = false;
    let mut prev_tx: Vec<u8> = vec![];
    let mut prev_index: u32 = 0;
    let mut prev_amount: u64 = 0;
    loop {
        if found {
            break;
        }
        // <8> wait for the merkleblock command, which proves inclusion
        // and the tx command, which gives us the transactions we interested
        let msg = node.wait_for(vec![NetworkCommand::MerkleBlock]);
        if msg.command == NetworkCommand::MerkleBlock {
            let merkle_block = MerkleBlock::parse(&mut Cursor::new(msg.payload));
            // <9> check that the merkle block proves transaction inclusion
            if !merkle_block.is_valid() {
                panic!("invalid merkle proof");
            }
        } else {
            // <10>
            let tx = Tx::parse(&mut Cursor::new(msg.payload), testnet).unwrap();
            for (i, tx_out) in tx.outputs.iter().enumerate() {
                if tx_out.script_pubkey.address(testnet) == addr {
                    // found the utxo; set prev_tx, prev_index, and tx
                    prev_tx = tx.hash();
                    prev_index = i as u32;
                    prev_amount = tx_out.amount;
                    println!("found: {}:{}", encode_hex(&prev_tx), prev_index);
                    found = true;
                }
            }
        }
    }

    // use the founding utxo to create an transaction
    if !found {
        return;
    }

    let target_address = "mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv";
    let target_h160 = decode_base58(target_address);
    let target_script = Script::p2pkh_script(target_h160);
    let fee = 5000;

    // create the TxIn
    let tx_in = TxIn::new(prev_tx, prev_index, None, None);
    // calculae the output amount
    let output_amount = prev_amount - fee;

    // create a new TxOut to the target script with the output amount
    let tx_out = TxOut::new(output_amount, target_script);

    // create a new transaction with the one input and one output
    let mut tx = Tx::new(1, vec![tx_in], vec![tx_out], 0, testnet, false);

    // sign the only input
    if !tx.sign_input(0, &private_key) {
        panic!("sign tx fail!");
    }

    // serialize and hex to see
    println!("{}", encode_hex(&tx.serialize()));

    // send this signed transaction on the network
    node.send(NetworkEnvelope::new(
        NetworkCommand::Tx,
        tx.serialize(),
        testnet,
    ));

    // wait a seconds
    //

    // ask for this transaction from the other node
    let get_data = vec![(BloomFilterDataTyle::TxDataType, tx.hash())];

    // send the message
    node.send(NetworkEnvelope::new(
        NetworkCommand::Getdata,
        NetworkEnvelope::get_data_payload(&get_data),
        testnet,
    ));

    // wait for Tx response
    let msg = node.wait_for(vec![NetworkCommand::Tx]);
    // if the received tx has the same id as our tx, we are done!
    let receive_tx = Tx::parse(&mut Cursor::new(msg.payload), testnet).unwrap();
    if receive_tx.id() == tx.id() {
        println!("success!")
    }
}
