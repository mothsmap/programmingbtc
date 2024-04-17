use chrono::prelude::*;
use programmingbtc::{
    block::Block,
    network::{NetworkCommand, NetworkEnvelope, SimpleNode},
    utils::encode_hex,
};
use std::process::Command;
use std::io::Cursor;
use std::{
    io::{self, BufRead, BufReader, Write},
    process::Child,
    env,
};

pub fn wait_external_command(child: &mut Child) {
    let stdout = child.stdout.as_mut().unwrap();
    let reader = BufReader::new(stdout);

    reader
        .lines()
        .filter_map(|line| line.ok())
        .for_each(|line| println!("{}", line));

    let exit_code = child.wait().unwrap();
    if !exit_code.success() {
        println!("external command fail");
    }
}

fn deploy_rune(yaml_file: &String, fee_rate: &String) {
    let output = Command::new("ord")
        .arg("wallet")
        .arg("batch")
        .arg("--fee-rate")
        .arg(fee_rate)
        .arg("--batch")
        .arg(yaml_file)
        .output()
        .unwrap();

    println!("status: {}", output.status);
    io::stdout().write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stderr).unwrap();
}


fn main() {
    let args: Vec<String> = env::args().collect();
    let batch_yaml = args[1].clone();
    let fee_rate = args[2].clone();
    let target_block: u32 = args[3].parse().unwrap();

    let testnet = false;
    // genesis block on mainnet
    let mut previous = Block::genesis_block(testnet);
    let mut count = 1;
    let mut node = SimpleNode::new(
        "localhost".into(),
        if testnet { 18333 } else { 8333 },
        testnet,
    );

    if !node.handshake() {
        return;
    }
    println!("handshake success!");

    loop {
        let msg = NetworkEnvelope::new(
            NetworkCommand::Getheaders,
            NetworkEnvelope::get_headers_payload(None, 1, previous.hash(), None),
            testnet,
        );

        node.send(msg);

        let msg = node.wait_for(vec![NetworkCommand::Headers]);
        let mut buffer = Cursor::new(msg.payload);
        let headers = NetworkEnvelope::parse_headers_message(&mut buffer);
        if headers.len() > 0 {
            println!("{}, #headers: {}, first block: {}", Utc::now().to_string(), headers.len(), encode_hex(&headers[0].hash()));
        }
        for header in headers {
            if count > target_block - 400 {
                println!("block #{}: {}", count, encode_hex(&header.hash()));
            }

            if count + 1 == target_block {
                deploy_rune(&batch_yaml, &fee_rate);
            }

            previous = header;
            count += 1;
        }
    }
}
