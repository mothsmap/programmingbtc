use programmingbtc::{
    private_key::PrivateKey,
    script::Script,
    tx::{Tx, TxIn, TxOut},
    utils::*,
};

use num::{bigint::Sign, BigInt};

fn main() {
    println!("Hello, world! Send me some btc from testnet!");

    // first create a Privatekey
    let passphase = hash256(b"BTC ON TOP!");
    let private_key = PrivateKey::new(BigInt::from_bytes_le(Sign::Plus, &passphase), true, true);
    // print address
    let address = private_key.address();
    // mx5svndN92FECeadidBqpoSt2kJa6NzFQX
    println!("My address: {}", address);

    // input transaction
    // 55e53207aba6c22ad39c8c1a5eb2ad70ebefb563539497401bdb74419d35e996:1
    // amount: 0.01706455
    // https://live.blockcypher.com/btc-testnet/tx/55e53207aba6c22ad39c8c1a5eb2ad70ebefb563539497401bdb74419d35e996/

    // spend
    // return back to facet: https://coinfaucet.eu/en/btc-testnet/
    // target address: mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB
    let tx_input = TxIn::new(
        decode_hex("55e53207aba6c22ad39c8c1a5eb2ad70ebefb563539497401bdb74419d35e996").unwrap(),
        1,
        None,
        None,
    );

    let tx_target = TxOut::new(
        sotachi(0.002),
        Script::p2pkh_script(decode_base58address("mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB")),
    );
    let tx_change = TxOut::new(
        sotachi(0.012),
        Script::p2pkh_script(decode_base58address("mx5svndN92FECeadidBqpoSt2kJa6NzFQX")),
    );

    let mut tx = Tx::new(
        1,
        vec![tx_input],
        vec![tx_target, tx_change],
        0,
        true,
        false,
    );
    println!("签名...");
    if !tx.sign_input(0, &private_key) {
        println!("签名失败！");
    }

    println!("{}", tx);

    let tx_hash = tx.serialize();
    println!("{}", encode_hex(&tx_hash));
    // using the output tx hex, we can broadcast it at: https://blockstream.info/testnet/tx/push
    // broadcast tx id: d9d054b19e57688bace987e7ce1525ee1f63d569562103cf0c1e6d029f852c3d
    // https://live.blockcypher.com/btc-testnet/tx/d9d054b19e57688bace987e7ce1525ee1f63d569562103cf0c1e6d029f852c3d/
}
