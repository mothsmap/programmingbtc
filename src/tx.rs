use crate::op::Command;
use crate::private_key::PrivateKey;
use crate::script::Script;
use crate::utils::{
    bigint_to_bytes, decode_hex, decode_varint, encode_hex, encode_varint, hash256,
};
use anyhow::{bail, Result};
use num::traits::{FromBytes, ToBytes};
use num::{BigInt, FromPrimitive, Zero, ToPrimitive};
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::io::{Cursor, Read, Seek};

// 交易输入
#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_tx: Vec<u8>, // 上一个交易的哈希
    pub prev_index: u32,  // 上一个交易的第几个输出
    pub script_sig: Script,
    pub sequence: u32, //
}

impl TxIn {
    pub fn new(
        prev_tx: Vec<u8>,
        prev_index: u32,
        script: Option<Script>,
        sequence: Option<u32>,
    ) -> TxIn {
        TxIn {
            prev_tx,
            prev_index,
            script_sig: if script.is_none() {
                Script::new(vec![])
            } else {
                script.unwrap()
            },
            sequence: if sequence.is_none() {
                0xffffffff
            } else {
                sequence.unwrap()
            },
        }
    }

    pub fn parse<T: Read + Seek>(buffer: &mut T) -> Result<TxIn> {
        println!("parse tx input ...");

        // 前32byte是上一个交易的哈希，以小端存储
        let mut prev_tx = [0u8; 32];
        buffer.read_exact(&mut prev_tx)?;
        prev_tx.reverse();
        println!("prev hash: {}", encode_hex(&prev_tx.to_vec()));

        // 第几个输出, 4byte整数存储，小端存储
        let mut prev_index_bytes = [0u8; 4];
        buffer.read_exact(&mut prev_index_bytes)?;
        let prev_index = u32::from_le_bytes(prev_index_bytes);
        println!("prev index: {}", prev_index);

        // script_sig
        let script_sig = Script::parse(buffer).unwrap();
        println!("script: {}", script_sig);

        // sequence 4 byte整数，小端存储
        let mut sequence_bytes = [0u8; 4];
        buffer.read_exact(&mut sequence_bytes)?;
        let sequence = u32::from_le_bytes(sequence_bytes);
        println!("sequence: {}", sequence);

        Ok(TxIn {
            prev_tx: prev_tx.to_vec(),
            prev_index,
            script_sig,
            sequence,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];

        // 上一个交易id, 32 bytes, little-endian
        let mut prev_tx_bytes: Vec<u8> = self.prev_tx.clone();
        prev_tx_bytes.reverse();
        result.append(&mut prev_tx_bytes);

        // 上一个交易输出，4 bytes，little-endian
        result.append(&mut self.prev_index.to_le_bytes().to_vec());

        // script
        result.append(&mut self.script_sig.serialize());

        // sequence, 4 bytes
        result.append(&mut self.sequence.to_le_bytes().to_vec());

        result
    }

    // 获取上一个交易的内容
    pub fn fetch_tx(&self, tx_fetcher: &mut TxFetcher, testnet: bool) -> Tx {
        tx_fetcher
            .fetch(encode_hex(&self.prev_tx), testnet, false)
            .clone()
    }

    // 获取输入的sotashi
    pub fn value(&self, tx_fetcher: &mut TxFetcher, testnet: bool) -> u64 {
        let tx = self.fetch_tx(tx_fetcher, testnet);
        tx.outputs[self.prev_index as usize].amount
    }

    // 获取输入的 locked-box;(需要解决的问题)
    pub fn script_pubkey(&self, tx_fetcher: &mut TxFetcher, testnet: bool) -> Script {
        let tx = self.fetch_tx(tx_fetcher, testnet);
        tx.outputs[self.prev_index as usize].script_pubkey.clone()
    }
}

impl fmt::Display for TxIn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}:{}\n", encode_hex(&self.prev_tx), self.prev_index)?;
        write!(f, "{}", self.script_sig)
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub amount: u64,
    pub script_pubkey: Script,
}

impl TxOut {
    pub fn new(amount: u64, script_pubkey: Script) -> TxOut {
        TxOut {
            amount,
            script_pubkey,
        }
    }

    pub fn parse<T: Read + Seek>(buffer: &mut T) -> Result<TxOut> {
        let mut amount_bytes = [0u8; 8];
        buffer.read_exact(&mut amount_bytes)?;

        let amount = u64::from_le_bytes(amount_bytes);

        let script_pubkey = Script::parse(buffer).unwrap();
        Ok(TxOut {
            amount,
            script_pubkey,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        // amount, 8 bytes
        let mut result = self.amount.to_le_bytes().to_vec();

        // script serialization
        result.append(&mut self.script_pubkey.serialize());

        result
    }
}

impl fmt::Display for TxOut {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.amount, self.script_pubkey)
    }
}

// 交易结构体
#[derive(Debug, Clone)]
pub struct Tx {
    pub version: u32,        // 版本号
    pub inputs: Vec<TxIn>,   // 输入
    pub outputs: Vec<TxOut>, // 输出
    // locktime > 500,000,000 表示时间戳，否则表示区块高度
    pub locktime: u32, // 锁定时间
    pub testnet: bool, // 是否测试网
}

impl Tx {
    pub fn new(
        version: u32,
        txin: Vec<TxIn>,
        txout: Vec<TxOut>,
        locktime: u32,
        testnet: bool,
    ) -> Tx {
        Tx {
            version,
            inputs: txin,
            outputs: txout,
            locktime,
            testnet,
        }
    }

    pub fn parse<T: Read + Seek>(buffer: &mut T, testnet: bool) -> Result<Tx> {
        println!("parse tx ...");

        // 4 byte little-endian integer
        let mut version_bytes = [0u8; 4];
        buffer.read_exact(&mut version_bytes)?;
        let version = u32::from_le_bytes(version_bytes);
        println!("version: {}", version);

        // inputs
        let inputs = decode_varint(buffer);
        println!("#inputs = {}", inputs);
        let mut tx_inputs: Vec<TxIn> = vec![];
        for _ in 0..inputs {
            tx_inputs.push(TxIn::parse(buffer).unwrap());
        }

        // outputs
        let outputs = decode_varint(buffer);
        println!("#outputs = {}", outputs);
        let mut tx_outputs: Vec<TxOut> = vec![];
        for _ in 0..outputs {
            tx_outputs.push(TxOut::parse(buffer).unwrap());
        }

        // timelock
        let mut locktime_bytes = [0u8; 4];
        buffer.read_exact(&mut locktime_bytes)?;
        let locktime = u32::from_le_bytes(locktime_bytes);
        println!("locktime = {}", locktime);

        Ok(Tx {
            version,
            inputs: tx_inputs,
            outputs: tx_outputs,
            locktime,
            testnet,
        })
    }

    // 二进制交易哈希
    pub fn hash(&self) -> Vec<u8> {
        let mut h = hash256(&self.serialize());
        // legacy serialization
        h.reverse();
        h
    }

    // 可读交易哈希
    pub fn id(&self) -> String {
        encode_hex(&self.hash())
    }

    // 序列化交易对象
    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];

        // version, 小端编码，4 bytes
        // version通常为1，使用OP_CHECKSEQUENCEVERIFY时version为2
        result.append(&mut self.version.to_le_bytes().to_vec());

        // inputs
        result.append(&mut encode_varint(self.inputs.len() as u64));
        for input in &self.inputs {
            result.append(&mut input.serialize());
        }

        // outputs
        result.append(&mut encode_varint(self.outputs.len() as u64));
        for output in &self.outputs {
            result.append(&mut output.serialize());
        }

        // locktime
        result.append(&mut self.locktime.to_le_bytes().to_vec());

        result
    }

    // 返回交易手续费，单位为satoshi
    pub fn fee(&self, tx_fetcher: &mut TxFetcher) -> u64 {
        let mut result = 0;
        for input in &self.inputs {
            result += input.value(tx_fetcher, self.testnet);
        }
        for output in &self.outputs {
            result -= output.amount;
        }
        result
    }

    // 获得待签名的hash
    // 返回对于特定input的签名hash代表的数字
    // 签名hash是对tx的序列化进行修改（清空所有input的scriptSig，替换待签名input的SciptPubkey），然后进行hash256操作
    pub fn sig_hash(&self, input_index: u32) -> BigInt {
        let mut tx_fetcher = TxFetcher::new();
        let mut result: Vec<u8> = vec![];

        // version, 小端编码，4 bytes
        // version通常为1，使用OP_CHECKSEQUENCEVERIFY时version为2
        result.append(&mut self.version.to_le_bytes().to_vec());

        // inputs
        result.append(&mut encode_varint(self.inputs.len() as u64));
        let mut cnt = 0;
        for input in &self.inputs {
            let txin = if cnt == input_index {
                // 替换ScriptPubkey
                TxIn::new(
                    input.prev_tx.clone(),
                    input.prev_index,
                    Some(input.script_pubkey(&mut tx_fetcher, self.testnet)),
                    Some(input.sequence),
                )
            } else {
                // 使用空的ScriptSig
                TxIn::new(
                    input.prev_tx.clone(),
                    input.prev_index,
                    None,
                    Some(input.sequence),
                )
            };
            result.append(&mut txin.serialize());
            cnt += 1;
        }

        // outputs
        result.append(&mut encode_varint(self.outputs.len() as u64));
        for output in &self.outputs {
            result.append(&mut output.serialize());
        }

        // locktime
        result.append(&mut self.locktime.to_le_bytes().to_vec());

        // SIGHASH_ALL, little-endian
        result.append(&mut 1u32.to_le_bytes().to_vec());

        // hash256 and to int
        BigInt::from_be_bytes(&hash256(&result))
    }

    // 返回特定输入的签名是否有效
    pub fn verify_input(&self, input_index: u32) -> bool {
        // for this input
        let tx_in = self.inputs[input_index as usize].clone();
        let mut tx_fetcher = TxFetcher::new();
        // ScriptSig + ScriptPubkey
        let combined_sig =
            (&tx_in).script_sig.clone() + (&tx_in).script_pubkey(&mut tx_fetcher, self.testnet);
        // get sig_hash for this input and evaluate
        combined_sig.evaluate(self.sig_hash(input_index))
    }

    pub fn sign_input(&mut self, input_index: u32, private_key: &PrivateKey) -> bool {
        // get the signature hash (z)
        let z = self.sig_hash(input_index);

        // get DER signature of z from private key
        let signature = private_key.sign(z);
        let mut der_signature = signature.der();

        // append the SIGHASH_ALL to der, big-edian, only one byte!!!
        der_signature.append(&mut 1u8.to_be_bytes().to_vec());

        // calculate the sec
        let sec = private_key.point.sec(private_key.compressed);

        // initialize a new script with [sig, sec] as the cmds
        let script_sig = Script::new(vec![Command::Element(der_signature), Command::Element(sec)]);
        self.inputs[input_index as usize].script_sig = script_sig;

        self.verify_input(input_index)
    }

    pub fn is_coinbase(&self) -> bool {
        // coinbase只有一个输入
        if self.inputs.len() != 1 {
            return false;
        }

        // 获取第一个输入
        let input = self.inputs[0].clone();

        // 确保第一个输入的prev_tx是32个0字节
        let want = [0u8; 32];
        if input.prev_tx != want.to_vec() {
            return false;
        }

        // 确保第一个输入的prev_index是0xffffffff
        if input.prev_index != 0xffffffff {
            return false;
        }
        true
    }

    pub fn coinbase_height(&self) -> Option<u32> {
        if !self.is_coinbase() {
            return None;
        }

        let first_cmd = &self.inputs[0].script_sig.commands[0];
        match first_cmd {
            Command::Element(e) => BigInt::from_le_bytes(e).to_u32(),
            Command::OP(o) => None
        }
    }
}

impl fmt::Display for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut tx_ins = String::from("");
        for tx_in in &self.inputs {
            tx_ins += &tx_in.to_string();
            tx_ins += "\n";
        }

        let mut tx_outs = String::from("");
        for tx_out in &self.outputs {
            tx_outs += &tx_out.to_string();
            tx_outs += "\n";
        }

        write!(
            f,
            "tx: {}\tversion: {}\ntx_ins:\n{}\ntx_outs:\n{}\nlocktime: {}",
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime
        )
    }
}

struct TxFetcher {
    // tx-hash -> tx
    pub cache: HashMap<String, Tx>,
}

impl TxFetcher {
    pub fn new() -> Self {
        TxFetcher {
            cache: HashMap::new(),
        }
    }

    pub fn url(testnet: bool) -> String {
        match testnet {
            true => "https://blockstream.info/testnet/api".into(),
            false => "https://blockstream.info/api".into(),
        }
    }

    pub fn fetch(&mut self, tx_id: String, testnet: bool, fresh: bool) -> &Tx {
        if fresh || !self.cache.contains_key(&tx_id) {
            let url = format!("{}/tx/{}/hex", TxFetcher::url(testnet), &tx_id);
            println!("request tx: {}", url);
            let response = reqwest::blocking::get(url).unwrap().text().unwrap();
            let bytes = decode_hex(response.trim()).unwrap();

            let mut tx: Tx;
            if bytes[4] == 0 {
                // coinbase tx?
                let mut left = bytes[..4].to_vec();
                let mut right = bytes[6..].to_vec();
                left.append(&mut right);
                let mut cursor = Cursor::new(left);

                tx = Tx::parse(&mut cursor, testnet).unwrap();
                let locktime_bytes: [u8; 4] = bytes[bytes.len() - 4..].try_into().unwrap();
                tx.locktime = u32::from_le_bytes(locktime_bytes);
            } else {
                let mut cursor = Cursor::new(bytes);
                tx = Tx::parse(&mut cursor, testnet).unwrap();
            }
            if tx.id() != tx_id {
                panic!("not the same id: {} vs {}", tx.id(), &tx_id);
            }
            self.cache.entry(tx_id.clone()).or_insert(tx);
        }

        self.cache.get(&tx_id).unwrap()
    }
}

mod tests {
    use crate::utils::decode_base58address;

    use super::*;

    #[test]
    pub fn test_parse_version() {
        let raw_tx = decode_hex("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
        let mut cursor = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut cursor, false).unwrap();
        println!("{}", tx);
        assert!(tx.version == 1);
    }

    #[test]
    pub fn test_parse_inputs() {
        let raw_tx = decode_hex("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
        let mut cursor = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut cursor, false).unwrap();
        assert!(tx.inputs.len() == 1);
        let want =
            decode_hex("d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81").unwrap();
        assert!(tx.inputs[0].prev_tx == want);
        assert!(tx.inputs[0].prev_index == 0);

        let want = decode_hex("6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a").unwrap();
        assert!(tx.inputs[0].script_sig.serialize() == want);
        assert!(tx.inputs[0].sequence == 0xfffffffe);
    }

    #[test]
    pub fn test_parse_outputs() {
        let raw_tx = decode_hex("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
        let mut cursor = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut cursor, false).unwrap();
        assert!(tx.outputs.len() == 2);

        let want = 32454049;
        assert!(tx.outputs[0].amount == want);
        let want = decode_hex("1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac").unwrap();
        assert!(tx.outputs[0].script_pubkey.serialize() == want);

        let want = 10011545;
        assert!(tx.outputs[1].amount == want);
        let want = decode_hex("1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac").unwrap();
        assert!(tx.outputs[1].script_pubkey.serialize() == want);
    }

    #[test]
    pub fn test_parse_locktime() {
        let raw_tx = decode_hex("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
        let mut cursor = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut cursor, false).unwrap();
        assert!(tx.locktime == 410393);
    }

    #[test]
    pub fn test_fee() {
        let raw_tx = decode_hex("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
        let mut cursor = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut cursor, false).unwrap();
        let mut tx_fetcher = TxFetcher::new();
        let f = tx.fee(&mut tx_fetcher);
        assert!(f == 40000);

        let raw_tx = decode_hex("010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600").unwrap();
        let mut cursor = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut cursor, false).unwrap();
        assert!(tx.fee(&mut tx_fetcher) == 140500);
    }

    #[test]
    pub fn test_ch05_exercise5() {
        let raw_tx = decode_hex("010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600").unwrap();
        let mut cursor = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut cursor, false).unwrap();
        println!("ScriptSig from second input: {}", tx.inputs[1].script_sig);
        println!(
            "ScriptPubKey from first output: {}",
            tx.outputs[0].script_pubkey
        );
        println!("amount from second output: {}", tx.outputs[1].amount);
    }

    #[test]
    pub fn test_ch07_create_sign_tx() {
        let prev_tx_bytes =
            decode_hex("0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299").unwrap();
        let prev_index = 13;
        let tx_in = TxIn::new(prev_tx_bytes, prev_index, None, None);

        let change_amount = (0.33 * 100000000.0) as u64;
        let change_h160 = decode_base58address("mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2");
        let change_script = Script::p2pkh_script(change_h160);
        let change_output = TxOut::new(change_amount, change_script);

        let target_amount = (0.1 * 100000000.0) as u64;
        let target_h160 = decode_base58address("mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf");
        let target_script = Script::p2pkh_script(target_h160);
        let target_output = TxOut::new(target_amount, target_script);

        let mut tx = Tx::new(1, vec![tx_in], vec![change_output, target_output], 0, true);
        println!("tx: {}", tx);

        // sign
        let private_key = PrivateKey::new(BigInt::from_u32(8675309).unwrap(), true, true);
        assert!(tx.sign_input(0, &private_key));

        println!("signed tx: {}", tx);

        let want = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006a47304402207db2402a3311a3b845b038885e3dd889c08126a8570f26a844e3e4049c482a11022010178cdca4129eacbeab7c44648bf5ac1f9cac217cd609d216ec2ebc8d242c0a012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67feffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        // assert!(want == encode_hex(&tx.serialize()));
        println!("{}", want);
        println!("{}", encode_hex(&tx.serialize()));
    }

    #[test]
    pub fn test_is_coinbase() {
        let raw_tx = decode_hex("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000").unwrap();
        let mut buffer = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut buffer, true).unwrap();
        assert!(tx.is_coinbase());
    }

    #[test]
    pub fn test_coinbase_height() {
        let raw_tx = decode_hex("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000").unwrap();
        let mut buffer = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut buffer, true).unwrap();
        assert!(tx.coinbase_height() == Some(465879));

        let raw_tx = decode_hex("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
        let mut buffer = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut buffer, true).unwrap();
        assert!(tx.coinbase_height() == None);



    }
}
