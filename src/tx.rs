use crate::utils::{hash256, encode_hex, encode_varint, decode_hex, bigint_to_bytes, decode_varint};
use crate::script::Script;
use anyhow::{Result, bail};
use num::traits::ToBytes;
use num::{BigInt, FromPrimitive};
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::io::{Read, Seek, Cursor};

// 交易输入
#[derive(Debug, Clone)]
struct TxIn {
    pub prev_tx: Vec<u8>,    // 上一个交易的哈希
    pub prev_index: u64,    // 上一个交易的第几个输出
    pub script_sig: Script,
    pub sequence: u32,        //
}

impl TxIn {
    pub fn new(prev_tx: Vec<u8>, prev_index: u64, script: Script, sequence: u32) -> TxIn {
        TxIn { prev_tx, prev_index, script_sig: script, sequence }
    }
    
    pub fn parse<T: Read + Seek>(buffer: &mut T) -> Result<TxIn> {
        // 前32byte是上一个交易的哈希，以小端存储
        let mut prev_tx = [0u8; 32];
        buffer.read_exact(&mut prev_tx)?;
        prev_tx.reverse();

        // 第几个输出,变长整数存储，小端存储
        let prev_index = decode_varint(buffer);

        // script_sig
        let script_sig = Script::parse(buffer).unwrap();

        // sequence 4 byte整数，小端存储
        let mut sequence_bytes = [0u8; 4];
        buffer.read_exact(&mut sequence_bytes)?;
        let sequence = u32::from_le_bytes(sequence_bytes);

        Ok(TxIn { prev_tx: prev_tx.to_vec(), prev_index, script_sig, sequence })
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
    pub async fn fetch_tx(&self, tx_fetcher: &mut TxFetcher, testnet: bool) -> Tx {
        tx_fetcher.fetch(encode_hex(&self.prev_tx), testnet, false).await.clone()
    }

    // 获取输入的sotashi
    pub async fn value(&self, tx_fetcher: &mut TxFetcher, testnet: bool) -> u64 {
        let tx = self.fetch_tx(tx_fetcher, testnet).await;
        tx.outputs[self.prev_index as usize].amount
    }

    // 获取输入的 locked-box;(需要解决的问题)
    pub async fn script_pubkey(&self, tx_fetcher: &mut TxFetcher, testnet: bool) -> Script {
        let tx = self.fetch_tx(tx_fetcher, testnet).await;
        tx.outputs[self.prev_index as usize].script_pubkey.clone()
    }
}

impl fmt::Display for TxIn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}:{}", encode_hex(&self.prev_tx), self.prev_index)
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub amount: u64,
    pub script_pubkey: Script,
}

impl TxOut {
    pub fn new(amount: u64, script_pubkey: Script) -> TxOut {
        TxOut { amount, script_pubkey }
    }

    pub fn parse<T: Read + Seek>(buffer: &mut T) -> Result<TxOut> {
        let mut amount_bytes = [0u8; 8];
        buffer.read_exact(&mut amount_bytes)?;

        let amount = u64::from_le_bytes(amount_bytes);

        let script_pubkey = Script::parse(buffer).unwrap();
        Ok(TxOut{ amount, script_pubkey })
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
struct Tx {
    pub version: u32,        // 版本号
    pub inputs: Vec<TxIn>,   // 输入
    pub outputs: Vec<TxOut>, // 输出
    // locktime > 500,000,000 表示时间戳，否则表示区块高度
    pub locktime: u32,       // 锁定时间
    pub testnet: bool,       // 是否测试网
}

impl Tx {
    pub fn new(version: u32, txin: Vec<TxIn>, txout: Vec<TxOut>, locktime: u32, testnet: bool) -> Tx {
        Tx {
            version,
            inputs: txin,
            outputs: txout,
            locktime,
            testnet,
        }
    }

    pub fn parse<T: Read + Seek>(buffer: &mut T, testnet: bool) -> Result<Tx> {
        // 4 byte little-endian integer
        let mut version_bytes=  [0u8; 4];
        buffer.read_exact(&mut version_bytes)?;
        let version = u32::from_le_bytes(version_bytes);

        // inputs
        let inputs = decode_varint(buffer);
        let mut tx_inputs: Vec<TxIn> = vec![];
        for i in 0..inputs {
            tx_inputs.push(TxIn::parse(buffer).unwrap());
        }

        // outputs
        let outputs = decode_varint(buffer);
        let mut tx_outputs: Vec<TxOut> = vec![];
        for i in 0..outputs {
            tx_outputs.push(TxOut::parse(buffer).unwrap());
        }

        // timelock
        let mut locktime_bytes = [0u8; 4];
        buffer.read_exact(&mut locktime_bytes)?;
        let locktime = u32::from_le_bytes(locktime_bytes);

        Ok(Tx{version, inputs: tx_inputs, outputs: tx_outputs, locktime, testnet})
    }

    // 二进制交易哈希
    pub fn hash(&self) ->Vec<u8> {
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
    pub fn fee(&self) -> u64 {
        0
    }
}

impl fmt::Display for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut tx_ins = String::from("");
        for tx_in in &self.inputs {
            tx_ins += &tx_in.to_string();
        }

        let mut tx_outs = String::from("");
        for tx_out in &self.outputs {
            tx_outs += &tx_out.to_string();
        }

        write!(f, "tx: {}\tversion: {}\ttx_ins:\n{}tx_outs:\n{}locktime: {}", self.id(), self.version, tx_ins, tx_outs, self.locktime)
    }
}

struct  TxFetcher {
    pub cache: HashMap<String, Tx>,
}

impl TxFetcher {
    pub fn url(testnet: bool) -> String {
        match testnet {
            true => "https://blockstream.info/testnet/api/".into(),
            false => "https://blockstream.info/api/".into(),
        }
    }

    pub async fn fetch(&mut self, tx_id: String, testnet: bool, fresh: bool) -> &Tx {
        if fresh || !self.cache.contains_key(&tx_id) {
            let url = format!("{}/tx/{}/hex", TxFetcher::url(testnet), &tx_id);
            let response = reqwest::get(url).await.unwrap().text().await.unwrap();
            let bytes = decode_hex(response.trim()).unwrap();

            let mut tx: Tx;
            if bytes[4] == 0 {
                // coinbase tx?
                let mut left = bytes[..4].to_vec();
                let mut right = bytes[6..].to_vec();
                left.append(&mut right);
                let mut cursor = Cursor::new(left);
                
                tx = Tx::parse(&mut cursor, testnet).unwrap();
                let locktime_bytes: [u8; 4] = bytes[bytes.len()-4..].try_into().unwrap();
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