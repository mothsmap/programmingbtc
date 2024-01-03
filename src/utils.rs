use std::io::{Read, Seek};

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use num::{bigint::BigInt, traits::ToBytes, FromPrimitive, Integer, ToPrimitive, Zero};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
type HmacSha256 = Hmac<Sha256>;

pub fn decode_hex(input: &str) -> Result<Vec<u8>> {
    // 奇数字符串前面补0
    let s = if input.len() % 2 != 0 {
        String::from("0") + input
    } else {
        input.into()
    };

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}

const HEX_BYTES: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                         202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                         404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
                         606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                         808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                         a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
                         c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
                         e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| unsafe {
            let i = 2 * b as usize;
            HEX_BYTES.get_unchecked(i..i + 2)
        })
        .collect()
}

pub fn bigint_from_hex(s: &str) -> Result<BigInt> {
    let bytes = decode_hex(s)?;
    Ok(BigInt::from_bytes_be(
        num::bigint::Sign::Plus,
        bytes.as_slice(),
    ))
}

pub fn bigint_to_hex(input: BigInt) -> Result<String> {
    let (sign, bytes) = input.to_bytes_be();
    if sign != num::bigint::Sign::Plus {
        bail!("不支持的输入，必须为正数");
    }
    Ok(encode_hex(bytes.as_slice()))
}

pub fn bigint_to_bytes(input: &BigInt, bytes: usize, endian: &str) -> Vec<u8> {
    // 确保输出bytes位
    // 对于椭圆曲线而言，符号位永远为正
    let (_, mut data_part) = match endian {
        "big" => input.to_bytes_be(),
        "little" => input.to_bytes_le(),
        _ => panic!("invalid endian"),
    };

    if data_part.len() > bytes {
        panic!("data not fit to {} bytes", bytes);
    }

    let mut result: Vec<u8> = vec![0; bytes - data_part.len()];
    result.append(&mut data_part);
    result
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.to_vec()
}

pub fn hash256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(hash);
    let hash2 = hasher2.finalize();

    hash2.to_vec()
}

pub fn hash160(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut hasher2 = Ripemd160::new();
    hasher2.update(hash);
    let hash2 = hasher2.finalize();
    hash2.to_vec()
}

pub fn ripemd160(data: &[u8]) -> Vec<u8> {
    let mut hasher2 = Ripemd160::new();
    hasher2.update(data);
    let hash2 = hasher2.finalize();
    hash2.to_vec()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encode_base58(bytes: &[u8]) -> String {
    // 收集前面0的个数,后面需要还原
    let mut count = 0;
    for b in bytes {
        if *b == 0u8 {
            count += 1;
        } else {
            break;
        }
    }

    let mut num = BigInt::from_bytes_be(num::bigint::Sign::Plus, bytes);
    let mut result: String = "".into();
    let mut reminder: BigInt;
    let base = BigInt::from_i32(58).unwrap();
    let base58_chars: Vec<char> = BASE58_ALPHABET.chars().collect();
    while num > BigInt::zero() {
        (num, reminder) = num.div_rem(&base);
        let reminder_usize = reminder.to_i64().unwrap() as usize;
        result = String::from(base58_chars[reminder_usize]) + &result;
    }

    let prefix = vec!["1"; count].join("");
    prefix + &result
}

pub fn decode_base58(input: &str) -> Vec<u8> {
    let mut num = BigInt::zero();
    let chars: Vec<char> = input.chars().collect();
    let base58_chars: Vec<char> = BASE58_ALPHABET.chars().collect();
    for c in chars {
        // 每次循环降低一个位到下一位，需要把上一位的数字乘以58
        num *= 58;
        // 再加上当前位的数字
        let index = base58_chars.iter().position(|&r| r == c).unwrap();
        num += index;
    }

    let (_, bytes) = num.to_bytes_be();
    bytes
}

pub trait Hex {
    fn from_hex(hex: &str) -> Self;
    fn to_hex(&self) -> String;
}

impl Hex for BigInt {
    fn from_hex(hex: &str) -> Self {
        bigint_from_hex(hex).unwrap()
    }

    fn to_hex(&self) -> String {
        bigint_to_hex(self.clone()).unwrap()
    }
}

// 整数变长编码
pub fn encode_varint(num: u64) -> Vec<u8> {
    let bytes = num.to_le_bytes();
    if num < 253 {
        vec![bytes[0]]
    } else if num < 0x10000 {
        vec![0xfd, bytes[0], bytes[1]]
    } else if num < 0x100000000 {
        vec![0xfe, bytes[0], bytes[1], bytes[2], bytes[3]]
    } else {
        // num < 0x10000000000000000
        vec![
            0xff, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]
    }
}

pub fn decode_varint<T: Read + Seek>(buffer: &mut T) -> u64 {
    let mut flag = [0u8; 1];
    buffer.read_exact(&mut flag).unwrap();

    match flag[0] {
        0xfd => {
            let mut bytes = [0u8; 2];
            buffer.read_exact(&mut bytes).unwrap();
            u16::from_le_bytes(bytes) as u64
        }
        0xfe => {
            let mut bytes = [0u8; 4];
            buffer.read_exact(&mut bytes).unwrap();
            u32::from_le_bytes(bytes) as u64
        }
        0xff => {
            let mut bytes = [0u8; 8];
            buffer.read_exact(&mut bytes).unwrap();
            u64::from_le_bytes(bytes) as u64
        }
        _ => flag[0] as u64,
    }
}


pub fn decode_base58address(input: &str) -> Vec<u8> {
    let bytes = decode_base58(input);

    // 最后4个字节是校验码，去掉
    let left = &bytes[..bytes.len()-4];
    let right = &bytes[bytes.len()-4..];
    if hash256(left)[0..4].to_vec() != right.to_vec() {
        panic!("bad address!");
    }
    // 去掉第一个字节，主网/测试网 flag
    // 返回的数据是20字节
    left[1..].to_vec()
}

pub fn sotachi(btc: f64) -> u64 {
    (btc * 100000000.0) as u64
}

mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    pub fn test_base58() {
        let x = "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d";
        let b = "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6";
        let bytes = decode_hex(x).unwrap();
        assert!(encode_base58(&bytes) == b);

        let x = "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c";
        let b = "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd";
        let bytes = decode_hex(x).unwrap();
        assert!(encode_base58(&bytes) == b);

        let x = "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
        let b = "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7";
        let bytes = decode_hex(x).unwrap();
        assert!(encode_base58(&bytes) == b);
    }

    #[test]
    pub fn test_varint() {
        let x = [100u64, 555, 70015, 18005558675309];
        let x_hex = ["64", "fd2b02", "fe7f110100", "ff6dc7ed3e60100000"];

        for i in 0usize..4 {
            let bytes = encode_varint(x[i]);
            assert!(&encode_hex(&bytes) == x_hex[i]);
            assert!(decode_varint(&mut Cursor::new(bytes)) == x[i]);
        }
    }
}
