use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use num::{bigint::BigInt, FromPrimitive};
use sha2::{Digest, Sha256};
type HmacSha256 = Hmac<Sha256>;

pub fn new_bigint(i: i64) -> BigInt {
    BigInt::from_i64(i).unwrap()
}

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

pub fn bigint_to_bytes(input: &BigInt, bytes: usize) -> Vec<u8> {
    // 确保输出bytes位
    let (_, mut data_part) = input.to_bytes_be();
    if data_part.len() < bytes {
        let mut result: Vec<u8> = vec![0; 32 - data_part.len()];
        result.append(&mut data_part);
        result
    } else {
        data_part
    }
}

pub fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    encode_hex(&hash)
}

pub fn hash256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(hash);
    let hash2 = hasher2.finalize();

    encode_hex(&hash2)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
