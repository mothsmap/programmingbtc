use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use murmur3::murmur3_32;
use num::{
    bigint::BigInt,
    traits::{FromBytes, ToBytes},
    FromPrimitive, Integer, ToPrimitive, Zero,
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Seek};
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
    let left = &bytes[..bytes.len() - 4];
    let right = &bytes[bytes.len() - 4..];
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

// target是一个很小的数，在256位的数字空间中（256进制），只有一个位被设置。
pub fn bits_to_target(bits: &Vec<u8>) -> BigInt {
    // last byte is exponent
    let exponent: u8 = bits[3];
    // the first three bytes are the coefficient in little endian
    let coefficient = BigInt::from_le_bytes(&bits[0..3].to_vec());
    // the formula is: coefficient * 256^(exponent - 3)
    coefficient * BigInt::from_u32(256).unwrap().pow(exponent as u32 - 3u32)
}

pub fn target_to_bits(target: BigInt) -> Vec<u8> {
    let raw_bytes = target.to_be_bytes();

    let exponent: u8;
    let coefficient: Vec<u8>;
    if raw_bytes[0] > 0x7f {
        exponent = raw_bytes.len() as u8 + 1u8;
        coefficient = vec![0, raw_bytes[0], raw_bytes[1]];
    } else {
        exponent = raw_bytes.len() as u8;
        coefficient = raw_bytes[..3].to_vec();
    };
    vec![coefficient[2], coefficient[1], coefficient[0], exponent]
}

pub fn calculate_new_bits(previous_bits: &Vec<u8>, mut time_differential: u32) -> Vec<u8> {
    // 给定2016个block的时间差，计算新的bits
    let two_weeks: u32 = 2 * 7 * 24 * 3600;
    let eight_weeks: u32 = two_weeks * 4;
    let half_week: u32 = two_weeks / 4 as u32;
    // 如果时间差大于8个星期，设置为8个星期
    if time_differential > eight_weeks {
        time_differential = eight_weeks;
    }

    // 如果时间差小于半个星期，设置为半个星期
    if time_differential < half_week {
        time_differential = half_week;
    }

    // 新的target = previs_target * time_differential/two_weeks
    let mut new_target = (bits_to_target(previous_bits) * time_differential)
        .div_floor(&BigInt::from_u32(two_weeks).unwrap());
    let max_target = 0xffff * BigInt::from_u32(256).unwrap().pow(0x1d - 3);
    if new_target > max_target {
        new_target = max_target;
    }

    target_to_bits(new_target)
}

pub fn merkle_parent(child_left: &Vec<u8>, child_right: &Vec<u8>) -> Vec<u8> {
    let mut combined = child_left.clone();
    combined.append(&mut child_right.clone());
    hash256(&combined)
}

pub fn merkle_parent_level(childs: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut odd_childs = childs.clone();
    if childs.len() % 2 == 1 {
        odd_childs.push(childs.last().unwrap().clone());
    }

    (0..odd_childs.len())
        .step_by(2)
        .map(|i| merkle_parent(&odd_childs[i], &odd_childs[i + 1]))
        .collect()
}

pub fn merkle_root(childs: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut result = childs.clone();
    loop {
        if result.len() <= 1 {
            break;
        }

        result = merkle_parent_level(&result);
    }
    result[0].clone()
}

pub fn bytes_to_bit_field(bytes: &Vec<u8>) -> Vec<u8> {
    let mut flag_bits: Vec<u8> = vec![];
    for b in bytes {
        let mut bb = b.clone();
        for _ in 0..8 {
            flag_bits.push(bb & 1);
            bb >>= 1;
        }
    }
    flag_bits
}

pub fn bit_field_to_bytes(bit_fields: &Vec<u8>) -> Vec<u8> {
    if bit_fields.len() % 8 != 0 {
        panic!("bit fields does not have a length that is divided by 8");
    }

    let mut result = vec![0u8; bit_fields.len() / 8];
    for (index, bit) in bit_fields.iter().enumerate() {
        let byte_index = index / 8;
        let bit_index = index % 8;
        if *bit == 1 {
            result[byte_index] += 1 << bit_index;
        }
    }
    result
}

// use crate
pub fn murmur3(data: &[u8], seed: u32) -> u32 {
    murmur3_32(&mut Cursor::new(data), seed).unwrap()
}

// hand craft, should get the same result with fn murmur3
pub fn murmur3_hash(data: &[u8], seed: BigInt) -> u32 {
    // from http://stackoverflow.com/questions/13305290/is-there-a-pure-python-implementation-of-murmurhash
    let c1 = BigInt::from_u64(0xcc9e2d51).unwrap();
    let c2 = BigInt::from_u64(0x1b873593).unwrap();
    let length = data.len();
    let mut h1 = seed;
    let rounded_end = length & 0xfffffffc; // round down to 4 byte block
    for i in (0..rounded_end).step_by(4) {
        // little endian load order
        let mut k1 = BigInt::from_u64(
            ((data[i] as u64) & 0xff)
                | (((data[i + 1] & 0xff) as u64) << 8u64)
                | (((data[i + 2] & 0xff) as u64) << 16)
                | ((data[i + 3] as u64) << 24),
        )
        .unwrap();
        k1 *= c1.clone();
        k1 = (k1.clone() << 15) | ((k1.clone() & BigInt::from_u64(0xffffffff).unwrap()) >> 17); // ROTL32(k1,15)
        k1 *= c2.clone();
        h1 ^= k1.clone();
        h1 = (h1.clone() << 13) | ((h1.clone() & BigInt::from_u64(0xffffffff).unwrap()) >> 19); // ROTL32(h1,13)
        h1 = h1 * 5 + BigInt::from_u64(0xe6546b64).unwrap();
    }
    // tail
    let mut k1 = BigInt::from_u64(0u64).unwrap();
    let val = length & 0x03;
    if val == 3 {
        k1 = BigInt::from_u64(((data[rounded_end + 2] & 0xff) as u64) << 16).unwrap();
    }
    // fallthrough
    if val == 2 || val == 3 {
        k1 |= BigInt::from_u64(((data[rounded_end + 1] & 0xff) as u64) << 8).unwrap();
    }
    // fallthrough
    if val == 1 || val == 2 || val == 3 {
        k1 |= BigInt::from_u64((data[rounded_end] & 0xff) as u64).unwrap();
        k1 *= c1;
        k1 = (k1.clone() << 15) | ((k1.clone() & BigInt::from_u64(0xffffffff).unwrap()) >> 17); // ROTL32(k1,15)
        k1 *= c2.clone();
        h1 ^= k1.clone();
    }
    // finalization
    h1 ^= BigInt::from_u64(length as u64).unwrap();
    // fmix(h1)
    h1 ^= (h1.clone() & BigInt::from_u64(0xffffffff).unwrap()) >> 16;
    h1 *= BigInt::from_u64(0x85ebca6b).unwrap();
    h1 ^= (h1.clone() & BigInt::from_u64(0xffffffff).unwrap()) >> 13;
    h1 *= BigInt::from_u64(0xc2b2ae35).unwrap();
    h1 ^= (h1.clone() & BigInt::from_u64(0xffffffff).unwrap()) >> 16;
    (h1 & BigInt::from_u64(0xffffffff).unwrap())
        .to_u32()
        .unwrap()
}

pub fn h160_to_p2pkh_address(h160: &Vec<u8>, testnet: bool) -> String {
    // takes a byte sequece hash160 and returns a p2pksh address string
    // p2pkh has a prefix of b'\x00' for mainnet, b'\x6f' for testnet
    let mut bytes = vec![];
    let prefix = if testnet { b'\x6f' } else { b'\x00' };
    bytes.push(prefix);

    bytes.append(&mut h160.clone());

    let mut checksum: Vec<u8> = hash256(&bytes).as_slice()[..4].to_vec();
    bytes.append(&mut checksum);
    encode_base58(&bytes)
}

pub fn h160_to_p2sh_address(h160: &Vec<u8>, testnet: bool) -> String {
    // Takes a byte sequence hash160 and returns a p2sh address string'''
    // p2sh has a prefix of b'\x05' for mainnet, b'\xc4' for testnet
    let mut bytes = vec![];
    let prefix = if testnet { b'\xc4' } else { b'\x05' };
    bytes.push(prefix);

    bytes.append(&mut h160.clone());

    let mut checksum: Vec<u8> = hash256(&bytes).as_slice()[..4].to_vec();
    bytes.append(&mut checksum);
    encode_base58(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
    #[test]
    pub fn test_bits_to_target() {
        let bits = decode_hex("e93c0118").unwrap();
        println!("old bits: {:?}", bits);
        let target = bits_to_target(&bits);
        println!("{}", target.to_hex());

        let bits_new = target_to_bits(target);
        println!("new bits: {:?}", bits_new);
    }

    #[test]
    pub fn test_merkle_parent() {
        let hash0 =
            decode_hex("c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5").unwrap();
        let hash1 =
            decode_hex("c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5").unwrap();
        let parent = merkle_parent(&hash0, &hash1);
        assert!(
            encode_hex(&parent)
                == "8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd"
        );
    }

    #[test]
    pub fn test_merkle_level() {
        let hex_hashes: Vec<&str> = vec![
            "c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5",
            "c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5",
            "f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0",
            "3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181",
            "10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae",
        ];

        let hashes: Vec<Vec<u8>> = hex_hashes.iter().map(|x| decode_hex(*x).unwrap()).collect();
        let parent_level = merkle_parent_level(&hashes);
        let parent_level_hex: Vec<String> = parent_level.iter().map(|x| encode_hex(x)).collect();
        assert!(
            parent_level_hex
                == vec![
                    "8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd".to_owned(),
                    "7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800".to_owned(),
                    "3ecf6115380c77e8aae56660f5634982ee897351ba906a6837d15ebc3a225df0".to_owned()
                ]
        );
    }

    #[test]
    pub fn test_merkle_root() {
        let hex_hashes: Vec<&str> = vec![
            "c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5",
            "c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5",
            "f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0",
            "3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181",
            "10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae",
            "7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161",
            "8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc",
            "dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877",
            "b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59",
            "95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c",
            "2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908",
            "b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0",
        ];

        let hashes: Vec<Vec<u8>> = hex_hashes.iter().map(|x| decode_hex(*x).unwrap()).collect();
        let merkle_root = merkle_root(&hashes);
        assert!(
            encode_hex(&merkle_root)
                == "acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6".to_owned()
        );
    }

    #[test]
    pub fn test_bit_field_to_bytes() {
        let bit_fields = vec![
            0u8, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        ];
        let want = "4000600a080000010940";

        assert!(encode_hex(&bit_field_to_bytes(&bit_fields)) == want);
        assert!(bytes_to_bit_field(&decode_hex(want).unwrap()) == bit_fields);
    }

    #[test]
    pub fn test_p2pkh_address() {
        let h160 = decode_hex("74d691da1574e6b3c192ecfb52cc8984ee7b6c56").unwrap();
        let want = "1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa";
        assert!(h160_to_p2pkh_address(&h160, false) == want);
        let want = "mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q";
        assert!(h160_to_p2pkh_address(&h160, true) == want);
    }

    #[test]
    pub fn test_p2sh_address() {
        let h160 = decode_hex("74d691da1574e6b3c192ecfb52cc8984ee7b6c56").unwrap();
        let want = "3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh";
        assert!(h160_to_p2sh_address(&h160, false) == want);
        let want = "2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B";
        assert!(h160_to_p2sh_address(&h160, true) == want);
    }
}
