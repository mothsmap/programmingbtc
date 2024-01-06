use anyhow::Result;
use num::{traits::FromBytes, BigInt, FromPrimitive};
use std::io::{Cursor, Read, Seek};

use crate::utils::{bits_to_target, decode_hex, hash256};

#[derive(Clone, Debug)]
pub struct Block {
    // BIP9: first 3 bits = 001 => version >> 29 == 0b001
    // BIP91: 4th bit is 1 => version >> 4 & 1 == 1
    // BIP141: 1th bit is 1 => version >> 1 & 1 == 1
    pub version: u32, // 32 bit;
    pub prev_block: Vec<u8>,
    // 32 byte
    pub merkle_root: Vec<u8>,
    // 4 byte
    pub timestamp: u32,
    //
    pub bits: Vec<u8>,
    // number-used-only-once
    pub nonce: Vec<u8>,
}

impl Block {
    pub fn new(
        version: u32,
        prev_block: Vec<u8>,
        merkle_root: Vec<u8>,
        timestamp: u32,
        bits: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Block {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        }
    }

    pub fn parse<T: Read + Seek>(buffer: &mut T) -> Result<Block> {
        // version: 4 bytes, little-ediean
        let mut version_bytes = [0u8; 4];
        buffer.read_exact(&mut version_bytes).unwrap();
        let version = u32::from_le_bytes(version_bytes);

        // prev_block: 32 bytes, little-endian
        let mut prev_block_bytes = [0u8; 32];
        buffer.read_exact(&mut prev_block_bytes).unwrap();
        prev_block_bytes.reverse();
        let prev_block = prev_block_bytes.to_vec();

        // merkle_root: 32 bytes, little endian
        let mut merkle_root_bytes = [0u8; 32];
        buffer.read_exact(&mut merkle_root_bytes).unwrap();
        merkle_root_bytes.reverse();
        let merkle_root = merkle_root_bytes.to_vec();

        // timestamp: 4 bytes, little endian
        let mut timestamp_bytes = [0u8; 4];
        buffer.read_exact(&mut timestamp_bytes).unwrap();
        let timestamp = u32::from_le_bytes(timestamp_bytes);

        // bits: 4 bytes
        let mut bits_bytes = [0u8; 4];
        buffer.read_exact(&mut bits_bytes).unwrap();
        let bits = bits_bytes.to_vec();

        // nonce: 4 bytes
        let mut nonce_bytes = [0u8; 4];
        buffer.read_exact(&mut nonce_bytes).unwrap();
        let nonce = nonce_bytes.to_vec();

        Ok(Block {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        // version
        result.append(&mut self.version.to_le_bytes().to_vec());

        // prev_block
        let mut prev_block_rev = self.prev_block.clone();
        prev_block_rev.reverse();
        result.append(&mut prev_block_rev);

        // merkle_root
        let mut merkle_root_rev = self.merkle_root.clone();
        merkle_root_rev.reverse();
        result.append(&mut merkle_root_rev);

        // timestamp
        result.append(&mut self.timestamp.to_le_bytes().to_vec());

        // bits
        result.append(&mut self.bits.clone());

        // nonce
        result.append(&mut self.nonce.clone());

        result
    }

    // hash256的小端呈现
    pub fn hash(&self) -> Vec<u8> {
        // serialize
        let bytes = self.serialize();

        // hash
        let mut hash = hash256(&bytes);

        // revert
        hash.reverse();

        hash
    }

    // 区块是否支持bip9
    pub fn bip9(&self) -> bool {
        self.version >> 29 == 0b001
    }

    //
    pub fn bip91(&self) -> bool {
        self.version >> 4 & 1 == 1
    }

    pub fn bip141(&self) -> bool {
        self.version >> 1 & 1 == 1
    }

    pub fn target(&self) -> BigInt {
        bits_to_target(&self.bits)
    }

    pub fn difficulty(&self) -> BigInt {
        // 0xffff * 256^(0x1d - 3) / target
        0xffff * BigInt::from_u32(256).unwrap().pow(0x1d - 3u32) / self.target()
    }

    pub fn check_pow(&self) -> bool {
        let bytes = self.serialize();
        let hash = hash256(&bytes);
        BigInt::from_le_bytes(&hash) < self.target()
    }

    pub fn genesis_block(testnet: bool) -> Block {
        let bytes = match testnet {
            true => decode_hex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18").unwrap(),
            false => decode_hex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c").unwrap(),
        };
        let mut buffer = Cursor::new(bytes);
        Block::parse(&mut buffer).unwrap()
    }

    pub fn lowest_bits() -> Vec<u8> {
        decode_hex("ffff001d").unwrap()
    }
}

#[allow(unused_imports)]
mod tests {
    use super::Block;
    use crate::utils::{bigint_from_hex, decode_hex, encode_hex, Hex};
    use num::{BigInt, FromPrimitive};
    use std::io::Cursor;

    #[test]
    pub fn test_parse_block() {
        let block_raw = decode_hex("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut buffer = Cursor::new(block_raw);
        let block = Block::parse(&mut buffer).unwrap();
        assert!(block.version == 0x20000002);

        let want =
            decode_hex("000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e").unwrap();
        assert!(block.prev_block == want);

        let want =
            decode_hex("be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b").unwrap();
        assert!(block.merkle_root == want);

        assert!(block.timestamp == 0x59a7771e);
        assert!(block.bits == decode_hex("e93c0118").unwrap());
        assert!(block.nonce == decode_hex("a4ffd71d").unwrap());
    }

    #[test]
    pub fn test_block_serialize() {
        let block_raw = decode_hex("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(block.serialize() == block_raw);
    }

    #[test]
    pub fn test_block_hash() {
        let block_raw = decode_hex("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(
            block.hash()
                == decode_hex("0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523")
                    .unwrap()
        );
    }

    #[test]
    pub fn test_bip9() {
        let block_raw = decode_hex("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(block.bip9());

        let block_raw = decode_hex("0400000039fa821848781f027a2e6dfabbf6bda920d9ae61b63400030000000000000000ecae536a304042e3154be0e3e9a8220e5568c3433a9ab49ac4cbb74f8df8e8b0cc2acf569fb9061806652c27").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(!block.bip9());
    }

    #[test]
    pub fn test_bip91() {
        let block_raw = decode_hex("1200002028856ec5bca29cf76980d368b0a163a0bb81fc192951270100000000000000003288f32a2831833c31a25401c52093eb545d28157e200a64b21b3ae8f21c507401877b5935470118144dbfd1").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(block.bip91());

        let block_raw = decode_hex("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(!block.bip91());
    }

    #[test]
    pub fn test_bip141() {
        let block_raw = decode_hex("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(block.bip141());

        let block_raw = decode_hex("0000002066f09203c1cf5ef1531f24ed21b1915ae9abeb691f0d2e0100000000000000003de0976428ce56125351bae62c5b8b8c79d8297c702ea05d60feabb4ed188b59c36fa759e93c0118b74b2618").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(!block.bip141());
    }

    #[test]
    pub fn test_block_target() {
        let block_raw = decode_hex("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();

        assert!(
            block.target()
                == bigint_from_hex("13ce9000000000000000000000000000000000000000000").unwrap()
        );
        assert!(block.difficulty() == BigInt::from_u64(888171856257).unwrap());
    }

    #[test]
    pub fn test_block_check_pow() {
        let block_raw = decode_hex("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(block.check_pow());

        let block_raw = decode_hex("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0").unwrap();
        let mut buffer = Cursor::new(block_raw.clone());
        let block = Block::parse(&mut buffer).unwrap();
        assert!(!block.check_pow());
    }
}
