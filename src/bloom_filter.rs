use crate::utils::{bit_field_to_bytes, encode_varint, murmur3};

#[derive(Debug, Clone)]
pub struct BloomFilter {
    pub size: u32,
    pub bit_field: Vec<u8>,
    pub function_count: u32,
    pub tweak: u32,
}

impl BloomFilter {
    pub fn new(size: u32, function_count: u32, tweak: u32) -> BloomFilter {
        BloomFilter {
            size,
            function_count,
            bit_field: vec![0u8; size as usize * 8],
            tweak,
        }
    }

    pub fn add(&mut self, item: &Vec<u8>) {
        // 往filter中添加一个元素
        for i in 0..self.function_count {
            let seed = i as u64 * 0xfba4c795 + self.tweak as u64;
            // let h = murmur3_hash(item, BigInt::from_u64(seed).unwrap());
            let h = murmur3(item, seed as u32);
            let bit: u32 = h % self.bit_field.len() as u32;
            self.bit_field[bit as usize] = 1;
        }
    }

    pub fn filter_bytes(&self) -> Vec<u8> {
        bit_field_to_bytes(&self.bit_field)
    }

    pub fn filterload_payload(&self, flag: u8) -> Vec<u8> {
        // 返回filterload消息体
        let mut result: Vec<u8> = vec![];

        // filter 大小
        result.append(&mut encode_varint(self.size as u64));

        // bit_field
        result.append(&mut self.filter_bytes());

        // function count: 4 bytes little-endian
        result.append(&mut self.function_count.to_le_bytes().to_vec());

        // tweak: 4 byte little-endian
        result.append(&mut self.tweak.to_le_bytes().to_vec());

        // flag: 1 byte little endian
        result.append(&mut flag.to_le_bytes().to_vec());

        result
    }
}

#[cfg(test)]
mod tests {
    use super::BloomFilter;
    use crate::utils::encode_hex;

    #[test]
    pub fn test_bloom_filter_add() {
        let mut bf = BloomFilter::new(10, 5, 99);
        let item = b"Hello World";
        bf.add(&item.to_vec());
        assert!(encode_hex(&bf.filter_bytes()) == "0000000a080000000140");

        let item = b"Goodbye!";
        bf.add(&item.to_vec());
        assert!(encode_hex(&bf.filter_bytes()) == "4000600a080000010940");
    }

    #[test]
    pub fn test_bloom_filter_filterload() {
        let mut bf = BloomFilter::new(10, 5, 99);
        let item = b"Hello World";
        bf.add(&item.to_vec());

        let item = b"Goodbye!";
        bf.add(&item.to_vec());

        let expected = "0a4000600a080000010940050000006300000001";
        println!("{}", expected);
        println!("{}", encode_hex(&bf.filterload_payload(1)));
        assert!(encode_hex(&bf.filterload_payload(1)) == expected);
    }
}
