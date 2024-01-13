use crate::utils::{bytes_to_bit_field, decode_varint, encode_hex, merkle_parent};
use num::traits::Pow;
use std::{
    fmt,
    io::{Read, Seek},
};

// 二维数组实现
#[derive(Clone, Debug)]
pub struct MerkleTree {
    pub total: usize,
    pub max_depth: usize,
    pub nodes: Vec<Vec<Option<Vec<u8>>>>,
    pub current_depth: usize,
    pub current_index: usize,
}

impl MerkleTree {
    // 初始化一个空的merkle树
    pub fn new(total: usize) -> MerkleTree {
        let max_depth = (total as f32).log2().ceil() as usize;
        let mut nodes: Vec<Vec<Option<Vec<u8>>>> = vec![];
        for depth in 0..max_depth + 1 {
            let num_items =
                ((total as f32) / 2.0f32.pow(max_depth as i32 - depth as i32)).ceil() as usize;
            let level_hashes: Vec<Option<Vec<u8>>> = vec![None; num_items];
            nodes.push(level_hashes);
        }

        MerkleTree {
            total,
            max_depth,
            nodes,
            current_depth: 0,
            current_index: 0,
        }
    }

    pub fn up(&mut self) {
        if self.current_depth == 0 {
            return;
        }

        self.current_depth -= 1;
        self.current_index /= 2;
    }

    pub fn left(&mut self) {
        self.current_depth += 1;
        self.current_index *= 2;
    }

    pub fn right(&mut self) {
        self.current_depth += 1;
        self.current_index = self.current_index * 2 + 1;
    }

    pub fn root(&self) -> Option<Vec<u8>> {
        self.nodes[0][0].clone()
    }

    pub fn set_current_node(&mut self, value: &Vec<u8>) {
        self.nodes[self.current_depth][self.current_index] = Some(value.clone());
    }

    pub fn get_current_node(&self) -> Option<Vec<u8>> {
        self.nodes[self.current_depth][self.current_index].clone()
    }

    pub fn get_left_node(&self) -> Option<Vec<u8>> {
        self.nodes[self.current_depth + 1][self.current_index * 2].clone()
    }

    pub fn get_right_node(&self) -> Option<Vec<u8>> {
        self.nodes[self.current_depth + 1][self.current_index * 2 + 1].clone()
    }

    pub fn is_leaf(&self) -> bool {
        self.current_depth == self.max_depth
    }

    pub fn right_exists(&self) -> bool {
        self.nodes[self.current_depth + 1].len() > self.current_index * 2 + 1
    }

    pub fn populate_tree(&mut self, flag_bits: &mut Vec<u8>, hashes: &mut Vec<Vec<u8>>) {
        loop {
            // 每次循环都会生成一个node，直到root节点被生成
            if self.root().is_some() {
                break;
            }

            match self.is_leaf() {
                true => {
                    // 对于叶子节点，直接得到hash即可
                    // println!("get leaf hash of #depth={}, #level={}", self.current_depth, self.current_index);
                    flag_bits.remove(0);
                    self.set_current_node(&hashes.remove(0));
                    self.up();
                }
                false => {
                    // 非叶子节点
                    let left_hash_opt = self.get_left_node();
                    match left_hash_opt {
                        Some(left_hash) => {
                            // 左节点不为空
                            match self.right_exists() {
                                true => {
                                    // 右节点存在
                                    let right_hash_opt = self.get_right_node();
                                    match right_hash_opt {
                                        Some(right_hash) => {
                                            // 右节点不为空
                                            // println!("cal hash of #depth={}, #level={}", self.current_depth, self.current_index);
                                            self.set_current_node(&merkle_parent(
                                                &left_hash,
                                                &right_hash,
                                            ));
                                            self.up();
                                        }
                                        None => {
                                            // 右节点为空
                                            // println!("jump to right: current #depth={}, #level={}", self.current_depth, self.current_index);
                                            self.right();
                                        }
                                    }
                                }
                                false => {
                                    // 右节点不存在
                                    // println!("cal2 hash of #depth={}, #level={}", self.current_depth, self.current_index);
                                    self.set_current_node(&merkle_parent(&left_hash, &left_hash));
                                    self.up();
                                }
                            }
                        }
                        None => {
                            // 左节点为空
                            match flag_bits.remove(0) {
                                0 => {
                                    // 不需要计算左右子树来计算，直接从hashes中取
                                    // println!("get hash of #depth={}, #level={}", self.current_depth, self.current_index);
                                    self.set_current_node(&hashes.remove(0));
                                    self.up()
                                }
                                _ => {
                                    // 需要从左右子树来计算
                                    // println!("jump to left: current #depth={}, #level={}", self.current_depth, self.current_index);
                                    self.left();
                                }
                            }
                        }
                    }
                }
            }
        }
        if hashes.len() != 0 {
            panic!("hashes not all consumed! {}", hashes.len())
        }

        for flag_bit in flag_bits {
            if flag_bit.clone() != 0u8 {
                panic!("flag bits not all consumed!");
            }
        }
    }
}

impl fmt::Display for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result: Vec<String> = vec![];

        for (depth, level) in self.nodes.iter().enumerate() {
            let mut items: Vec<String> = vec![];
            for (index, h) in level.iter().enumerate() {
                let short = match h {
                    Some(hash) => encode_hex(hash)[..8].to_owned(),
                    None => "None".to_owned(),
                };

                if depth == self.current_depth && index == self.current_index {
                    items.push(format!("*{}*", short[..short.len() - 2].to_owned()));
                } else {
                    items.push(short);
                }
            }
            result.push(items.join(", "));
        }
        write!(f, "{}", result.join("\n"))
    }
}

pub struct MerkleBlock {
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
    // total #tx
    pub total: u32,
    // tx hashes
    pub tx_hashes: Vec<Vec<u8>>,
    // flags
    pub flags: Vec<u8>,
}

impl fmt::Display for MerkleBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\n", self.total)?;

        for h in &self.tx_hashes {
            write!(f, "{}\n", encode_hex(h))?;
        }
        write!(f, "{}", encode_hex(&self.flags))
    }
}

impl MerkleBlock {
    pub fn parse<T: Read + Seek>(buffer: &mut T) -> MerkleBlock {
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

        // total transactions in block - 4 bytes, le
        let mut tx_bytes = [0u8; 4];
        buffer.read_exact(&mut tx_bytes).unwrap();
        let total = u32::from_le_bytes(tx_bytes);

        // number of transaction hashes -varint
        let hashes = decode_varint(buffer);

        let mut tx_hashes: Vec<Vec<u8>> = vec![];
        for _ in 0..hashes {
            let mut hash_bytes = [0u8; 32];
            buffer.read_exact(&mut hash_bytes).unwrap();
            // 小端序！
            hash_bytes.reverse();
            tx_hashes.push(hash_bytes.to_vec());
        }

        // length of flags field
        let flags_length = decode_varint(buffer);
        let mut flags_bytes = vec![0u8; flags_length as usize];
        buffer.read_exact(&mut flags_bytes).unwrap();

        MerkleBlock {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
            total,
            tx_hashes,
            flags: flags_bytes.to_vec(),
        }
    }

    pub fn is_valid(&self) -> bool {
        // flag -> bit fields
        // 转二进制
        let mut bit_fields: Vec<u8> = bytes_to_bit_field(&self.flags);

        // hash需要小端顺序
        let mut hashes: Vec<Vec<u8>> = self
            .tx_hashes
            .iter()
            .map(|f| {
                let mut h = f.clone();
                h.reverse();
                h
            })
            .collect();

        // 构造merkle树
        let mut mt = MerkleTree::new(self.total as usize);
        mt.populate_tree(&mut bit_fields, &mut hashes);

        // 验证merkle root
        let mut calculate_root = mt.root().unwrap().clone();
        calculate_root.reverse();
        calculate_root == self.merkle_root
    }
}
#[cfg(test)]
mod tests {
    use super::{MerkleBlock, MerkleTree};
    use crate::utils::{decode_hex, encode_hex};
    use std::io::Cursor;

    #[test]
    pub fn test_create_empty_merkle_tree() {
        let tree = MerkleTree::new(9);
        assert!(tree.nodes[0].len() == 1);
        assert!(tree.nodes[1].len() == 2);
        assert!(tree.nodes[2].len() == 3);
        assert!(tree.nodes[3].len() == 5);
        assert!(tree.nodes[4].len() == 9);
    }

    #[test]
    pub fn test_populate_tree_1() {
        let hex_hashes = [
            "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
            "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
            "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
            "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
            "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
            "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
            "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
            "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
            "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
            "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
            "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
            "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
            "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
            "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
            "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
            "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
        ];
        let mut tree = MerkleTree::new(hex_hashes.len());
        println!("{}", tree);
        let mut hashes: Vec<Vec<u8>> = hex_hashes.iter().map(|x| decode_hex(*x).unwrap()).collect();
        let mut flag_bits: Vec<u8> = vec![1; 31];
        tree.populate_tree(&mut flag_bits, &mut hashes);
        assert!(
            encode_hex(&tree.root().unwrap())
                == "597c4bafe3832b17cbbabe56f878f4fc2ad0f6a402cee7fa851a9cb205f87ed1"
        );
    }

    #[test]
    pub fn test_populate_tree_2() {
        let hex_hashes = [
            "42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e",
            "94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4",
            "959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953",
            "a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2",
            "62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577",
        ];

        let mut tree = MerkleTree::new(hex_hashes.len());
        println!("{}", tree);
        let mut hashes: Vec<Vec<u8>> = hex_hashes.iter().map(|x| decode_hex(*x).unwrap()).collect();
        let mut flag_bits: Vec<u8> = vec![1; 11];
        tree.populate_tree(&mut flag_bits, &mut hashes);
        assert!(
            encode_hex(&tree.root().unwrap())
                == "a8e8bd023169b81bc56854137a135b97ef47a6a7237f4c6e037baed16285a5ab"
        );
    }

    #[test]
    pub fn test_merkle_block_parse() {
        let hex_merkle_block = "00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635";
        let mut buffer = Cursor::new(decode_hex(hex_merkle_block).unwrap());
        let mb = MerkleBlock::parse(&mut buffer);

        assert!(mb.version == 0x20000000);

        let mut merkle_root =
            decode_hex("ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4").unwrap();
        merkle_root.reverse();
        assert!(mb.merkle_root == merkle_root);

        let mut prev_block =
            decode_hex("df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000").unwrap();
        prev_block.reverse();
        assert!(mb.prev_block == prev_block);

        let timestamp = decode_hex("dc7c835b").unwrap();
        assert!(mb.timestamp == u32::from_le_bytes(timestamp.as_slice().try_into().unwrap()));

        assert!(mb.bits == decode_hex("67d8001a").unwrap());
        assert!(mb.nonce == decode_hex("c157e670").unwrap());
        assert!(
            mb.total
                == u32::from_le_bytes(
                    decode_hex("bf0d0000")
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap()
                )
        );

        let hex_hashes = [
            "ba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a",
            "7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d",
            "34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2",
            "158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cba",
            "ee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763ce",
            "f8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097",
            "c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d",
            "6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543",
            "d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274c",
            "dfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb62261",
        ];
        let hashes: Vec<Vec<u8>> = hex_hashes
            .iter()
            .map(|f| {
                let mut hash = decode_hex(f).unwrap();
                hash.reverse();
                hash
            })
            .collect();
        assert!(mb.tx_hashes == hashes);
        assert!(mb.flags == decode_hex("b55635").unwrap());

        assert!(mb.is_valid());
    }

    #[test]
    pub fn test_merkle_block_is_valid() {
        let hex_merkle_block = "00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635";
        let mut buffer = Cursor::new(decode_hex(hex_merkle_block).unwrap());
        let mb = MerkleBlock::parse(&mut buffer);
        assert!(mb.is_valid());
    }
}
