use crate::utils::{decode_varint, encode_varint};
use crate::{
    op::{op_code_name, op_equal, op_hash160, op_operation, op_verify, Command},
    utils::{encode_hex, h160_to_p2pkh_address, h160_to_p2sh_address, sha256},
};
use anyhow::{bail, Result};
use num::BigInt;
use std::io::Cursor;
use std::{
    fmt,
    io::{Read, Seek},
    ops,
};

// 脚本就是命令的一个数组,命令包含数据和操作符
#[derive(Debug, Clone)]
pub struct Script {
    pub commands: Vec<Command>,
}

impl Script {
    pub fn new(commands: Vec<Command>) -> Script {
        Script { commands }
    }

    // 合并两个脚本，通常是将花费脚本和锁定脚本合并
    pub fn add(&mut self, other: &mut Script) {
        self.commands.append(&mut other.commands);
    }

    // 序列化脚本，逐个命令序列化
    // 注意区分数据和操作符序列化方式的不同
    // 操作符就是一个byte（大于等于75）
    // 数据可以是一个byte（小于75），也可以用76和77这两个特殊操作符来指定数据的长度进行序列化
    pub fn serialize(&self) -> Vec<u8> {
        let mut raw_result = self.raw_serialize();
        let mut result = encode_varint(raw_result.len() as u64);
        result.append(&mut raw_result);
        result
    }

    pub fn raw_serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        for cmd in &self.commands {
            match cmd {
                Command::Element(e) => {
                    let length = e.len();
                    if length < 75 {
                        // 用一个byte表示其长度
                        let mut bytes = (length as u8).to_le_bytes().to_vec();
                        result.append(&mut bytes);
                    } else if length > 75 && length < 0x100 {
                        // 用1个byte表示其长度,并使用OP_DATA1操作符
                        let mut op_data1_bytes = 76u8.to_le_bytes().to_vec();
                        result.append(&mut op_data1_bytes);
                        let mut bytes = (length as u8).to_le_bytes().to_vec();
                        result.append(&mut bytes);
                    } else if length >= 0x100 && length <= 520 {
                        // 用2个byte表示其长度，并使用OP_DATA2操作符
                        let mut op_data2_bytes = 77u8.to_le_bytes().to_vec();
                        result.append(&mut op_data2_bytes);
                        let mut bytes = (length as u16).to_le_bytes().to_vec();
                        result.append(&mut bytes);
                    } else {
                        panic!("too long an cmd");
                    }
                    // 序列化数据本身
                    let mut data_bytes = e.clone();
                    result.append(&mut data_bytes);
                }
                Command::OP(o) => {
                    let mut bytes = o.to_le_bytes().to_vec();
                    result.append(&mut bytes);
                }
            }
        }
        result
    }

    // 解析脚本
    pub fn parse<T: Read + Seek>(buffer: &mut T) -> Result<Script> {
        // 总共的命令数
        let length = decode_varint(buffer);

        let mut cmds: Vec<Command> = vec![];
        let mut count = 0;
        while count < length {
            let mut current = [0u8; 1];
            buffer.read_exact(&mut current).unwrap();
            count += 1;

            let current_number = u8::from_le_bytes(current);
            if current_number >= 1 && current_number <= 75 {
                // cmd: element
                let mut element = vec![0u8; current_number as usize];
                buffer.read_exact(&mut element).unwrap();
                cmds.push(Command::Element(element));
                count += current_number as u64;
            } else if current_number == 76 {
                // OP_DATA1
                let mut data_length_byte = [0u8; 1];
                buffer.read_exact(&mut data_length_byte).unwrap();
                count += 1;

                let data_length = u8::from_le_bytes(data_length_byte);
                let mut data = vec![0u8; data_length as usize];
                buffer.read_exact(&mut data).unwrap();
                cmds.push(Command::Element(data));
                count += data_length as u64;
            } else if current_number == 77 {
                // OP_DATA2
                let mut data_length_bytes = [0u8; 2];
                buffer.read_exact(&mut data_length_bytes).unwrap();
                count += 2;

                let data_length = u16::from_le_bytes(data_length_bytes);
                let mut data = vec![0u8; data_length as usize];
                buffer.read_exact(&mut data).unwrap();
                cmds.push(Command::Element(data));
                count += data_length as u64;
            } else {
                // cmd: op
                cmds.push(Command::OP(current_number));
            }
        }
        if count != length {
            bail!("解析脚本失败！");
        }
        Ok(Script::new(cmds))
    }

    pub fn evaluate(&self, z: BigInt, witness: Option<Vec<Command>>) -> bool {
        let mut cmds = self.commands.clone();
        let mut stack: Vec<Vec<u8>> = vec![];
        let mut altstack: Vec<Vec<u8>> = vec![];
        while cmds.len() > 0 {
            let cmd = cmds.remove(0);
            match cmd.clone() {
                Command::Element(e) => {
                    stack.push(e.clone());

                    // p2sh 规则。
                    // OP_HASH160 <20-byte-hash> OP_EQUAL => RedeemScript
                    // OP_HASH160 == 0xa9 and OP_EQUAL = 0x87
                    if cmds.len() == 3
                        && match cmds[0] {
                            Command::Element(_) => false,
                            Command::OP(o) => o == 0xa9,
                        }
                        && match &cmds[1] {
                            Command::Element(e) => e.len() == 20,
                            Command::OP(_) => false,
                        }
                        && match cmds[2] {
                            Command::Element(_) => false,
                            Command::OP(o) => o == 0x87,
                        }
                    {
                        // let mut redeem_script = encode_varint(e.len() as u64);
                        // execute the next three opcodes
                        cmds.pop();
                        let h160 = cmds.pop().unwrap();
                        cmds.pop();
                        if !op_hash160(&mut stack) {
                            return false;
                        }
                        match h160 {
                            Command::Element(e) => stack.push(e),
                            Command::OP(_) => panic!("uexpected op"),
                        };
                        if !op_equal(&mut stack) {
                            return false;
                        }
                        // final result should be 1
                        if !op_verify(&mut stack) {
                            println!("bad p2sh h160");
                            return false;
                        }

                        // hashes match! now add the RedeemScript
                        let mut redeem_script = encode_varint(e.len() as u64);
                        redeem_script.append(&mut e.clone());
                        cmds.append(
                            &mut Script::parse(&mut Cursor::new(&redeem_script))
                                .unwrap()
                                .commands,
                        );
                    }

                    // witness program version 0 rule:
                    // 0 <20-byte-hash>(20字节是pubkey的hash160)
                    // this is p2wpkh
                    if stack.len() == 2 && stack[0].len() == 0 && stack[1].len() == 20 {
                        println!("witness program version 0 with pubkey-hash(h160)...");
                        let h160 = stack.pop().unwrap();
                        stack.pop();
                        cmds.append(&mut witness.clone().unwrap()); // signature + pubkey-hash
                        cmds.append(&mut Script::p2pkh_script(h160).commands);
                    }

                    // witness program version 0 rule
                    // 0 <32-byte-hash>(32字节是script的hash256)
                    // this is p2wsh
                    if stack.len() == 2 && stack[0].len() == 0 && stack[1].len() == 32 {
                        println!("witness program version 0 with script-hash(s256)...");
                        let wit = witness.clone().unwrap();
                        let s256 = stack.pop().unwrap();
                        stack.pop();
                        cmds.append(&mut wit[..wit.len() - 1].to_vec());
                        let witness_script = wit.last().unwrap();
                        match witness_script {
                            Command::Element(w) => {
                                if s256 != sha256(w) {
                                    println!("bad sha256!");
                                    return false;
                                }
                                let mut raw_witness = encode_varint(w.len() as u64);
                                raw_witness.append(&mut w.clone());
                                let mut witness_cmmands =
                                    Script::parse(&mut Cursor::new(&raw_witness))
                                        .unwrap()
                                        .commands;
                                println!("witness commands: {:?}", witness_cmmands);
                                cmds.append(&mut witness_cmmands);
                            }
                            Command::OP(_) => panic!("unexpected op"),
                        };
                    }
                }
                Command::OP(o) => {
                    if !op_operation(
                        o,
                        &mut stack,
                        Some(&mut cmds),
                        Some(&mut altstack),
                        Some(&z),
                    ) {
                        println!("执行OP失败：{}", op_code_name(o));
                        return false;
                    }
                }
            }
        }
        if stack.len() == 0 {
            println!("stack empty");
            return false;
        }

        // integer 0 is not stored as the 00 byte, byte empty byte string
        let e = stack.pop().unwrap();
        if e.len() == 0 {
            println!("stack remains 0");
            return false;
        }

        true
    }

    pub fn p2pkh_script(hash160: Vec<u8>) -> Script {
        Script::new(vec![
            Command::OP(0x76), // OP_DUP
            Command::OP(0xa9), // OP_HASH160
            Command::Element(hash160),
            Command::OP(0x88), // OP_EQUALVERIFY
            Command::OP(0xac), // OP_CHECKSIG
        ])
    }

    pub fn p2sh_script(hash160: Vec<u8>) -> Script {
        Script::new(vec![
            Command::OP(0xa9), // OP_HASH160
            Command::Element(hash160),
            Command::OP(0x87), // OP_EQUAL
        ])
    }

    pub fn p2wpkh_script(hash160: Vec<u8>) -> Script {
        Script::new(vec![Command::OP(0x00), Command::Element(hash160)])
    }

    pub fn p2wsh_script(hash256: Vec<u8>) -> Script {
        Script::new(vec![Command::OP(0x00), Command::Element(hash256)])
    }

    pub fn is_p2pkh_script_pubkey(&self) -> bool {
        // returns whether this follows the
        // OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG pattern
        self.commands.len() == 5
            && match self.commands[0] {
                Command::Element(_) => false,
                Command::OP(o) => o == 0x76,
            }
            && match self.commands[1] {
                Command::Element(_) => false,
                Command::OP(o) => o == 0xa9,
            }
            && match &self.commands[2] {
                Command::Element(e) => e.len() == 20,
                Command::OP(_) => false,
            }
            && match self.commands[3] {
                Command::Element(_) => false,
                Command::OP(o) => o == 0x88,
            }
            && match self.commands[4] {
                Command::Element(_) => false,
                Command::OP(o) => o == 0xac,
            }
    }

    pub fn is_p2sh_script_pubkey(&self) -> bool {
        // returns whether this follows the
        // OP_HASH160 <20 byte hash> OP_EQUAL pattern
        self.commands.len() == 3
            && match self.commands[0] {
                Command::Element(_) => false,
                Command::OP(o) => o == 0xa9,
            }
            && match &self.commands[1] {
                Command::Element(e) => e.len() == 20,
                Command::OP(_) => false,
            }
            && match self.commands[2] {
                Command::Element(_) => false,
                Command::OP(o) => o == 0x87,
            }
    }

    pub fn is_p2wpkh_script_pubkey(&self) -> bool {
        self.commands.len() == 2
            && match self.commands[0] {
                Command::Element(_) => false,
                Command::OP(o) => o == 0x00,
            }
            && match &self.commands[1] {
                Command::Element(e) => e.len() == 20,
                Command::OP(_) => false,
            }
    }

    pub fn is_p2wsh_script_pubkey(&self) -> bool {
        self.commands.len() == 2
            && match self.commands[0] {
                Command::Element(_) => false,
                Command::OP(o) => o == 0x00,
            }
            && match &self.commands[1] {
                Command::Element(e) => e.len() == 32,
                Command::OP(_) => false,
            }
    }

    pub fn address(&self, testnet: bool) -> String {
        // return the address corresponding to the script
        if self.is_p2pkh_script_pubkey() {
            // hash160
            match self.commands[2].clone() {
                Command::Element(e) => h160_to_p2pkh_address(&e, testnet),
                Command::OP(_) => panic!("bad address!"),
            }
        } else if self.is_p2sh_script_pubkey() {
            match self.commands[1].clone() {
                Command::Element(e) => h160_to_p2sh_address(&e, testnet),
                Command::OP(_) => panic!("bad address!"),
            }
        } else {
            panic!("unexpect!");
        }
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "script: {}\n", encode_hex(&self.serialize()[1..]))?; // remove first byte(length)
        write!(f, "[")?;
        for cmd in self.commands.clone() {
            match cmd {
                Command::Element(e) => write!(f, "0x{}, ", encode_hex(&e))?,
                Command::OP(o) => write!(f, "{}, ", op_code_name(o))?,
            };
        }
        write!(f, "]")
    }
}

impl ops::Add<Script> for Script {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut cmds: Vec<Command> = vec![];
        cmds.append(&mut self.commands.clone());
        cmds.append(&mut other.commands.clone());

        Self { commands: cmds }
    }
}

#[cfg(test)]
mod tests {
    use super::Script;
    use crate::{
        op::encode_num,
        script::Command,
        utils::{bigint_from_hex, decode_base58address, decode_hex, encode_hex},
    };
    use num::{traits::FromBytes, BigInt, Zero};
    use std::io::Cursor;
    use std::str;

    #[test]
    pub fn test_script_parse() {
        let script_pubkey = decode_hex("6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937").unwrap();
        let mut script_pubkey_cursor = Cursor::new(script_pubkey);
        let script = Script::parse(&mut script_pubkey_cursor).unwrap();
        let want = decode_hex("304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601").unwrap();
        match &script.commands[0] {
            Command::Element(e) => assert!(encode_hex(e) == encode_hex(&want)),
            _ => assert!(false),
        };
    }

    #[test]
    pub fn test_script_serialize() {
        let want = "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937";
        let mut script_pubkey = Cursor::new(decode_hex(want).unwrap());
        let script = Script::parse(&mut script_pubkey).unwrap();
        assert!(encode_hex(&script.serialize()) == want);
    }

    #[test]
    pub fn test_script_evaluate() {
        let z = "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d";
        let sec = decode_hex("04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34").unwrap();
        let sig = decode_hex("3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601").unwrap();
        let script_pubkey = Script::new(vec![Command::Element(sec), Command::OP(0xac)]);
        println!("script pubkey: {}", script_pubkey);
        let script_sig = Script::new(vec![Command::Element(sig)]);
        println!("script sig: {}", script_sig);
        let combined_script = script_sig + script_pubkey;
        println!("combined script: {}", combined_script);
        assert!(combined_script.evaluate(bigint_from_hex(z).unwrap(), None));
    }

    #[test]
    pub fn test_ch06_exercise3() {
        // OP_DUP, OP_DUP, OP_MUL, OP_ADD, OP_6, OP_EQUAL
        // x*x + x = 6
        let mut script_pubkey = Script::new(vec![
            Command::OP(0x76),
            Command::OP(0x76),
            Command::OP(0x95),
            Command::OP(0x93),
            Command::OP(0x56),
            Command::OP(0x87),
        ]);

        let mut script_sig = Script::new(vec![Command::Element(encode_num(2))]);
        script_sig.add(&mut script_pubkey);
        assert!(script_sig.evaluate(BigInt::zero(), None));
    }

    #[test]
    pub fn test_ch06_exercise4() {
        //     let commands: Vec<u8> = hex!("6e879169a77ca787").to_vec();
        //     println!("{:?}", commands);
        //     let mut cursor = Cursor::new(commands);
        //     let script = Script::parse(&mut cursor).unwrap();
        //     println!("script: {}", script);
    }

    #[test]
    pub fn test_genisis_scriptsig() {
        let stream = decode_hex("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap();
        let mut buffer = Cursor::new(stream);
        let s = Script::parse(&mut buffer).unwrap();
        // The Times 03/Jan/2009 Chancellor on brink of second bailout for banks
        match &s.commands[2] {
            Command::Element(e) => println!("{}", str::from_utf8(e).unwrap()),
            Command::OP(_) => panic!("unexpected command."),
        };
    }

    #[test]
    pub fn test_parse_block_height() {
        let stream = decode_hex("5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00").unwrap();
        let mut buffer = Cursor::new(stream);
        let s = Script::parse(&mut buffer).unwrap();
        match &s.commands[0] {
            Command::Element(e) => println!("block height: {}", BigInt::from_le_bytes(e)),
            Command::OP(_) => panic!("unexpected command."),
        };
    }

    #[test]
    pub fn test_address() {
        let address_1 = "1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa";
        let h160 = decode_base58address(address_1);
        let p2pkh_script_pubkey = Script::p2pkh_script(h160);
        assert!(p2pkh_script_pubkey.address(false) == address_1);
        let address_2 = "mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q";
        assert!(p2pkh_script_pubkey.address(true) == address_2);

        let address_3 = "3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh";
        let h160 = decode_base58address(address_3);
        let p2sh_script_pubkey = Script::p2sh_script(h160);
        println!("{}", p2sh_script_pubkey);
        assert!(p2sh_script_pubkey.address(false) == address_3);
        let address_4 = "2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B";
        assert!(p2sh_script_pubkey.address(true) == address_4);
    }
}
