use crate::op::{op_code_name, op_operation, Command, decode_num, encode_num};
use anyhow::{bail, Result};
use num::BigInt;
use std::{
    fmt,
    io::{Read, Seek},
};

use crate::utils::{decode_varint, encode_varint};

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
                    } else if length < 0x100 {
                        // 用1个byte表示其长度,并使用OP_DATA1操作符
                        let mut op_data1_bytes = 76u8.to_le_bytes().to_vec();
                        result.append(&mut op_data1_bytes);
                        let mut bytes = (length as u8).to_le_bytes().to_vec();
                        result.append(&mut bytes);
                    } else if length < 520 {
                        // 用2个byte表示其长度，并使用OP_DATA2操作符
                        let mut op_data2_bytes = 77u8.to_le_bytes().to_vec();
                        result.append(&mut op_data2_bytes);
                        let mut bytes = (length as u16).to_le_bytes().to_vec();
                        result.append(&mut bytes);
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

    pub fn evaluate(&self, z: BigInt) -> bool {
        let mut cmds = self.commands.clone();
        let mut stack: Vec<Vec<u8>> = vec![];
        let mut altstack: Vec<Vec<u8>> = vec![];
        while cmds.len() > 0 {
            let cmd = cmds.remove(0);
            match cmd.clone() {
                Command::Element(e) => {
                    println!("push stack: {}", decode_num(e.clone()));
                    stack.push(e);
                }
                Command::OP(o) => {
                    println!("execute op: {}", op_code_name(o));

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
            return false;
        }

        // integer 0 is not stored as the 00 byte, byte empty byte string
        let e = stack.pop().unwrap();
        if e.len() == 0 {
            return false;
        }

        true
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for cmd in self.commands.clone() {
            match cmd {
                Command::Element(e) => write!(f, "{}, ", decode_num(e))?,
                Command::OP(o) => write!(f, "{}, ", op_code_name(o))?,
            };
        }
        write!(f, "]")
    }
}

mod tests {
    use std::io::Cursor;

    use num::{BigInt, Zero};

    use crate::{
        op::encode_num,
        script::Command,
        utils::{decode_hex, encode_hex, bigint_from_hex},
    };
    use hex_literal::hex;
    use super::Script;

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
        let mut script_pubkey = Script::new(vec![Command::Element(sec), Command::OP(0xac)]);
        println!("script pubkey: {}", script_pubkey);
        let mut script_sig = Script::new(vec![Command::Element(sig)]);
        println!("script sig: {}", script_sig);
        script_sig.add(&mut script_pubkey);
        println!("combined script: {}", script_sig);
        assert!(script_sig.evaluate(bigint_from_hex(z).unwrap()));
    }

    #[test]
    pub fn test_ch06_exercise3() {
        // OP_DUP, OP_DUP, OP_MUL, OP_ADD, OP_6, OP_EQUAL
        // x*x + x = 6
        let mut script_pubkey = Script::new(
            vec![Command::OP(0x76), Command::OP(0x76), Command::OP(0x95), Command::OP(0x93), Command::OP(0x56), Command::OP(0x87)]);

        let mut script_sig = Script::new(vec![Command::Element(encode_num(2))]);
        script_sig.add(&mut script_pubkey);
        assert!(script_sig.evaluate(BigInt::zero()));
    }

    #[test]
    pub fn test_ch06_exercise4() {
    //     let commands: Vec<u8> = hex!("6e879169a77ca787").to_vec();
    //     println!("{:?}", commands);
    //     let mut cursor = Cursor::new(commands);
    //     let script = Script::parse(&mut cursor).unwrap();
    //     println!("script: {}", script);
    }
}
