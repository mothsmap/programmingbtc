use crate::{
    field_point::FieldPoint,
    signature::Signature,
    utils::{hash160, hash256, ripemd160, sha256},
};
use num::BigInt;

#[derive(Debug, Clone)]
pub enum Command {
    Element(Vec<u8>), // elements are byte strings of length 1 to 520
    OP(u8),           // operations is int
}

pub fn encode_num(num: i64) -> Vec<u8> {
    // 编码0为空字节数组
    if num == 0 {
        return vec![];
    }

    // 编码整数部分
    let mut abs_num: u64 = num.abs() as u64;
    let negative = num < 0;

    let mut result: Vec<u8> = vec![];
    while abs_num > 0 {
        // 对于每个byte
        result.push(abs_num as u8 & 0xff);
        abs_num >>= 8;
    }

    if result[result.len() - 1] & 0x80 == 1 {
        // 整数部分第一个byte是128<0b10000000>
        if negative {
            result.push(0x80);
        } else {
            result.push(0);
        }
    } else if negative {
        let idx = result.len() - 1;
        result[idx] |= 0x80;
    }
    result
}

pub fn decode_num(element: Vec<u8>) -> i64 {
    if element.is_empty() {
        return 0;
    }

    let mut result: i64;

    let mut big_edian = element.clone();
    big_edian.reverse();

    let negative: bool;
    if big_edian[0] & 0x80 == 1 {
        negative = true;
        result = (big_edian[0] & 0x7f) as i64;
    } else {
        negative = false;
        result = big_edian[0] as i64;
    }

    for c in big_edian[1..].iter() {
        result <<= 8;
        result += *c as i64;
    }

    if negative {
        -result
    } else {
        result
    }
}

pub fn op_0(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(0));
    true
}

pub fn op_1negate(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(-1));
    true
}

pub fn op_1(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(1));
    true
}

pub fn op_2(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(2));
    true
}

pub fn op_3(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(3));
    true
}

pub fn op_4(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(4));
    true
}

pub fn op_5(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(5));
    true
}

pub fn op_6(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(6));
    true
}

pub fn op_7(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(7));
    true
}

pub fn op_8(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(8));
    true
}

pub fn op_9(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(9));
    true
}

pub fn op_10(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(10));
    true
}

pub fn op_11(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(11));
    true
}

pub fn op_12(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(12));
    true
}

pub fn op_13(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(13));
    true
}

pub fn op_14(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(14));
    true
}

pub fn op_15(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(15));
    true
}

pub fn op_16(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(16));
    true
}

pub fn op_nop(_stack: &mut Vec<Vec<u8>>) -> bool {
    true
}

pub fn op_if(_stack: &mut Vec<Vec<u8>>, _items: &mut Vec<Command>) -> bool {
    false
}

pub fn op_notif(_stack: &mut Vec<Vec<u8>>, _items: &mut Vec<Command>) -> bool {
    false
}

pub fn op_verify(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    let element = stack.pop().unwrap();
    if decode_num(element) == 0 {
        false
    } else {
        true
    }
}

pub fn op_return(_stack: &mut Vec<Vec<u8>>) -> bool {
    false
}

pub fn op_totalstack(stack: &mut Vec<Vec<u8>>, altstack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }
    altstack.push(stack.pop().unwrap());
    true
}

pub fn op_fromaltstack(stack: &mut Vec<Vec<u8>>, altstack: &mut Vec<Vec<u8>>) -> bool {
    if altstack.len() < 1 {
        return false;
    }
    stack.push(altstack.pop().unwrap());
    true
}

pub fn op_2drop(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }

    stack.pop();
    stack.pop();
    true
}

pub fn op_2dup(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }

    let a = stack[stack.len() - 2].clone();
    let b = stack[stack.len() - 1].clone();
    stack.push(a);
    stack.push(b);
    true
}

pub fn op_3dup(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 3 {
        return false;
    }
    let a = stack[stack.len() - 3].clone();
    let b = stack[stack.len() - 2].clone();
    let c = stack[stack.len() - 1].clone();
    stack.push(a);
    stack.push(b);
    stack.push(c);
    true
}

pub fn op_2over(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 4 {
        return false;
    }
    let a = stack[stack.len() - 4].clone();
    let b = stack[stack.len() - 3].clone();

    stack.push(a);
    stack.push(b);
    true
}

pub fn op_2rot(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 6 {
        return false;
    }
    let a = stack[stack.len() - 6].clone();
    let b = stack[stack.len() - 5].clone();

    stack.push(a);
    stack.push(b);
    true
}

pub fn op_2swap(stack: &mut Vec<Vec<u8>>) -> bool {
    let len = stack.len();
    if len < 4 {
        return false;
    }

    let stack_bk = stack[len - 4..].to_vec();
    stack[len - 4] = stack_bk[len - 2].clone();
    stack[len - 3] = stack_bk[len - 1].clone();
    stack[len - 2] = stack_bk[len - 4].clone();
    stack[len - 1] = stack_bk[len - 3].clone();
    true
}

pub fn op_ifdup(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    if decode_num(stack[stack.len() - 1].clone()) != 0 {
        stack.push(stack[stack.len() - 1].clone());
    }
    true
}

pub fn op_depth(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(stack.len() as i64));
    true
}

pub fn op_drop(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    stack.pop();
    true
}

pub fn op_dup(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    stack.push(stack[stack.len() - 1].clone());
    true
}

pub fn op_nip(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let e = stack.pop().unwrap();
    let idx = stack.len() - 1;
    stack[idx] = e;
    true
}

pub fn op_over(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    stack.push(stack[stack.len() - 2].clone());
    true
}

pub fn op_pick(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    let n = decode_num(stack.pop().unwrap()) as usize;
    if stack.len() < n + 1 {
        return false;
    }
    stack.push(stack[stack.len() - n - 1].clone());
    true
}

pub fn op_roll(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    let n = decode_num(stack.pop().unwrap()) as usize;
    if stack.len() < n + 1 {
        return false;
    }

    if n == 0 {
        return true;
    }

    stack.push(stack[stack.len() - n - 1].clone());
    true
}

pub fn op_rot(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 3 {
        return false;
    }
    let e = stack.remove(stack.len() - 3);
    stack.push(e);
    true
}

pub fn op_swap(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let e = stack.remove(stack.len() - 2);
    stack.push(e);
    true
}

pub fn op_tuck(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    stack.insert(stack.len() - 2, stack[stack.len() - 1].clone());
    true
}

pub fn op_size(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }
    stack.push(encode_num(stack[stack.len() - 1].len() as i64));
    true
}

pub fn op_equal(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }

    let element1 = stack.pop();
    let element2 = stack.pop();

    if element1 == element2 {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_equalverify(stack: &mut Vec<Vec<u8>>) -> bool {
    op_equal(stack) && op_verify(stack)
}

pub fn op_1add(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    let element = decode_num(stack.pop().unwrap());
    stack.push(encode_num(element + 1));
    true
}

pub fn op_1sub(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }
    let element = decode_num(stack.pop().unwrap());
    stack.push(encode_num(element - 1));
    true
}

pub fn op_negate(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }
    let element = decode_num(stack.pop().unwrap());
    stack.push(encode_num(-element));
    true
}

pub fn op_abs(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }
    let element = decode_num(stack.pop().unwrap());
    if element < 0 {
        stack.push(encode_num(-element));
    } else {
        stack.push(encode_num(element));
    }
    true
}

pub fn op_not(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }
    let element = decode_num(stack.pop().unwrap());
    if element == 0 {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_0notequal(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }
    let element = decode_num(stack.pop().unwrap());
    if element == 0 {
        stack.push(encode_num(0));
    } else {
        stack.push(encode_num(1));
    }
    true
}

pub fn op_add(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    stack.push(encode_num(element1 + element2));
    true
}

pub fn op_sub(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    stack.push(encode_num(element2 - element1));
    true
}

pub fn op_mul(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    stack.push(encode_num(element1 * element2));
    true
}

pub fn op_booland(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element1 > 0 && element2 > 0 {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_boolor(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element1 > 0 || element2 > 0 {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_numequal(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element1 == element2 {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_numequalverify(stack: &mut Vec<Vec<u8>>) -> bool {
    op_numequal(stack) && op_verify(stack)
}

pub fn op_numnotequal(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element1 == element2 {
        stack.push(encode_num(0));
    } else {
        stack.push(encode_num(1));
    }
    true
}

pub fn op_lessthan(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element2 < element1 {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_greaterthan(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element2 > element1 {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_lessthanorequal(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element2 <= element1 {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_greaterthanorequal(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element2 >= element1 {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_min(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element1 < element2 {
        stack.push(encode_num(element1));
    } else {
        stack.push(encode_num(element2));
    }
    true
}

pub fn op_max(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let element1 = decode_num(stack.pop().unwrap());
    let element2 = decode_num(stack.pop().unwrap());
    if element1 > element2 {
        stack.push(encode_num(element1));
    } else {
        stack.push(encode_num(element2));
    }
    true
}

pub fn op_within(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 3 {
        return false;
    }
    let maximum = decode_num(stack.pop().unwrap());
    let minimum = decode_num(stack.pop().unwrap());
    let element = decode_num(stack.pop().unwrap());
    if element >= minimum && element <= maximum {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_ripemd160(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    let element = stack.pop().unwrap();
    stack.push(ripemd160(&element));
    true
}

// not implemented
pub fn op_sha1(_stack: &mut Vec<Vec<u8>>) -> bool {
    return false;
}

pub fn op_sha256(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    let element = stack.pop().unwrap();
    stack.push(sha256(&element));
    true
}

pub fn op_hash160(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    let element = stack.pop().unwrap();
    stack.push(hash160(&element));
    true
}

pub fn op_hash256(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false;
    }

    let element = stack.pop().unwrap();
    stack.push(hash256(&element));
    true
}

pub fn op_checksig(stack: &mut Vec<Vec<u8>>, z: &BigInt) -> bool {
    if stack.len() < 2 {
        return false;
    }

    // the top element of the stack is the SEC pubkey
    let pubkey_sec = stack.pop().unwrap();
    let pubkey = FieldPoint::parse_sec(&pubkey_sec);

    // the next element of the stack is the der signature
    let mut signature_der = stack.pop().unwrap();

    // take off the last byte of the signature as that's the hash_type(mostly SIGHASH_ALL)
    signature_der.pop();
    let sig = Signature::from_der(&signature_der);

    // verify
    if sig.verify_bigint(z, &pubkey.x.unwrap().num, &pubkey.y.unwrap().num) {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}

pub fn op_checksigverify(stack: &mut Vec<Vec<u8>>, z: &BigInt) -> bool {
    op_checksig(stack, z) && op_verify(stack)
}

// not implemented
pub fn op_checkmultisig(_stack: &mut Vec<Vec<u8>>, _z: &BigInt) -> bool {
    false
}

// not implemented
pub fn op_checkmultisigverify(stack: &mut Vec<Vec<u8>>, z: &BigInt) -> bool {
    op_checkmultisig(stack, z) && op_verify(stack)
}

pub fn op_checklocktimeverify(stack: &mut Vec<Vec<u8>>, locktime: u32, sequence: u32) -> bool {
    if sequence == 0xffffffff {
        return false;
    }

    if stack.len() < 1 {
        return false;
    }

    let element = decode_num(stack[stack.len() - 1].clone());
    if element < 0 {
        return false;
    }
    let element = element as u32;
    if element < 500000000 && locktime > 500000000 {
        return false;
    }

    if locktime < element {
        return false;
    }
    true
}

pub fn op_checksequenceverify(stack: &mut Vec<Vec<u8>>, version: u32, sequence: u32) -> bool {
    if sequence & (1 << 31) == (1 << 31) {
        return false;
    }
    if stack.len() < 1 {
        return false;
    }
    let element = decode_num(stack[stack.len() - 1].clone());
    if element < 0 {
        return false;
    }
    let element: u32 = element as u32;
    if element & (1 << 31) == (1 << 31) {
        if version < 2 {
            return false;
        } else if sequence & (1 << 31) == (1 << 31) {
            return false;
        } else if element & (1 << 22) != sequence & (1 << 22) {
            return false;
        } else if element & 0xffff > sequence & 0xffff {
            return false;
        }
    }
    true
}

pub fn op_code_name(code: u8) -> String {
    match code {
        0 => "OP_0".into(),
        76 => "OP_PUSHDATA1".into(),
        77 => "OP_PUSHDATA2".into(),
        78 => "OP_PUSHDATA4".into(),
        79 => "OP_1NEGATE".into(),
        81 => "OP_1".into(),
        82 => "OP_2".into(),
        83 => "OP_3".into(),
        84 => "OP_4".into(),
        85 => "OP_5".into(),
        86 => "OP_6".into(),
        87 => "OP_7".into(),
        88 => "OP_8".into(),
        89 => "OP_9".into(),
        90 => "OP_10".into(),
        91 => "OP_11".into(),
        92 => "OP_12".into(),
        93 => "OP_13".into(),
        94 => "OP_14".into(),
        95 => "OP_15".into(),
        96 => "OP_16".into(),
        97 => "OP_NOP".into(),
        99 => "OP_IF".into(),
        100 => "OP_NOTIF".into(),
        103 => "OP_ELSE".into(),
        104 => "OP_ENDIF".into(),
        105 => "OP_VERIFY".into(),
        106 => "OP_RETURN".into(),
        107 => "OP_TOALTSTACK".into(),
        108 => "OP_FROMALTSTACK".into(),
        109 => "OP_2DROP".into(),
        110 => "OP_2DUP".into(),
        111 => "OP_3DUP".into(),
        112 => "OP_2OVER".into(),
        113 => "OP_2ROT".into(),
        114 => "OP_2SWAP".into(),
        115 => "OP_IFDUP".into(),
        116 => "OP_DEPTH".into(),
        117 => "OP_DROP".into(),
        118 => "OP_DUP".into(),
        119 => "OP_NIP".into(),
        120 => "OP_OVER".into(),
        121 => "OP_PICK".into(),
        122 => "OP_ROLL".into(),
        123 => "OP_ROT".into(),
        124 => "OP_SWAP".into(),
        125 => "OP_TUCK".into(),
        130 => "OP_SIZE".into(),
        135 => "OP_EQUAL".into(),
        136 => "OP_EQUALVERIFY".into(),
        139 => "OP_1ADD".into(),
        140 => "OP_1SUB".into(),
        143 => "OP_NEGATE".into(),
        144 => "OP_ABS".into(),
        145 => "OP_NOT".into(),
        146 => "OP_0NOTEQUAL".into(),
        147 => "OP_ADD".into(),
        148 => "OP_SUB".into(),
        149 => "OP_MUL".into(),
        154 => "OP_BOOLAND".into(),
        155 => "OP_BOOLOR".into(),
        156 => "OP_NUMEQUAL".into(),
        157 => "OP_NUMEQUALVERIFY".into(),
        158 => "OP_NUMNOTEQUAL".into(),
        159 => "OP_LESSTHAN".into(),
        160 => "OP_GREATERTHAN".into(),
        161 => "OP_LESSTHANOREQUAL".into(),
        162 => "OP_GREATERTHANOREQUAL".into(),
        163 => "OP_MIN".into(),
        164 => "OP_MAX".into(),
        165 => "OP_WITHIN".into(),
        166 => "OP_RIPEMD160".into(),
        167 => "OP_SHA1".into(),
        168 => "OP_SHA256".into(),
        169 => "OP_HASH160".into(),
        170 => "OP_HASH256".into(),
        171 => "OP_CODESEPARATOR".into(),
        172 => "OP_CHECKSIG".into(),
        173 => "OP_CHECKSIGVERIFY".into(),
        174 => "OP_CHECKMULTISIG".into(),
        175 => "OP_CHECKMULTISIGVERIFY".into(),
        176 => "OP_NOP1".into(),
        177 => "OP_CHECKLOCKTIMEVERIFY".into(),
        178 => "OP_CHECKSEQUENCEVERIFY".into(),
        179 => "OP_NOP4".into(),
        180 => "OP_NOP5".into(),
        181 => "OP_NOP6".into(),
        182 => "OP_NOP7".into(),
        183 => "OP_NOP8".into(),
        184 => "OP_NOP9".into(),
        185 => "OP_NOP10".into(),
        x => format!("UNKNOW_OP{}", x),
    }
}

pub fn op_operation(
    code: u8,
    stack: &mut Vec<Vec<u8>>,
    cmds: Option<&mut Vec<Command>>,
    altstack: Option<&mut Vec<Vec<u8>>>,
    z: Option<&BigInt>,
) -> bool {
    match code {
        0 => op_0(stack),
        79 => op_1negate(stack),
        81 => op_1(stack),
        82 => op_2(stack),
        83 => op_3(stack),
        84 => op_4(stack),
        85 => op_5(stack),
        86 => op_6(stack),
        87 => op_7(stack),
        88 => op_8(stack),
        89 => op_9(stack),
        90 => op_10(stack),
        91 => op_11(stack),
        92 => op_12(stack),
        93 => op_13(stack),
        94 => op_14(stack),
        95 => op_15(stack),
        96 => op_16(stack),
        97 => op_nop(stack),
        99 => op_if(stack, cmds.unwrap()),
        100 => op_notif(stack, cmds.unwrap()),
        105 => op_verify(stack),
        106 => op_return(stack),
        107 => op_totalstack(stack, altstack.unwrap()),
        108 => op_fromaltstack(stack, altstack.unwrap()),
        109 => op_2drop(stack),
        110 => op_2dup(stack),
        111 => op_3dup(stack),
        112 => op_2over(stack),
        113 => op_2rot(stack),
        114 => op_2swap(stack),
        115 => op_ifdup(stack),
        116 => op_depth(stack),
        117 => op_drop(stack),
        118 => op_dup(stack),
        119 => op_nip(stack),
        120 => op_over(stack),
        121 => op_pick(stack),
        122 => op_roll(stack),
        123 => op_rot(stack),
        124 => op_swap(stack),
        125 => op_tuck(stack),
        130 => op_size(stack),
        135 => op_equal(stack),
        136 => op_equalverify(stack),
        139 => op_1add(stack),
        140 => op_1sub(stack),
        143 => op_negate(stack),
        144 => op_abs(stack),
        145 => op_not(stack),
        146 => op_0notequal(stack),
        147 => op_add(stack),
        148 => op_sub(stack),
        149 => op_mul(stack),
        154 => op_booland(stack),
        155 => op_boolor(stack),
        156 => op_numequal(stack),
        157 => op_numequalverify(stack),
        158 => op_numnotequal(stack),
        159 => op_lessthan(stack),
        160 => op_greaterthan(stack),
        161 => op_lessthanorequal(stack),
        162 => op_greaterthanorequal(stack),
        163 => op_min(stack),
        164 => op_max(stack),
        165 => op_within(stack),
        166 => op_ripemd160(stack),
        167 => op_sha1(stack),
        168 => op_sha256(stack),
        169 => op_hash160(stack),
        170 => op_hash256(stack),
        172 => op_checksig(stack, z.unwrap()),
        173 => op_checksigverify(stack, z.unwrap()),
        174 => op_checkmultisig(stack, z.unwrap()),
        175 => op_checkmultisigverify(stack, z.unwrap()),
        176 => op_nop(stack),
        177 => false, //"OP_CHECKLOCKTIMEVERIFY",
        178 => false, //"OP_CHECKSEQUENCEVERIFY",
        179 => op_nop(stack),
        180 => op_nop(stack),
        181 => op_nop(stack),
        182 => op_nop(stack),
        183 => op_nop(stack),
        184 => op_nop(stack),
        185 => op_nop(stack),
        _ => panic!("invalid code"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{bigint_from_hex, decode_hex, encode_hex};

    #[test]
    pub fn test_op_hash160() {
        let mut stack = vec![String::from("hello world").as_bytes().to_vec()];
        assert!(op_hash160(&mut stack));
        assert!(encode_hex(&stack[0]) == "d7d5ee7824ff93f94c3055af9382c86c68b5ca92");
    }

    #[test]
    pub fn test_op_checksig() {
        let z = bigint_from_hex("7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d")
            .unwrap();
        let sec = decode_hex("04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34").unwrap();
        let sig = decode_hex("3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601").unwrap();
        let mut stack = vec![sig, sec];
        assert!(op_checksig(&mut stack, &z));
        let ret = decode_num(stack[0].clone());
        assert!(ret == 1);
    }
}
