use std::fmt;

use num::{traits::Euclid, BigInt};

use crate::{finite_cyclic_group::FiniteCyclicGroup, utils::bigint_from_hex};

#[derive(Debug, PartialEq, Clone)]
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

impl Signature {
    pub fn from_hex(r: &str, s: &str) -> Signature {
        if !r.starts_with("0x") || !s.starts_with("0x") {
            panic!("十六进制字符串必须以0x开头");
        }
        Signature {
            r: bigint_from_hex(&r[2..]).unwrap(),
            s: bigint_from_hex(&s[2..]).unwrap(),
        }
    }

    pub fn from_der(bytes: &[u8]) -> Signature {
        let mut pos = 0;
        // der标记位
        if bytes[pos] != 0x30 {
            panic!("无效的签名1！");
        }
        pos += 1;

        // 签名长度
        let len = bytes[pos];
        if len + 2 != bytes.len() as u8 {
            panic!("无效的签名2！");
        }
        pos += 1;

        // r标记
        let marker = bytes[pos];
        if marker != 0x02 {
            panic!("无效的签名3！");
        }
        pos += 1;

        // r长度
        let r_length = bytes[pos] as usize;
        pos += 1;

        // r数据
        let r = BigInt::from_bytes_be(num::bigint::Sign::Plus, &bytes[pos..r_length + pos]);
        pos += r_length;

        // s 标记
        let marker = bytes[pos];
        if marker != 0x02 {
            panic!("无效的签名4！");
        }
        pos += 1;

        // s 长度
        let s_length = bytes[pos] as usize;
        pos += 1;

        // s 数据
        let s = BigInt::from_bytes_be(num::bigint::Sign::Plus, &bytes[pos..s_length + pos]);
        if bytes.len() != 6 + s_length + r_length {
            panic!("签名过长！");
        }
        Signature { r, s }
    }

    pub fn verify_bigint(&self, z: &BigInt, pub_key_x: &BigInt, pub_key_y: &BigInt) -> bool {
        let group = FiniteCyclicGroup::from_secp256k1();

        // check uG + vP = kG
        // u = z/s, v = r/s
        let s_inv = &self.s.modpow(&(&group.n - 2), &group.n);
        let u = (z * s_inv).rem_euclid(&group.n);
        let v = (&self.r * s_inv).rem_euclid(&group.n);
        let ug = group.generate(&u);
        let vg = group.generate_from_point(&v, pub_key_x, pub_key_y);
        match (ug + vg).x {
            Some(x) => x.num == self.r,
            None => false,
        }
    }

    // 十六进制字符串以0x开头
    pub fn verify(&self, z: &str, pub_key_x: &str, pub_key_y: &str) -> bool {
        if !z.starts_with("0x") || !pub_key_x.starts_with("0x") || !pub_key_y.starts_with("0x") {
            panic!("十六进制字符串必须以0x开头");
        }

        self.verify_bigint(
            &bigint_from_hex(&z[2..]).unwrap(),
            &bigint_from_hex(&pub_key_x[2..]).unwrap(),
            &bigint_from_hex(&pub_key_y[2..]).unwrap(),
        )
    }

    pub fn der(&self) -> Vec<u8> {
        // DER 签名以0x30开头
        let mut result: Vec<u8> = vec![0x30];

        // 第二个byte记录剩余签名的长度，先设为0
        result.push(0);

        // 标记位： 0x02
        result.push(0x02);

        // 编码r，大端法转为bytes，如果第一个byte的第一个bit为1的话（byte >= 0x80）说明r是负数，
        // 需要设置符号标记位0x00，但是对于ecsda签名来说，所有r都是正数
        let (_, mut r_bytes) = BigInt::to_bytes_be(&self.r);
        if r_bytes[0] >= 0x80 {
            result.push(r_bytes.len() as u8 + 1);
            result.push(0);
        } else {
            result.push(r_bytes.len() as u8);
        }
        result.append(&mut r_bytes);

        // 标记为, 0x02
        result.push(0x02);

        // 编码s
        let (_, mut s_bytes) = BigInt::to_bytes_be(&self.s);
        if s_bytes[0] >= 0x80 {
            result.push(s_bytes.len() as u8 + 1);
            result.push(0);
        } else {
            result.push(s_bytes.len() as u8);
        }
        result.append(&mut s_bytes);

        // 更新第二个byte
        result[1] = (result.len() - 2) as u8;
        result
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signature({},{})", &self.r, &self.s,)
    }
}

mod tests {
    use crate::utils::{decode_hex, encode_hex};

    use super::*;

    #[test]
    pub fn test_sig_verify() {
        let pub_key_x = "0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c";
        let pub_key_y = "0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34";

        let r1 = "0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395";
        let z1 = "0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60";
        let s1 = "0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4";
        let signature1 = Signature::from_hex(r1, s1);
        assert!(signature1.verify(z1, pub_key_x, pub_key_y));

        let r2 = "0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c";
        let z2 = "0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d";
        let s2 = "0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
        let signature2 = Signature::from_hex(r2, s2);
        assert!(signature2.verify(z2, pub_key_x, pub_key_y));
    }

    #[test]
    pub fn test_der() {
        let r = "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6";
        let s = "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        let sig_hex = "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        let sig = Signature {
            r: bigint_from_hex(&r[2..]).unwrap(),
            s: bigint_from_hex(&s[2..]).unwrap(),
        };
        println!("sig: {}", encode_hex(&sig.der()));
        assert!(encode_hex(&sig.der()) == sig_hex);

        // parse
        let sig2 = Signature::from_der(&decode_hex(sig_hex).unwrap());
        println!("sig: {:}, sig2: {}", sig, sig2);
        assert!(sig == sig2);
    }
}
