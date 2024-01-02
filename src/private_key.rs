use anyhow::{bail, Result};
use num::{
    traits::{Euclid, ToBytes},
    BigInt, One,
};

use crate::{
    field_point::FieldPoint,
    finite_cyclic_group::FiniteCyclicGroup,
    signature::Signature,
    utils::{bigint_to_bytes, decode_base58, encode_base58, encode_hex, hash256, hmac_sha256},
};

#[derive(Debug, PartialEq, Clone)]
pub struct PrivateKey {
    pub secret: BigInt,
    pub point: FieldPoint,
    pub group: FiniteCyclicGroup,
    compressed: bool, // 是否为SEC压缩格式
    testnet: bool,    // 是否为测试网的地址
}

impl PrivateKey {
    pub fn new(secret: BigInt, compressed: bool, testnet: bool) -> PrivateKey {
        let group = FiniteCyclicGroup::from_secp256k1();
        PrivateKey {
            secret: secret.clone(),
            point: group.generate(&secret),
            group,
            compressed,
            testnet,
        }
    }

    pub fn sign(self, z: BigInt) -> Signature {
        let k = self.deterministic_k(&z);

        // r is the x coordinate of kG
        let r = self.group.generate(&k).x.unwrap().num;
        // uG + vP = kG
        // z/s + er/s = k
        // s = (z + er) / k
        let k_inv = (&k).modpow(&(&self.group.n - 2), &self.group.n);
        let s = ((&z + &r * &self.secret) * &k_inv).rem_euclid(&self.group.n);
        if s > &self.group.n / 2 {
            Signature {
                r,
                s: &self.group.n - s,
            }
        } else {
            Signature { r, s }
        }
    }

    // 对于每一对(z, secrect), k是确定唯一的
    pub fn deterministic_k(&self, z: &BigInt) -> BigInt {
        let mut k: Vec<u8> = vec![0; 32];
        let mut v: Vec<u8> = vec![1; 32];

        let reduced_z = if z > &self.group.n {
            z - &self.group.n
        } else {
            z.clone()
        };

        let z_bytes = bigint_to_bytes(&reduced_z, 32, "big");
        let secret_bytes = bigint_to_bytes(&self.secret, 32, "big");

        let mut data1: Vec<u8> = vec![];
        data1.append(&mut v.clone());
        data1.push(0);
        data1.append(&mut secret_bytes.clone());
        data1.append(&mut z_bytes.clone());
        k = hmac_sha256(&k, &data1);
        v = hmac_sha256(&k, &v);

        let mut data2: Vec<u8> = vec![];
        data2.append(&mut v.clone());
        data2.push(1);
        data2.append(&mut secret_bytes.clone());
        data2.append(&mut z_bytes.clone());
        k = hmac_sha256(&k, &data2);
        v = hmac_sha256(&k, &v);

        loop {
            v = hmac_sha256(&k, &v);
            let candidate = BigInt::from_bytes_be(num::bigint::Sign::Plus, &v);
            if candidate >= BigInt::one() && candidate < self.group.n {
                return candidate;
            }
            let mut data: Vec<u8> = vec![];
            data.append(&mut v.clone());
            data.push(0);
            k = hmac_sha256(&k, &data);
            v = hmac_sha256(&k, &v);
        }
    }

    pub fn wif(&self) -> String {
        //  1. 前缀：对于主网，前缀为0x80，对于测试网，前缀为0xef
        let mut bytes: Vec<u8> = if self.testnet { vec![0xef] } else { vec![0x80] };

        // 2. serect以大端方式编码为32字节
        let mut s_bytes = bigint_to_bytes(&self.secret, 32, "big");
        bytes.append(&mut s_bytes);

        // 3.如果public key的sec编码方式是压缩的，添加0x01标记
        if self.compressed {
            bytes.push(0x01);
        }

        // 4. 前3步的结果combined之后，做hash256，拿到前四个字符的校验码
        let mut checksum: Vec<u8> = hash256(&bytes).as_slice()[..4].to_vec();

        // 5. 3的结果加上校验码，做base58编码
        bytes.append(&mut checksum);
        encode_base58(&bytes)
    }

    pub fn from_wif(wif: String) -> Result<PrivateKey> {
        // base58解码
        let bytes = decode_base58(&wif);
        // 校验
        let len = bytes.len();
        if len != 38 && len != 37 {
            bail!("私钥错误！");
        }

        let checksum = hash256(&bytes.as_slice()[..len - 4])[..4].to_vec();
        if checksum != bytes[len - 4..].to_vec() {
            bail!("私钥错误！");
        }

        let is_testnet: bool;
        match bytes[0] {
            0x80 => {
                println!("导入主网私钥");
                is_testnet = false;
            }
            0xef => {
                println!("导入测试网私钥");
                is_testnet = true;
            }
            _ => bail!("私钥格式错误！"),
        };

        if bytes[len - 5] == 0x01 {
            if len != 38 {
                bail!("私钥错误！");
            }
            // 公钥是压缩的
            Ok(PrivateKey::new(
                BigInt::from_bytes_be(num::bigint::Sign::Plus, &bytes.as_slice()[1..33]),
                true,
                is_testnet,
            ))
        } else {
            if len != 37 {
                bail!("私钥错误！");
            }
            Ok(PrivateKey::new(
                BigInt::from_bytes_be(num::bigint::Sign::Plus, &bytes.as_slice()[1..33]),
                false,
                is_testnet,
            ))
        }
    }

    pub fn hex(&self) -> String {
        String::from("0x") + &encode_hex(&self.secret.to_be_bytes())
    }

    pub fn address(&self) -> String {
        self.point.address(self.compressed, self.testnet)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num::FromPrimitive;

    use crate::utils::{decode_hex, hash256, Hex};

    use super::*;

    #[test]
    pub fn test_deterministic_k() {
        let key = PrivateKey::new(BigInt::from_i64(100).unwrap(), true, true);
        let k = key.deterministic_k(&BigInt::from_i64(10012).unwrap());
        let target =
            "42695049216645585062640330142435867217220364746155645266231669475379433942288";
        assert!(k == BigInt::from_str(target).unwrap());

        let secrect = BigInt::from_str(
            "61487454132488076575180963038085065582507398223936223029494779138210615773559",
        )
        .unwrap();
        let key = PrivateKey::new(secrect, true, true);
        let z = BigInt::from_str(
            "35224773764014901550789983228161827426520721227593273774884622297661387815467",
        )
        .unwrap();
        let k = key.deterministic_k(&z);
        let target =
            "82201750424828010361691422018693420038273380306457468260098575684456174963810";
        assert!(k == BigInt::from_str(target).unwrap());
    }

    #[test]
    pub fn test_sign() {
        let key = PrivateKey::new(BigInt::from_i64(12345).unwrap(), true, true);
        let z = BigInt::from_bytes_be(num::bigint::Sign::Plus, &hash256(b"Programming Bitcoin!"));
        let sig = key.sign(z.clone());
        println!("z: {}", z.to_hex());
        println!("r: {}", sig.r.to_hex());
        println!("s: {}", sig.s.to_hex());
    }

    #[test]
    pub fn test_sec() {
        let secret = BigInt::from_i64(5000).unwrap();
        let key = PrivateKey::new(secret, true, true);

        assert!(
            encode_hex(&key.point.sec(false)) == "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10");
        let point = FieldPoint::parse_sec(&decode_hex("04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10").unwrap());
        assert!(point.x.unwrap() == key.point.x.unwrap());
        assert!(point.y.unwrap() == key.point.y.unwrap());

        let key = PrivateKey::new(BigInt::from_i64(2018).unwrap().pow(5), true, true);
        assert!(
            encode_hex(&key.point.sec(false)) == "04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06"
        );
        let point = FieldPoint::parse_sec(&decode_hex("04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06").unwrap());
        assert!(point.x.unwrap() == key.point.x.unwrap());
        assert!(point.y.unwrap() == key.point.y.unwrap());

        let key = PrivateKey::new(BigInt::from_hex("deadbeef12345"), true, true);
        assert!(
            encode_hex(&key.point.sec(false)) == "04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121"
        );
        let point = FieldPoint::parse_sec(&decode_hex("04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121").unwrap());
        assert!(point.x.unwrap() == key.point.x.unwrap());
        assert!(point.y.unwrap() == key.point.y.unwrap());
    }

    #[test]
    pub fn test_address() {
        let secret = BigInt::from_i64(5002).unwrap();
        let key = PrivateKey::new(secret, false, true);
        let address = key.address();
        assert!(address == "mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA");

        let key = PrivateKey::new(BigInt::from_i64(2020).unwrap().pow(5), true, true);
        let address = key.address();
        assert!(address == "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH");

        let key = PrivateKey::new(BigInt::from_hex("12345deadbeef"), true, false);
        let address = key.address();
        assert!(address == "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1");
    }

    #[test]
    pub fn test_wif() {
        let secret = BigInt::from_i64(5003).unwrap();
        let key = PrivateKey::new(secret.clone(), true, true);
        let wif = key.wif();
        assert!(wif == "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK");
        // parse from wif
        let key2 = PrivateKey::from_wif(wif).unwrap();
        println!("secrect: {}", key2.secret);
        assert!(key2.secret == secret);

        let secret = BigInt::from_i64(2021).unwrap().pow(5);
        let key = PrivateKey::new(secret.clone(), false, true);
        let wif = key.wif();
        assert!(wif == "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic");
        let key2 = PrivateKey::from_wif(wif).unwrap();
        assert!(key2.secret == secret);

        let secret = BigInt::from_hex("54321deadbeef");
        let key = PrivateKey::new(secret.clone(), true, false);
        let wif = key.wif();
        assert!(wif == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a");
        let key2 = PrivateKey::from_wif(wif).unwrap();
        assert!(key2.secret == secret);
    }

    #[test]
    pub fn test_create_address() {
        let passphrase = b"jimmy@programmingblockchain.com my secret";
        let secrect =
            BigInt::from_bytes_le(num::bigint::Sign::Plus, &hash256(passphrase.as_slice()));
        let key = PrivateKey::new(secrect, true, true);
        assert!(key.address() == "mft9LRNtaBNtpkknB8xgm17UvPedZ4ecYL");
    }
}
