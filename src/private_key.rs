use num::{
    traits::{Euclid, ToBytes},
    BigInt, One, Zero,
};

use crate::{
    field_point::FieldPoint,
    finite_cyclic_group::FiniteCyclicGroup,
    signature::Signature,
    utils::{bigint_to_bytes, encode_hex, hmac_sha256},
};

pub struct PrivateKey {
    pub secrect: BigInt,
    pub point: FieldPoint,
    pub group: FiniteCyclicGroup,
}

impl PrivateKey {
    pub fn new(secrect: BigInt) -> PrivateKey {
        let group = FiniteCyclicGroup::from_secp256k1();
        PrivateKey {
            secrect: secrect.clone(),
            point: group.generate(&secrect),
            group,
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
        let s = ((&z + &r * self.secrect) * &k_inv).rem_euclid(&self.group.n);
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

        let z_bytes = bigint_to_bytes(&reduced_z, 32);
        let secrect_bytes = bigint_to_bytes(&self.secrect, 32);

        let mut data1: Vec<u8> = vec![];
        data1.append(&mut v.clone());
        data1.push(0);
        data1.append(&mut secrect_bytes.clone());
        data1.append(&mut z_bytes.clone());
        k = hmac_sha256(&k, &data1);
        v = hmac_sha256(&k, &v);

        let mut data2: Vec<u8> = vec![];
        data2.append(&mut v.clone());
        data2.push(1);
        data2.append(&mut secrect_bytes.clone());
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

    pub fn hex(self) -> String {
        String::from("0x") + &encode_hex(&self.secrect.to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::utils::{bigint_from_hex, decode_hex, hash256, new_bigint, bigint_to_hex};

    use super::*;

    #[test]
    pub fn test_deterministic_k() {
        let key = PrivateKey::new(new_bigint(100));
        let k = key.deterministic_k(&new_bigint(10012));
        let target =
            "42695049216645585062640330142435867217220364746155645266231669475379433942288";
        assert!(k == BigInt::from_str(target).unwrap());

        let secrect = BigInt::from_str(
            "61487454132488076575180963038085065582507398223936223029494779138210615773559",
        )
        .unwrap();
        let key = PrivateKey::new(secrect);
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
        let key = PrivateKey::new(new_bigint(12345));
        let z = bigint_from_hex(&hash256(b"Programming Bitcoin!")).unwrap();
        let sig = key.sign(z.clone());
        println!("z: {}", bigint_to_hex(z).unwrap());
        println!("r: {}", bigint_to_hex(sig.r).unwrap());
        println!("s: {}", bigint_to_hex(sig.s).unwrap());
    }
}
