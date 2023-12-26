use num::{traits::Euclid, BigInt};

use crate::{finite_cyclic_group::FiniteCyclicGroup, utils::bigint_from_hex};
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
}

mod tests {
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
}
