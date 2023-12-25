use super::*;
use anyhow::Result;

pub struct S256Point(Point);

// S256 椭圆曲线参数
const A: i64 = 0;
const B: i64 = 7;
// P = 2**256 - 2**32 - 977
const P: &str = "115792089237316195423570985008687907853269984665640564039457584007908834671663";
// N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
const N: &str = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
// 原点
const GX: &str = "55066263022277343669578718895168534326250603453777594175500187360389116729240";
const GY: &str = "32670510020758816978083085130507043184471273380659243275938904335757337482424";

impl S256Point {
    pub fn new(x: Option<FieldElement>, y: Option<FieldElement>) -> Result<Self> {
        let a = FieldElement::from_bigint(new_bigint(A), BigInt::from_str(P).unwrap()).unwrap();
        let b = FieldElement::from_bigint(new_bigint(B), BigInt::from_str(P).unwrap()).unwrap();

        match Point::from(x, y, a, b) {
            Ok(p) => Ok(S256Point(p)),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use num::traits::{Euclid};

    use super::*;

    #[test]
    pub fn test_ecc_parameters() {
        let big_gx = BigInt::from_str(GX).unwrap();
        let big_gy = BigInt::from_str(GY).unwrap();
        let prime = BigInt::from_str(P).unwrap();
        let big_n = BigInt::from_str(N).unwrap();
        let big_a = new_bigint(A);
        let big_b = new_bigint(B);

        // point on curve
        assert!(
            (&big_gy).pow(2u32).rem_euclid(&prime)
                == ((&big_gx).pow(3u32) + &big_b).rem_euclid(&prime)
        );

        let x = FieldElement::from_bigint(big_gx, prime.clone()).unwrap();
        let y = FieldElement::from_bigint(big_gy, prime.clone()).unwrap();
        let a = FieldElement::from_bigint(big_a, prime.clone()).unwrap();
        let b = FieldElement::from_bigint(big_b, prime.clone()).unwrap();

        let g = Point::from(Some(x), Some(y), a, b).unwrap();
        println!("G: {}", g);
        println!("n*G: {}", big_n * g);
    }
}
