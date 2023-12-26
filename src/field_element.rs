use super::utils::new_bigint;
use anyhow::{bail, Result};
use num::{
    bigint::BigInt,
    traits::{Euclid, One, Pow, Zero},
};
use std::ops;
use std::{fmt, str::FromStr};

// 有限域元素
#[derive(Debug, PartialEq, Clone)]
pub struct FieldElement {
    pub prime: BigInt, // 有限域的阶
    pub num: BigInt,   // 元素
}

impl FieldElement {
    pub fn from_bigint(num: BigInt, prime: BigInt) -> Result<Self> {
        if num >= prime || num < BigInt::zero() {
            bail!("元素{}不在范围[0,  {}]内！", num, prime - 1);
        }

        Ok(FieldElement { num, prime })
    }

    pub fn from_i64(num: i64, prime: i64) -> Result<Self> {
        FieldElement::from_bigint(new_bigint(num), new_bigint(prime))
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FieldElement_{}({})", self.prime, self.num)
    }
}

// 操作符重载: pow
impl Pow<BigInt> for FieldElement {
    type Output = FieldElement;

    fn pow(self, rhs: BigInt) -> Self::Output {
        // 根据费马小定理：a^(p-1) = 1
        // 可以把指数加上或者减去任意个p-1
        let e = rhs.rem_euclid(&(self.prime.clone() - BigInt::one()));

        FieldElement {
            num: self.num.modpow(&e, &self.prime),
            prime: self.prime,
        }
    }
}

impl Pow<&BigInt> for FieldElement {
    type Output = FieldElement;

    fn pow(self, rhs: &BigInt) -> Self::Output {
        self.pow(rhs.clone())
    }
}

impl Pow<BigInt> for &FieldElement {
    type Output = FieldElement;

    fn pow(self, rhs: BigInt) -> Self::Output {
        self.clone().pow(rhs)
    }
}

impl Pow<&BigInt> for &FieldElement {
    type Output = FieldElement;

    fn pow(self, rhs: &BigInt) -> Self::Output {
        self.clone().pow(rhs.clone())
    }
}

impl Pow<i64> for FieldElement {
    type Output = FieldElement;

    fn pow(self, rhs: i64) -> Self::Output {
        self.pow(new_bigint(rhs))
    }
}

impl Pow<i64> for &FieldElement {
    type Output = FieldElement;

    fn pow(self, rhs: i64) -> Self::Output {
        self.clone().pow(new_bigint(rhs))
    }
}

// 操作符重载: +
impl ops::Add<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: Self) -> Self {
        if self.prime != other.prime {
            panic!("不同阶的元素不能相加！");
        }

        FieldElement {
            num: (self.num + other.num).rem_euclid(&self.prime),
            prime: self.prime,
        }
    }
}

impl ops::Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: &Self) -> Self {
        self.add(other.clone())
    }
}

impl ops::Add<FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: FieldElement) -> FieldElement {
        self.clone().add(other)
    }
}

impl ops::Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        self.clone().add(other.clone())
    }
}

// 操作符重载: -
impl ops::Sub<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        if self.prime != other.prime {
            panic!("不同阶的元素不能相减！");
        }

        FieldElement {
            num: (self.num - other.num).rem_euclid(&self.prime),
            prime: self.prime,
        }
    }
}

impl ops::Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        self.sub(other.clone())
    }
}

impl ops::Sub<FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        self.clone().sub(other)
    }
}

impl ops::Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        self.clone().sub(other.clone())
    }
}

// 操作符重载: *
impl ops::Mul<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        if self.prime != rhs.prime {
            panic!("不同阶的元素不能相减！");
        }

        FieldElement {
            num: (self.num * rhs.num).rem_euclid(&self.prime),
            prime: self.prime,
        }
    }
}

impl ops::Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        self.mul(rhs.clone())
    }
}

impl ops::Mul<FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        self.clone().mul(rhs)
    }
}

impl ops::Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        self.clone().mul(rhs.clone())
    }
}

impl ops::Mul<&FieldElement> for i64 {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::from_bigint(new_bigint(self), rhs.prime.clone()).unwrap() * rhs
    }
}

impl ops::Mul<FieldElement> for i64 {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        FieldElement::from_bigint(new_bigint(self), rhs.prime.clone()).unwrap() * rhs
    }
}

impl ops::Mul<&FieldElement> for BigInt {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::from_bigint(self, rhs.prime.clone()).unwrap() * rhs
    }
}

impl ops::Mul<FieldElement> for BigInt {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        FieldElement::from_bigint(self, rhs.clone().prime).unwrap() * rhs
    }
}

impl ops::Mul<&FieldElement> for &BigInt {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::from_bigint(self.clone(), rhs.prime.clone()).unwrap() * rhs
    }
}

impl ops::Mul<FieldElement> for &BigInt {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        FieldElement::from_bigint(self.clone(), rhs.clone().prime).unwrap() * rhs
    }
}

// 操作符重载: /

// 根据费马小定理： n^(p-1) % p = 1
// 有限域内的除法：
// a / b = a * b^-1 = a * b^-1 * b^(p-1) = a * b^(p-2)
impl ops::Div<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn div(self, rhs: FieldElement) -> FieldElement {
        if self.prime != rhs.prime {
            panic!("不同阶的元素不能相除！");
        }

        // 注意这里的pow运算不能用BigInt内置的，必须使用FieldElement来运算，否则会溢出
        self.num * rhs.pow(&(self.prime - 2u32))
    }
}

impl ops::Div<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn div(self, rhs: &FieldElement) -> FieldElement {
        self.div(rhs.clone())
    }
}

impl ops::Div<FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn div(self, rhs: FieldElement) -> FieldElement {
        self.clone().div(rhs)
    }
}

impl ops::Div<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn div(self, rhs: &FieldElement) -> FieldElement {
        self.clone().div(rhs.clone())
    }
}

#[cfg(test)]
mod tests {
    use num::ToPrimitive;

    use super::*;

    #[test]
    fn create_field_element() {
        assert!(FieldElement::from_i64(3, 3).is_err());

        let e = FieldElement::from_i64(2, 3).unwrap();
        assert_eq!(e.num.to_i64().unwrap(), 2i64);
        assert_eq!(e.prime.to_i64().unwrap(), 3i64);
        println!("{:?}", e);
        println!("{}", e);
    }

    #[test]
    fn compare_field_element() {
        assert_eq!(
            FieldElement::from_i64(6, 13).unwrap(),
            FieldElement::from_i64(6, 13).unwrap()
        );
        assert_ne!(
            FieldElement::from_i64(6, 13).unwrap(),
            FieldElement::from_i64(1, 13).unwrap()
        );
    }

    #[test]
    fn add_field_element() {
        let a = FieldElement::from_i64(7, 19).unwrap();
        let b = FieldElement::from_i64(8, 19).unwrap();
        let c = FieldElement::from_i64(15, 19).unwrap();
        assert!(a + b == c);

        let a = FieldElement::from_i64(11, 19).unwrap();
        let b = FieldElement::from_i64(17, 19).unwrap();
        let c = FieldElement::from_i64(9, 19).unwrap();
        assert!(a + b == c);
    }

    #[test]
    fn sub_field_element() {
        let a = FieldElement::from_i64(11, 19).unwrap();
        let b = FieldElement::from_i64(9, 19).unwrap();
        let c = FieldElement::from_i64(2, 19).unwrap();
        assert!(a - b == c);

        let a = FieldElement::from_i64(6, 19).unwrap();
        let b = FieldElement::from_i64(13, 19).unwrap();
        let c = FieldElement::from_i64(12, 19).unwrap();
        assert!(a - b == c);
    }

    #[test]
    fn mul_field_element() {
        let a = FieldElement::from_i64(8, 19).unwrap();
        let b = FieldElement::from_i64(17, 19).unwrap();
        let c = FieldElement::from_i64(3, 19).unwrap();
        assert!(a * b == c);
    }

    #[test]
    fn pow_field_element() {
        let a = FieldElement::from_i64(7, 19).unwrap();
        let b = FieldElement::from_i64(1, 19).unwrap();
        assert!(a.pow(3i64) == b);

        let a = FieldElement::from_i64(9, 19).unwrap();
        let b = FieldElement::from_i64(7, 19).unwrap();
        assert!(a.pow(12i64) == b);
    }

    #[test]
    fn exercise_5() {
        // 阶数为质数的特性：集合乘上k后不变
        println!("练习5: {{k*0, k*1, k*2, ..., k*18}}");
        for k in vec![1, 3, 7, 13, 18] {
            print!("k={}, {{", k);
            for i in 0..19 {
                let num = FieldElement::from_i64(k as i64, 19i64).unwrap()
                    * FieldElement::from_i64(i as i64, 19i64).unwrap();
                //let num = (k * i as i64).rem_euclid(19);
                print!("{},", num);
            }
            println!("}}");
        }
    }

    #[test]
    fn exercise_7() {
        println!("练习7：{{1^(p-1), 2^(p-1), ..., (p-1)^(p-1)}}");
        for p in vec![7i64, 11, 17, 31] {
            print!("p={}, {{", p);
            for i in 1i64..p {
                let num = FieldElement::from_i64(i, p).unwrap().pow(p - 1);
                // let big_p = BigInt::from_i32(p).unwrap();
                // let big_i = BigInt::from_i32(i).unwrap();
                // let num = big_i.modpow(&(big_p.clone() - BigInt::one()), &big_p);
                print!("{},", num);
            }
            println!("}}");
        }
    }

    #[test]
    fn div_field_element() {
        let a = FieldElement::from_i64(2, 19).unwrap();
        let b = FieldElement::from_i64(7, 19).unwrap();
        let c = FieldElement::from_i64(3, 19).unwrap();
        assert!(a / b == c);

        let a = FieldElement::from_i64(7, 19).unwrap();
        let b = FieldElement::from_i64(5, 19).unwrap();
        let c = FieldElement::from_i64(9, 19).unwrap();
        assert!(a / b == c);
    }

    #[test]
    fn exercise_8() {
        // 3/24
        let a = FieldElement::from_i64(3, 31).unwrap();
        let b = FieldElement::from_i64(24, 31).unwrap();
        let c = FieldElement::from_i64(4, 31).unwrap();
        assert!(&a / &b == c);
        assert!(a == b * c);

        // 17^(-3)
        let a = FieldElement::from_i64(1, 31).unwrap();
        let b = FieldElement::from_i64(17, 31).unwrap();
        let c = FieldElement::from_i64(29, 31).unwrap();
        assert!(&a / (&b).pow(3) == c);
        assert!(a == (&b).pow(3) * &c);
        assert!(b.pow(-3) == c);

        // 4^(-4) * 11
        let a = FieldElement::from_i64(1, 31).unwrap();
        let b = FieldElement::from_i64(4, 31).unwrap();
        let c = FieldElement::from_i64(11, 31).unwrap();
        let d = (&b).pow(-4) * &c;
        assert!(a / b.pow(4) * c == d);
    }
}
