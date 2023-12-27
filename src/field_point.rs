use super::field_element::FieldElement;
use crate::utils::{bigint_to_bytes, new_bigint};
use crate::utils::{encode_base58, hash160, hash256};
use anyhow::{bail, Result};
use num::traits::Pow;
use num::BigInt;
use num::One;
use num::Zero;
use std::fmt;
use std::ops;
use std::ops::Rem;
use std::str::FromStr;

// 有限域上椭圆曲线上的点
// 椭圆曲线方程： y^2 = x^3 + ax + b
#[derive(Debug, PartialEq, Clone)]
pub struct FieldPoint {
    // x, y 为 None 表示无穷远点
    pub x: Option<FieldElement>,
    pub y: Option<FieldElement>,
    pub a: FieldElement,
    pub b: FieldElement,
}

impl FieldPoint {
    pub fn from(
        x: Option<FieldElement>,
        y: Option<FieldElement>,
        a: FieldElement,
        b: FieldElement,
    ) -> Result<Self> {
        if x.is_none() && y.is_none() {
            return Ok(FieldPoint {
                x: None,
                y: None,
                a,
                b,
            });
        }

        if (x.is_none() && y.is_some()) || (x.is_some() && y.is_none()) {
            bail!("无效输入！");
        }

        let x = x.unwrap();
        let y = y.unwrap();
        if (&y).pow(2) != (&x).pow(3) + &a * &x + &b {
            bail!("点({}, {})不在曲线上！", x, y);
        }

        Ok(FieldPoint {
            x: Some(x),
            y: Some(y),
            a,
            b,
        })
    }

    pub fn is_infinity(&self) -> bool {
        self.x.is_none()
    }

    pub fn sec(&self, compressed: bool) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        match compressed {
            true => {
                // 压缩格式，以0x02或0x03开头
                if self.y.clone().unwrap().num.rem(2) == BigInt::zero() {
                    result.push(2);
                } else {
                    result.push(3);
                }
                result.append(&mut bigint_to_bytes(&self.x.clone().unwrap().num, 32));
                result
            }
            false => {
                // 未压缩格式，以0x04开头
                result.push(4);
                result.append(&mut bigint_to_bytes(&self.x.clone().unwrap().num, 32));
                result.append(&mut bigint_to_bytes(&self.y.clone().unwrap().num, 32));
                result
            }
        }
    }

    pub fn parse_sec(bytes: &[u8]) -> FieldPoint {
        if bytes[0] != 2 && bytes[0] != 3 && bytes[0] != 4 {
            panic!("无效sec格式！");
        }

        // 椭圆曲线参数
        pub const P: &str =
            "115792089237316195423570985008687907853269984665640564039457584007908834671663";
        let prime = BigInt::from_str(P).unwrap();
        let a_field = FieldElement::from_bigint(BigInt::zero(), prime.clone()).unwrap();
        let b_field = FieldElement::from_bigint(new_bigint(7), prime.clone()).unwrap();

        // 解析坐标
        let x = BigInt::from_bytes_be(num::bigint::Sign::Plus, &bytes[1..33]);
        let x_field = FieldElement::from_bigint(x, prime.clone()).unwrap();
        let mut y_field = match bytes[0] == 4 {
            true => {
                // sec 曲线：y^2 = x^3 + B
                // 对于压缩格式，我们想求w，已知v以及w^2 = v
                // w^2 = w^2 * 1 = w^2 * w^(n-1) = w^(n+1)
                // => w = w^((n+1)/2) = w^(2*((n+1)/4)) = v^((n+1)/4)
                // 前提是n+1/4为整数，对于sec而言是成立的
                let v = x_field.clone().pow(3) + b_field.clone();
                v.pow((&prime + 1) / 4)
            }
            false => {
                let y = BigInt::from_bytes_be(num::bigint::Sign::Plus, &bytes[33..65]);
                FieldElement::from_bigint(y, prime.clone()).unwrap()
            }
        };

        let even_odd = if bytes[0] == 2 {
            BigInt::zero()
        } else {
            BigInt::one()
        };

        y_field = match y_field.num.clone().rem(2) == even_odd {
            true => y_field,
            false => FieldElement::from_bigint(&prime - &y_field.num, prime.clone()).unwrap(),
        };

        FieldPoint::from(Some(x_field), Some(y_field), a_field, b_field).unwrap()
    }

    pub fn address(&self, compressed: bool, testnet: bool) -> String {
        // 1. 前缀：对于主网，前缀是0x00; 对于测试网，前缀是 0x6f
        let mut bytes: Vec<u8> = if testnet { vec![0x6f] } else { vec![0] };

        // 2. 对sec格式做hash160
        let mut hash160_sec = hash160(&self.sec(compressed));

        // 3. 组合1和2
        bytes.append(&mut hash160_sec);

        // 4. 对3做hash256拿到前四个字符作为校验码
        let mut checksum = hash256(&bytes).as_slice()[..4].to_vec();

        // 5. 把验证码加到3后面，再做base58编码
        bytes.append(&mut checksum);
        encode_base58(&bytes)
    }
}

impl fmt::Display for FieldPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "FieldPoint(infinity)")
        } else {
            write!(
                f,
                "FieldPoint({},{})_{}_{} FieldElement({})",
                &self.x.clone().unwrap().num,
                &self.y.clone().unwrap().num,
                &self.a.num,
                &self.b.num,
                &self.a.prime,
            )
        }
    }
}

// 操作符重载：+
impl ops::Add<FieldPoint> for FieldPoint {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        if self.a != other.a && self.b != other.b {
            panic!("不同曲线的点不能相加！");
        }

        // case 1: 任何点加上无穷远点都等于自身
        if self.is_infinity() {
            return other;
        }
        if other.is_infinity() {
            return self;
        }

        // case 2: 关于x轴对称的两个点相加等于无穷远点
        if self.x == other.x && self.y != other.y {
            return FieldPoint {
                x: None,
                y: None,
                a: self.a,
                b: self.b,
            };
        }

        // case 3: 两个点的x坐标不相同
        if self.x != other.x {
            // s = (y2 - y1) / (x2 - x1)
            // x3 = s^2 - x1 - x2
            // y3 = s(x1 - x3) - y1
            let x1 = self.x.unwrap();
            let y1 = self.y.unwrap();
            let x2 = other.x.unwrap();
            let y2 = other.y.unwrap();

            let s = (&y2 - &y1) / (&x2 - &x1);
            let x3 = (&s).pow(2) - &x1 - &x2;
            let y3 = s * (&x1 - &x3) - &y1;
            return FieldPoint {
                x: Some(x3),
                y: Some(y3),
                a: self.a,
                b: self.b,
            };
        }

        // case 4: 两个点相同(self == other)，y为0，无法计算斜率
        if self.y.clone().unwrap().num == BigInt::zero() {
            return FieldPoint {
                x: None,
                y: None,
                a: self.a,
                b: self.b,
            };
        }

        // case 5: 两个点相同(self == other)
        // 需要做这个点的切线，找到另一个交点
        let x1 = self.x.unwrap();
        let y1 = self.y.unwrap();

        // s = (3x1^2 + a) / 2y1
        // x3 = s^2 - 2x1
        // y3 = s(x1 - x3) - y1
        let s = (3 * (&x1).pow(2) + &self.a) / (2 * &y1);
        let x3 = (&s).pow(2) - 2 * &x1;
        let y3 = s * (&x1 - &x3) - y1;
        return FieldPoint {
            x: Some(x3),
            y: Some(y3),
            a: self.a,
            b: self.b,
        };
    }
}

impl ops::Add<&FieldPoint> for FieldPoint {
    type Output = Self;

    fn add(self, other: &Self) -> Self {
        self.add(other.clone())
    }
}

impl ops::Add<FieldPoint> for &FieldPoint {
    type Output = FieldPoint;

    fn add(self, other: FieldPoint) -> Self::Output {
        self.clone().add(other)
    }
}

impl ops::Add<&FieldPoint> for &FieldPoint {
    type Output = FieldPoint;

    fn add(self, other: &FieldPoint) -> Self::Output {
        self.clone().add(other.clone())
    }
}

// 操作符重载：*
impl ops::Mul<FieldPoint> for BigInt {
    type Output = FieldPoint;

    fn mul(self, rhs: FieldPoint) -> FieldPoint {
        let mut coef = self;
        let mut current = rhs;
        // 从无穷远点开始
        let mut result =
            FieldPoint::from(None, None, current.a.clone(), current.b.clone()).unwrap();
        // 二进制展开
        while coef.clone() != BigInt::zero() {
            if coef.clone() & BigInt::one() == BigInt::one() {
                result = &result + &current;
            }
            current = &current + &current;
            coef >>= 1;
        }
        result
    }
}

impl ops::Mul<&FieldPoint> for BigInt {
    type Output = FieldPoint;

    fn mul(self, rhs: &FieldPoint) -> FieldPoint {
        self.mul(rhs.clone())
    }
}

impl ops::Mul<&FieldPoint> for u64 {
    type Output = FieldPoint;

    fn mul(self, rhs: &FieldPoint) -> FieldPoint {
        new_bigint(self as i64).mul(rhs.clone())
    }
}

impl ops::Mul<FieldPoint> for u64 {
    type Output = FieldPoint;

    fn mul(self, rhs: FieldPoint) -> FieldPoint {
        new_bigint(self as i64).mul(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn ecc_test() {
        let prime = 223;
        let a = FieldElement::from_i64(0, prime).unwrap();
        let b = FieldElement::from_i64(7, prime).unwrap();
        let valid_pts = vec![
            FieldPoint::from(
                Some(FieldElement::from_i64(192, prime).unwrap()),
                Some(FieldElement::from_i64(105, prime).unwrap()),
                a.clone(),
                b.clone(),
            ),
            FieldPoint::from(
                Some(FieldElement::from_i64(17, prime).unwrap()),
                Some(FieldElement::from_i64(56, prime).unwrap()),
                a.clone(),
                b.clone(),
            ),
            FieldPoint::from(
                Some(FieldElement::from_i64(1, prime).unwrap()),
                Some(FieldElement::from_i64(193, prime).unwrap()),
                a.clone(),
                b.clone(),
            ),
        ];
        let invalid_pts = vec![
            FieldPoint::from(
                Some(FieldElement::from_i64(200, prime).unwrap()),
                Some(FieldElement::from_i64(119, prime).unwrap()),
                a.clone(),
                b.clone(),
            ),
            FieldPoint::from(
                Some(FieldElement::from_i64(42, prime).unwrap()),
                Some(FieldElement::from_i64(99, prime).unwrap()),
                a.clone(),
                b.clone(),
            ),
        ];
        for pt in valid_pts {
            assert!(pt.is_ok());
        }
        for pt in invalid_pts {
            assert!(pt.is_err());
        }
    }

    #[test]
    pub fn ecc_test_add() {
        let prime = 223;
        let a = FieldElement::from_i64(0, prime).unwrap();
        let b = FieldElement::from_i64(7, prime).unwrap();

        // （170， 142) + (60, 139)
        let x1 = FieldElement::from_i64(170, prime).unwrap();
        let y1 = FieldElement::from_i64(142, prime).unwrap();
        let x2 = FieldElement::from_i64(60, prime).unwrap();
        let y2 = FieldElement::from_i64(139, prime).unwrap();
        let p1 = FieldPoint::from(Some(x1), Some(y1), a.clone(), b.clone()).unwrap();
        let p2 = FieldPoint::from(Some(x2), Some(y2), a.clone(), b.clone()).unwrap();
        println!("{} + {} = {}", &p1, &p2, &p1 + &p2);

        // (47 71) + (17, 56)
        let x1 = FieldElement::from_i64(47, prime).unwrap();
        let y1 = FieldElement::from_i64(71, prime).unwrap();
        let x2 = FieldElement::from_i64(17, prime).unwrap();
        let y2 = FieldElement::from_i64(56, prime).unwrap();
        let p1 = FieldPoint::from(Some(x1), Some(y1), a.clone(), b.clone()).unwrap();
        let p2 = FieldPoint::from(Some(x2), Some(y2), a.clone(), b.clone()).unwrap();
        println!("{} + {} = {}", &p1, &p2, &p1 + &p2);

        // （143， 98) + (76, 66)
        let x1 = FieldElement::from_i64(143, prime).unwrap();
        let y1 = FieldElement::from_i64(98, prime).unwrap();
        let x2 = FieldElement::from_i64(76, prime).unwrap();
        let y2 = FieldElement::from_i64(66, prime).unwrap();
        let p1 = FieldPoint::from(Some(x1), Some(y1), a.clone(), b.clone()).unwrap();
        let p2 = FieldPoint::from(Some(x2), Some(y2), a.clone(), b.clone()).unwrap();
        println!("{} + {} = {}", &p1, &p2, &p1 + &p2);
    }

    #[test]
    pub fn ecc_test_mul() {
        let prime = 223;
        let a = FieldElement::from_i64(0, prime).unwrap();
        let b = FieldElement::from_i64(7, prime).unwrap();

        let x1 = FieldElement::from_i64(15, prime).unwrap();
        let y1 = FieldElement::from_i64(86, prime).unwrap();
        let p1 = FieldPoint::from(Some(x1), Some(y1), a.clone(), b.clone()).unwrap();
        println!("{}", 7 * p1);
    }
}
