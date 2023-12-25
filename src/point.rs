use anyhow::bail;
use anyhow::Result;
use num::Zero;
use num:: BigInt;
use num::traits::Pow;
use std::fmt;
use std::ops;

// use crate::utils::new_bigint;

use super::field_element::FieldElement;

// const P: BigInt = new_bigint(2).pow(256u32) - new_bigint(2).pow(32u32) - 977;
// const A: FieldElement = FieldElement::from_bigint(BigInt::zero(), P).unwrap();
const P: BigInt = BigInt::from_bytes_le(num::bigint::Sign::Plus, vec![101, 4].as_slice());

// 椭圆曲线上的点
// 椭圆曲线方程： y^2 = x^3 + ax + b
#[derive(Debug, PartialEq, Clone)]
pub struct Point {
    // x, y 为 None 表示无穷远点
    pub x: Option<FieldElement>,
    pub y: Option<FieldElement>,
    pub a: FieldElement,
    pub b: FieldElement,
}

impl Point {
    pub fn from(x: Option<FieldElement>, y: Option<FieldElement>, a: FieldElement, b: FieldElement) -> Result<Self> {
        if x.is_none() && y.is_none() {
            return Ok(Point {
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

        Ok(Point {
            x: Some(x),
            y: Some(y),
            a,
            b,
        })
    }

    pub fn is_infinity(&self) -> bool {
        self.x.is_none()
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "Point(infinity)")
        } else {
            write!(
                f,
                "Point({},{})_{}_{} FieldElement({})",
                &self.x.clone().unwrap().num,
                &self.y.clone().unwrap().num,
                &self.a.num,
                &self.b.num,
                &self.a.prime,
            )
        }
    }
}

impl ops::Add<Point> for Point {
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
            return Point {
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
            return Point {
                x: Some(x3),
                y: Some(y3),
                a: self.a,
                b: self.b,
            };
        }

        // case 4: 两个点相同(self == other)，y为0，无法计算斜率
        if self.y.clone().unwrap().num == BigInt::zero() {
            return Point {
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
        return Point {
            x: Some(x3),
            y: Some(y3),
            a: self.a,
            b: self.b,
        };
    }
}

impl ops::Add<&Point> for Point {
    type Output = Self;

    fn add(self, other: &Self) -> Self {
        self.add(other.clone())
    }
}

impl ops::Add<Point> for &Point {
    type Output = Point;

    fn add(self, other: Point) -> Self::Output {
        self.clone().add(other)
    }
}

impl ops::Add<&Point> for &Point {
    type Output = Point;

    fn add(self, other: &Point) -> Self::Output {
        self.clone().add(other.clone())
    }
}

impl ops::Mul<&Point> for u64 {
    type Output = Point;

    fn mul(self, rhs: &Point) -> Point {
        self.mul(rhs.clone())
    }
}

impl ops::Mul<Point> for u64 {
    type Output = Point;

    fn mul(self, rhs: Point) -> Point {
        let mut coef = self;
        
        let mut current = rhs;
        // 从无穷远点开始
        let mut result = Point::from(None, None, current.a.clone(), current.b.clone()).unwrap();
        while coef != 0 {
            if coef & 1 == 1 {
                result = &result + &current;
            }
            current = &current + &current;
            coef >>= 1;
        }
        result
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
            Point::from(Some(FieldElement::from_i64(192, prime).unwrap()), Some(FieldElement::from_i64(105, prime).unwrap()), a.clone(), b.clone()),
            Point::from(Some(FieldElement::from_i64(17, prime).unwrap()), Some(FieldElement::from_i64(56, prime).unwrap()), a.clone(), b.clone()),
            Point::from(Some(FieldElement::from_i64(1, prime).unwrap()), Some(FieldElement::from_i64(193, prime).unwrap()), a.clone(), b.clone()),
        ];
        let invalid_pts = vec![
            Point::from(Some(FieldElement::from_i64(200, prime).unwrap()), Some(FieldElement::from_i64(119, prime).unwrap()), a.clone(), b.clone()),
            Point::from(Some(FieldElement::from_i64(42, prime).unwrap()), Some(FieldElement::from_i64(99, prime).unwrap()), a.clone(), b.clone()),
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
        let p1 = Point::from(Some(x1), Some(y1), a.clone(), b.clone()).unwrap();
        let p2 = Point::from(Some(x2), Some(y2), a.clone(), b.clone()).unwrap();
        println!("{} + {} = {}", &p1, &p2, &p1+&p2);

        // (47 71) + (17, 56)
        let x1 = FieldElement::from_i64(47, prime).unwrap();
        let y1 = FieldElement::from_i64(71, prime).unwrap();
        let x2 = FieldElement::from_i64(17, prime).unwrap();
        let y2 = FieldElement::from_i64(56, prime).unwrap();
        let p1 = Point::from(Some(x1), Some(y1), a.clone(), b.clone()).unwrap();
        let p2 = Point::from(Some(x2), Some(y2), a.clone(), b.clone()).unwrap();
        println!("{} + {} = {}", &p1, &p2, &p1+&p2);

        // （143， 98) + (76, 66)
        let x1 = FieldElement::from_i64(143, prime).unwrap();
        let y1 = FieldElement::from_i64(98, prime).unwrap();
        let x2 = FieldElement::from_i64(76, prime).unwrap();
        let y2 = FieldElement::from_i64(66, prime).unwrap();
        let p1 = Point::from(Some(x1), Some(y1), a.clone(), b.clone()).unwrap();
        let p2 = Point::from(Some(x2), Some(y2), a.clone(), b.clone()).unwrap();
        println!("{} + {} = {}", &p1, &p2, &p1+&p2);
    }

    #[test]
    pub fn ecc_test_mul() {
        let prime = 223;
        let a = FieldElement::from_i64(0, prime).unwrap();
        let b = FieldElement::from_i64(7, prime).unwrap();

        let x1 = FieldElement::from_i64(15, prime).unwrap();
        let y1 = FieldElement::from_i64(86, prime).unwrap();
        let p1 = Point::from(Some(x1), Some(y1), a.clone(), b.clone()).unwrap();
        println!("{}", 7*p1);
    }
}
