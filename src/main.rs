mod field_element;
mod point;
mod utils;

use field_element::FieldElement;
use point::Point;

use crate::utils::new_bigint;

fn main() {
    println!("Hello, world!");
    let a = FieldElement::from_i64(0, 223).unwrap();
    let b = FieldElement::from_i64(7, 223).unwrap();
    let x1 = FieldElement::from_i64(192, 223).unwrap();
    let y1 = FieldElement::from_i64(105, 223).unwrap();
    let x2 = FieldElement::from_i64(17, 223).unwrap();
    let y2 = FieldElement::from_i64(56, 223).unwrap();

    let p1 = Point::from(Some(x1), Some(y1), a.clone(), b.clone()).unwrap();
    println!("{}", p1);
    let p2 = Point::from(Some(x2), Some(y2), a.clone(), b.clone()).unwrap();
    println!("{}", p2);

    let p3 = p1 + p2;
    println!("{}", p3);

    let p = new_bigint(2).pow(256u32) - new_bigint(2).pow(32u32) - new_bigint(977);
    println!("{}", p);
    println!("{:?}", p.to_u32_digits());
}
