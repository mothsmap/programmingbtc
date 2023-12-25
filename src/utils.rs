use num::{bigint::BigInt, FromPrimitive};

pub fn new_bigint(i: i64) -> BigInt {
    BigInt::from_i64(i).unwrap()
}
