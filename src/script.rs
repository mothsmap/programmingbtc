use std::{fmt, io::{Read, Seek}};
use anyhow::{Result, bail};

#[derive(Debug, Clone)]
pub struct Script {
}

impl Script {
    pub fn serialize(&self) -> Vec<u8> {
        vec![]
    }

    pub fn parse<T: Read + Seek>(buffer: &mut T) -> Result<Script> {
        Ok(Script {  })
    }
}


impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "")
    }
}
