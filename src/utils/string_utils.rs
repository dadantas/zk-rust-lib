use std::str::FromStr;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigInt;
use num_traits::Num;

use hex::FromHexError;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum StrToFrError {
    #[error("Hex decoding failed: {0}")]
    HexError(#[from] FromHexError),
    #[error("Field parsing failed")]
    FieldParseError,
}

pub fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}
pub fn goodbye(name: &str) -> String {
    format!("Goodbye, {}!", name)
}


pub fn str_to_bigint(s: &str) -> Result<BigInt, num_bigint::ParseBigIntError> {
    if s.starts_with("0x") {
        BigInt::from_str_radix(&s[2..], 16)
    } else {
        BigInt::from_str(s)
    }
}

pub fn str_to_fr(s: &str) -> Result<Fr, StrToFrError> {
    if s.starts_with("0x") {
        let bytes = hex::decode(&s[2..])?; // Propagate hex decoding errors
        Ok(Fr::from_be_bytes_mod_order(&bytes))
    } else {
        Fr::from_str(s).map_err(|_| StrToFrError::FieldParseError)
    }
}