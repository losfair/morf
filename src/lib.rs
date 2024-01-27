#![allow(incomplete_features)]
#![cfg_attr(not(test), no_std)]
#![feature(generic_const_exprs)]

pub mod peer;

#[cfg(test)]
pub mod peer_test;
