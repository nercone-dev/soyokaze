#![allow(dead_code)]

pub mod fields;
pub mod frames;
pub mod hpack;
pub mod huffman;
pub mod input;
pub mod qpack;
pub mod rng;

pub fn all(data: &[u8]) {
    fields::check(data);
    huffman::check(data);
    hpack::check(data);
    qpack::check(data);
    frames::check(data);
}
