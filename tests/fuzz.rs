mod harness;

use harness::rng::Rng;

const CASES: usize = 2_000;

fn case_count() -> usize {
    std::env::var("SOYOKAZE_FUZZ_CASES").ok().and_then(|value| value.parse().ok()).unwrap_or(CASES)
}

const ALPHABET: &[u8] = &[
    0x00, 0x01, 0x0f, 0x10, 0x1f, 0x20, 0x3f, 0x40, 0x7f, 0x80, 0x81, 0xc0, 0xfe, 0xff, b'a', b':',
];

const SEEDS: &[&[u8]] = &[
    b"",
    b"\x00",
    b"\xff",
    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    b"\x82\x44\x0fwww.example.com",
    b"\x3f\xe1\xff\xff\xff\x07",
    b"\x1f\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
    b"\xff\xff\xff\xff\xff",
    b"\xff\xff\xff\x00",
    b"\x00\x00\x03\x04\x00\x00\x00\x00\x00\x01\x02\x03",
    b"\x00\x00\x05\x00\x08\x00\x00\x00\x01\xff\x01\x02\x03\x04",
    b"\x01\xbf\xff\xff\xff\x00",
    b"\x82\xff\xff\xff\xff\xff\xff\xff\xff\xff",
];

fn cases(seed: u64) -> impl Iterator<Item = Vec<u8>> {
    let mut rng = Rng::new(seed);

    SEEDS.iter().map(|seed| seed.to_vec()).chain((0..case_count()).map(move |index| {
        if index % 2 == 0 { rng.bytes(256) } else { rng.biased(256, ALPHABET) }
    }))
}

#[test]
fn field_harness() {
    for case in cases(0x5eed_0005) {
        harness::fields::check(&case);
    }
}

#[test]
fn huffman_harness() {
    for case in cases(0x5eed_0001) {
        harness::huffman::check(&case);
    }
}

#[test]
fn hpack_harness() {
    for case in cases(0x5eed_0002) {
        harness::hpack::check(&case);
    }
}

#[test]
fn qpack_harness() {
    for case in cases(0x5eed_0003) {
        harness::qpack::check(&case);
    }
}

#[test]
fn frame_harness() {
    for case in cases(0x5eed_0004) {
        harness::frames::check(&case);
    }
}

#[test]
fn every_harness_runs_over_every_seed() {
    for case in SEEDS {
        harness::all(case);
    }
}

#[test]
fn the_generator_is_deterministic() {
    let first: Vec<Vec<u8>> = cases(0x5eed_0001).take(32).collect();
    let second: Vec<Vec<u8>> = cases(0x5eed_0001).take(32).collect();

    assert_eq!(first, second, "the same seed produced different cases");
    assert_ne!(
        first,
        cases(0x5eed_0002).take(32).collect::<Vec<_>>(),
        "different seeds produced the same cases",
    );
}
