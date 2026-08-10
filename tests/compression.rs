mod harness;

use harness::rng::Rng;
use soyokaze::helpers::compression::{Coding, Compression, Error};

/// `Hello, soyokaze!` as each coding writes it.
///
/// Produced by implementations outside this crate — GNU gzip, Python's zlib,
/// the reference `zstd` and `brotli` command line tools — so that decoding
/// them tests interoperability rather than this crate agreeing with itself.
const PLAINTEXT: &[u8] = b"Hello, soyokaze!";

const VECTORS: &[(Compression, &str)] = &[
    (Compression::Gzip, "1f8b0800000000000203f348cdc9c9d75128ceafcccf4eac4a550400e098594b10000000"),
    (Compression::Deflate, "78daf348cdc9c9d75128ceafcccf4eac4a550400319705d7"),
    (Compression::Zstd, "28b52ffd241081000048656c6c6f2c20736f796f6b617a65217b5cfec0"),
    (Compression::Brotli, "213c000448656c6c6f2c20736f796f6b617a652103"),
];

/// The same plaintext as raw RFC 1951 deflate, with no zlib wrapper.
const RAW_DEFLATE: &str = "f348cdc9c9d75128ceafcccf4eac4a550400";

/// A ceiling large enough that no test body reaches it.
const ROOMY: u64 = 16 * 1024 * 1024;

fn octets(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2).map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn noise(length: usize) -> Vec<u8> {
    let mut rng = Rng::new(0x5040_3020_1008_0402);
    (0..length).map(|_| rng.next_u64() as u8).collect()
}

#[test]
fn decodes_what_other_implementations_produce() {
    for (coding, encoded) in VECTORS {
        assert_eq!(coding.decode(&octets(encoded), ROOMY).as_deref(), Ok(PLAINTEXT), "decoding {coding}");
    }
}

#[test]
fn deflate_reads_both_a_zlib_stream_and_a_raw_one() {
    assert_eq!(Compression::Deflate.decode(&octets(RAW_DEFLATE), ROOMY).as_deref(), Ok(PLAINTEXT));
}

#[test]
fn every_coding_round_trips() {
    let bodies: &[Vec<u8>] = &[Vec::new(), vec![0x2a], PLAINTEXT.to_vec(), vec![0; 1024 * 1024], noise(64 * 1024)];

    for coding in Compression::CODINGS {
        for body in bodies {
            let encoded = coding.encode(body).unwrap_or_else(|err| panic!("encoding {} octets as {coding}: {err}", body.len()));
            let decoded = coding.decode(&encoded, ROOMY).unwrap_or_else(|err| panic!("decoding {} octets of {coding}: {err}", body.len()));

            assert_eq!(&decoded[..], &body[..], "round tripping {} octets through {coding}", body.len());
        }
    }
}

#[test]
fn encoding_into_a_buffer_appends_to_what_is_there() {
    for coding in Compression::CODINGS {
        let mut out = b"kept".to_vec();
        coding.encode_into(PLAINTEXT, &mut out).unwrap();

        assert_eq!(&out[..4], b"kept", "{coding} overwrote the buffer it was given");
        assert_eq!(coding.decode(&out[4..], ROOMY).as_deref(), Ok(PLAINTEXT), "{coding}");
    }
}

#[test]
fn codings_are_named_by_their_rfc_tokens() {
    assert_eq!(Compression::Zstd.as_str(), "zstd");
    assert_eq!(Compression::Brotli.as_str(), "br");
    assert_eq!(Compression::Gzip.as_str(), "gzip");
    assert_eq!(Compression::Deflate.as_str(), "deflate");
}

#[test]
fn auto_names_no_coding_of_its_own() {
    assert_eq!(Compression::Auto.as_str(), "");
    assert_eq!(Compression::parse(""), None);
    assert!(matches!(Compression::Auto.encode(PLAINTEXT), Err(Error::Settled)));
    assert!(matches!(Compression::Auto.decode(PLAINTEXT, ROOMY), Err(Error::Settled)));
}

#[test]
fn a_token_parses_whatever_case_it_is_written_in() {
    assert_eq!(Compression::parse("GZIP"), Some(Compression::Gzip));
    assert_eq!(Compression::parse("Br"), Some(Compression::Brotli));
    assert_eq!(Compression::parse(" zstd "), Some(Compression::Zstd));
    assert_eq!(Compression::parse("X-Gzip"), Some(Compression::Gzip));
}

#[test]
fn a_coding_this_crate_does_not_implement_names_nothing() {
    for token in ["compress", "x-compress", "identity", "auto", "", "gzip2"] {
        assert_eq!(Compression::parse(token), None, "{token:?} must not name a coding");
    }
}

#[test]
fn the_advertised_field_lists_exactly_the_codings_that_decode() {
    let advertised: Vec<Compression> = Coding::list(Compression::ACCEPTED).filter_map(|coding| coding.compression()).collect();
    assert_eq!(advertised, Compression::CODINGS);
}

#[test]
fn accept_encoding_prefers_this_ends_order_not_the_peers() {
    assert_eq!(Compression::accepted(["gzip;q=1.0, zstd;q=0.1"].into_iter()), Some(Compression::Zstd));
    assert_eq!(Compression::accepted(["deflate, gzip"].into_iter()), Some(Compression::Gzip));
}

#[test]
fn an_absent_accept_encoding_permits_nothing() {
    assert_eq!(Compression::accepted(std::iter::empty()), None);
    assert_eq!(Compression::accepted([""].into_iter()), None);
    assert_eq!(Compression::accepted(["identity"].into_iter()), None);
}

#[test]
fn a_coding_at_zero_quality_is_refused() {
    assert_eq!(Compression::accepted(["zstd;q=0, br;q=0, gzip"].into_iter()), Some(Compression::Gzip));
    assert_eq!(Compression::accepted(["gzip;q=0"].into_iter()), None);
    assert_eq!(Compression::accepted(["gzip;q=0.000"].into_iter()), None);
}

#[test]
fn a_wildcard_accepts_everything_it_does_not_name() {
    assert_eq!(Compression::accepted(["*"].into_iter()), Some(Compression::Zstd));
    assert_eq!(Compression::accepted(["*, zstd;q=0"].into_iter()), Some(Compression::Brotli));
    assert_eq!(Compression::accepted(["*;q=0, gzip"].into_iter()), Some(Compression::Gzip));
    assert_eq!(Compression::accepted(["*;q=0"].into_iter()), None);
}

#[test]
fn accept_encoding_is_read_across_repeated_fields() {
    assert_eq!(Compression::accepted(["gzip", "zstd"].into_iter()), Some(Compression::Zstd));
    assert_eq!(Compression::accepted(["zstd;q=0", "br"].into_iter()), Some(Compression::Brotli));
}

#[test]
fn a_quality_outside_zero_to_one_is_a_refusal() {
    assert_eq!(Compression::accepted(["gzip;q=2"].into_iter()), None);
    assert_eq!(Compression::accepted(["gzip;q=-1"].into_iter()), None);
    assert_eq!(Compression::accepted(["gzip;q=what"].into_iter()), None);
}

#[test]
fn parameters_other_than_quality_are_ignored() {
    assert_eq!(Compression::accepted(["gzip;level=9"].into_iter()), Some(Compression::Gzip));
    assert_eq!(Compression::accepted(["gzip; level=9 ; Q=0"].into_iter()), None);
}

#[test]
fn content_encoding_names_a_coding_only_when_it_names_one() {
    assert_eq!(Compression::applied(["gzip"].into_iter()), Some(Compression::Gzip));
    assert_eq!(Compression::applied(["gzip, br"].into_iter()), None);
    assert_eq!(Compression::applied(["gzip", "br"].into_iter()), None);
    assert_eq!(Compression::applied(["compress"].into_iter()), None);
    assert_eq!(Compression::applied(std::iter::empty()), None);
}

#[test]
fn identity_codes_nothing() {
    assert_eq!(Compression::applied(["identity"].into_iter()), None);
    assert_eq!(Compression::applied(["identity, gzip"].into_iter()), Some(Compression::Gzip));
    assert!(!Compression::encoded(["identity"].into_iter()));
    assert!(!Compression::encoded([""].into_iter()));
    assert!(!Compression::encoded(std::iter::empty()));
}

#[test]
fn a_body_is_encoded_whether_or_not_this_crate_can_decode_it() {
    assert!(Compression::encoded(["gzip"].into_iter()));
    assert!(Compression::encoded(["compress"].into_iter()));
    assert!(Compression::encoded(["gzip, br"].into_iter()));
}

#[test]
fn decoding_stops_at_the_ceiling() {
    let bomb = Compression::Gzip.encode(&vec![0u8; 64 * 1024 * 1024]).unwrap();
    assert!(bomb.len() < 128 * 1024, "the fixture is not a compression bomb");

    match Compression::Gzip.decode(&bomb, 1024) {
        Err(Error::TooLarge(1024)) => {}
        other => panic!("a 64 MiB body decoded under a 1 KiB ceiling: {other:?}"),
    }
}

#[test]
fn a_ceiling_admits_a_body_of_exactly_its_size() {
    let body = noise(4096);

    for coding in Compression::CODINGS {
        let encoded = coding.encode(&body).unwrap();

        assert_eq!(coding.decode(&encoded, 4096).as_deref(), Ok(&body[..]), "{coding} refused a body of exactly the ceiling");
        assert!(matches!(coding.decode(&encoded, 4095), Err(Error::TooLarge(4095))), "{coding} admitted a body one octet past the ceiling");
    }
}

#[test]
fn a_refused_decode_leaves_the_buffer_as_it_was() {
    let bomb = Compression::Gzip.encode(&vec![0u8; 1024 * 1024]).unwrap();
    let mut out = b"kept".to_vec();

    assert!(Compression::Gzip.decode_into(&bomb, 16, &mut out).is_err());
    assert_eq!(out, b"kept");
}

#[test]
fn a_stream_that_will_not_decode_is_refused() {
    for coding in Compression::CODINGS {
        assert!(matches!(coding.decode(b"not a compressed stream at all", ROOMY), Err(Error::Coding(_))), "{coding} accepted rubbish");
    }
}

#[test]
fn never_panics_on_arbitrary_octets() {
    let mut rng = Rng::new(7);

    for _ in 0..256 {
        let input = rng.bytes(64);

        for coding in Compression::CODINGS {
            let _ = coding.decode(&input, ROOMY);
        }
    }
}

#[test]
fn a_coding_writes_itself_as_its_token() {
    for coding in Compression::CODINGS {
        assert_eq!(coding.to_string(), coding.as_str());
        assert_eq!(coding.as_str().parse::<Compression>(), Ok(*coding));
    }

    assert_eq!("nonsense".parse::<Compression>(), Err(()));
}

#[test]
fn an_entry_without_a_quality_is_fully_acceptable() {
    assert_eq!(Coding::parse("gzip").quality, Coding::FULL);
    assert_eq!(Coding::parse("gzip;q=0.5").quality, 0.5);
    assert!(Coding::parse("gzip").accepts());
    assert!(!Coding::parse("gzip;q=0").accepts());
    assert!(Coding::parse("*").wildcard());
    assert!(!Coding::parse("gzip").wildcard());
}

#[test]
fn errors_describe_themselves() {
    assert_eq!(Error::Settled.to_string(), "the content coding was never settled");
    assert_eq!(Error::TooLarge(64).to_string(), "the decoded body exceeds 64 octets");
    assert_eq!(Error::coding("broken").to_string(), "the content coding failed: broken");
}

#[test]
fn a_ceiling_failure_is_a_limit_and_a_broken_stream_is_a_protocol_error() {
    assert!(matches!(soyokaze::Error::from(Error::TooLarge(64)), soyokaze::Error::Limit(_)));
    assert!(matches!(soyokaze::Error::from(Error::coding("broken")), soyokaze::Error::Protocol(_)));
    assert!(matches!(soyokaze::Error::from(Error::Settled), soyokaze::Error::Protocol(_)));
}
