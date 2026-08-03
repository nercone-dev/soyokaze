mod harness;

use std::time::{Duration, Instant};

use soyokaze::helpers::base64::{self, DecodeError};
use soyokaze::helpers::hsts::{HstsPolicy, HstsStore};
use soyokaze::helpers::scan;
use soyokaze::helpers::sha1::{self, Sha1};
use soyokaze::models::{Headers, Message, Version};
use soyokaze::protocol::h1;
use soyokaze::{http_date, DateCache};

const VECTORS: &[(&[u8], &str)] = &[
    (b"", ""),
    (b"f", "Zg=="),
    (b"fo", "Zm8="),
    (b"foo", "Zm9v"),
    (b"foob", "Zm9vYg=="),
    (b"fooba", "Zm9vYmE="),
    (b"foobar", "Zm9vYmFy"),
];

#[test]
fn base64_matches_the_specification_vectors() {
    for (plain, encoded) in VECTORS {
        assert_eq!(base64::encode(plain), *encoded, "encoding {plain:?}");
        assert_eq!(base64::decode(encoded).as_deref(), Ok(*plain), "decoding {encoded:?}");
    }
}

#[test]
fn base64_round_trips_every_length() {
    for length in 0..64usize {
        let input: Vec<u8> = (0..length).map(|index| (index * 7) as u8).collect();

        let encoded = base64::encode(&input);
        assert_eq!(encoded.len(), base64::encoded_len(&input));
        assert_eq!(base64::decode(&encoded).as_deref(), Ok(&input[..]));
    }
}

#[test]
fn base64_covers_the_whole_alphabet() {
    let all: Vec<u8> = (0..=255).collect();
    let encoded = base64::encode(&all);

    assert!(encoded.bytes().all(|byte| base64::ALPHABET.contains(&byte) || byte == base64::PAD));
    assert_eq!(base64::decode(&encoded).as_deref(), Ok(&all[..]));
}

#[test]
fn base64_refuses_a_length_that_is_not_a_multiple_of_four() {
    assert_eq!(base64::decode("Zg="), Err(DecodeError::InvalidLength(3)));
    assert_eq!(base64::decode("Z"), Err(DecodeError::InvalidLength(1)));
}

#[test]
fn base64_refuses_a_symbol_outside_the_alphabet() {
    assert_eq!(base64::decode("Zm9-"), Err(DecodeError::InvalidSymbol(b'-')));
    assert_eq!(base64::decode("Zm9 "), Err(DecodeError::InvalidSymbol(b' ')));
}

#[test]
fn base64_refuses_misplaced_or_dirty_padding() {
    assert_eq!(base64::decode("=Zm9"), Err(DecodeError::InvalidPadding));
    assert_eq!(base64::decode("Zg==Zg=="), Err(DecodeError::InvalidPadding));
    assert_eq!(base64::decode("Z==="), Err(DecodeError::InvalidPadding));
    assert_eq!(base64::decode("Zh=="), Err(DecodeError::InvalidPadding));
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn sha1_matches_the_specification_vectors() {
    assert_eq!(hex(&sha1::sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(hex(&sha1::sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(
        hex(&sha1::sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    );
    assert_eq!(hex(&sha1::sha1(&[b'a'; 1_000_000])), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}

#[test]
fn sha1_is_indifferent_to_how_the_input_arrives() {
    let input: Vec<u8> = (0..1000u32).map(|index| index as u8).collect();
    let expected = sha1::sha1(&input);

    for chunk in [1usize, 7, 63, 64, 65, 128] {
        let mut hash = Sha1::new();
        for part in input.chunks(chunk) {
            hash.update(part);
        }
        assert_eq!(hash.finish(), expected, "chunked into {chunk} octets");
    }
}

#[test]
fn sha1_pads_across_the_awkward_block_boundaries() {
    for length in [54usize, 55, 56, 57, 63, 64, 119, 120] {
        let input = vec![b'x'; length];
        assert_eq!(sha1::sha1(&input).len(), sha1::DIGEST_SIZE, "length {length}");
    }
}

#[test]
fn hsts_builds_and_parses_a_policy() {
    let mut policy = HstsPolicy::new(31_536_000);
    assert_eq!(policy.build(), "max-age=31536000");

    policy.include_subdomains = true;
    policy.preload = true;
    assert_eq!(policy.build(), "max-age=31536000; includeSubDomains; preload");

    assert_eq!(HstsPolicy::parse("max-age=31536000; includeSubDomains; preload"), Some(policy));
}

#[test]
fn hsts_parsing_ignores_case_and_quotes_and_unknown_directives() {
    let policy = HstsPolicy::parse("MAX-AGE=\"600\"; IncludeSubDomains; something-else");

    assert_eq!(policy, Some(HstsPolicy { max_age: 600, include_subdomains: true, preload: false }));
}

#[test]
fn hsts_refuses_a_header_with_no_usable_max_age() {
    assert_eq!(HstsPolicy::parse(""), None);
    assert_eq!(HstsPolicy::parse("includeSubDomains"), None);
    assert_eq!(HstsPolicy::parse("max-age"), None);
    assert_eq!(HstsPolicy::parse("max-age=-1"), None);
    assert_eq!(HstsPolicy::parse("max-age=abc"), None);
    assert_eq!(HstsPolicy::parse("max-age=1; max-age=2"), None);
}

#[test]
fn hsts_is_only_learned_over_a_secure_connection() {
    let store = HstsStore::new();
    let now = Instant::now();

    store.learn("example.test", "max-age=600", false, now);
    assert!(!store.secure("example.test", now));

    store.learn("example.test", "max-age=600", true, now);
    assert!(store.secure("example.test", now));
}

#[test]
fn hsts_covers_subdomains_only_when_asked() {
    let store = HstsStore::new();
    let now = Instant::now();

    store.learn("example.test", "max-age=600", true, now);
    assert!(!store.secure("api.example.test", now));

    store.learn("other.test", "max-age=600; includeSubDomains", true, now);
    assert!(store.secure("api.other.test", now));
    assert!(!store.secure("notother.test", now));
}

#[test]
fn hsts_forgets_an_expired_or_withdrawn_policy() {
    let store = HstsStore::new();
    let now = Instant::now();

    store.learn("example.test", "max-age=60", true, now);
    assert!(store.secure("example.test", now));
    assert!(!store.secure("example.test", now + Duration::from_secs(61)));

    store.learn("other.test", "max-age=60", true, now);
    store.learn("other.test", "max-age=0", true, now);
    assert!(!store.secure("other.test", now));
}

#[test]
fn hsts_never_applies_to_an_address_literal() {
    let store = HstsStore::new();
    let now = Instant::now();

    store.learn("127.0.0.1", "max-age=600", true, now);
    store.learn("[::1]", "max-age=600", true, now);

    assert!(!store.secure("127.0.0.1", now));
    assert!(!store.secure("::1", now));
    assert_eq!(HstsStore::normalize("192.0.2.1"), None);
    assert_eq!(HstsStore::normalize("Example.Test."), Some("example.test".to_owned()));
}

#[test]
fn http_date_formats_the_imf_fixdate_form() {
    assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    assert_eq!(http_date(1_382_386_401), "Mon, 21 Oct 2013 20:13:21 GMT");
    assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
}

#[test]
fn the_date_cache_returns_a_well_formed_date() {
    let cache = DateCache::new();

    let first = cache.now();
    assert!(first.ends_with(" GMT"), "{first:?} is not an IMF-fixdate");
    assert_eq!(first.len(), 29);
    assert_eq!(cache.now(), first);
}

#[test]
fn a_response_gains_a_date_and_a_server_field() {
    let cache = DateCache::new();
    let mut response = Message::response(200, Version::V1_1);

    soyokaze::finalizer::finalize_response(&mut response, &cache, None);

    let headers = response.headers.as_ref().expect("the response lost its fields");
    assert!(headers.contains("date"));
    assert_eq!(headers.get("server"), Some("Soyokaze"));
}

#[test]
fn finalizing_leaves_fields_the_handler_already_set() {
    let cache = DateCache::new();

    let mut headers = Headers::new();
    headers.append("date", "Thu, 01 Jan 1970 00:00:00 GMT");
    headers.append("server", "something-else");

    let mut response = Message::response(200, Version::V1_1);
    response.headers = Some(headers);

    soyokaze::finalizer::finalize_response(&mut response, &cache, None);

    let headers = response.headers.as_ref().expect("the response lost its fields");
    assert_eq!(headers.get("date"), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
    assert_eq!(headers.get("server"), Some("something-else"));
    assert_eq!(headers.get_all("date").count(), 1);
}

#[test]
fn an_informational_response_is_left_alone() {
    let cache = DateCache::new();
    let mut response = Message::response(103, Version::V2_0);

    soyokaze::finalizer::finalize_response(&mut response, &cache, None);

    let headers = response.headers.as_ref().expect("the response lost its fields");
    assert!(!headers.contains("date"), "an informational response must not carry a Date");
}

#[test]
fn hsts_is_only_advertised_on_a_secure_response() {
    let cache = DateCache::new();
    let policy = HstsPolicy::new(600);

    let mut plain = Message::response(200, Version::V1_1);
    soyokaze::finalizer::finalize_response(&mut plain, &cache, Some(&policy));
    assert!(!plain.headers.as_ref().is_some_and(|headers| headers.contains("strict-transport-security")));

    let mut secure = Message::response(200, Version::V1_1);
    secure.secure = true;
    soyokaze::finalizer::finalize_response(&mut secure, &cache, Some(&policy));
    assert_eq!(
        secure.headers.as_ref().and_then(|headers| headers.get("strict-transport-security")),
        Some("max-age=600"),
    );
}

#[test]
fn a_request_gains_a_host_field_on_http_1() {
    let mut request = Message::request(soyokaze::Method::GET, "/", Version::V1_1);
    soyokaze::finalizer::finalize_request(&mut request, "example.test:8443");

    assert_eq!(request.headers.as_ref().and_then(|headers| headers.get("host")), Some("example.test:8443"));

    let mut later = Message::request(soyokaze::Method::GET, "/", Version::V2_0);
    soyokaze::finalizer::finalize_request(&mut later, "example.test");
    assert!(!later.headers.as_ref().is_some_and(|headers| headers.contains("host")));
}

#[test]
fn the_hsts_store_does_not_remember_hosts_without_limit() {
    let store = HstsStore::new();
    let now = Instant::now();

    let ceiling = store.limits.max_hsts_entries as usize;

    for index in 0..(ceiling + 128) {
        store.learn(&format!("host{index}.test"), "max-age=31536000", true, now);
    }

    let held = store.entries.lock().expect("the store was poisoned").len();
    assert!(held <= ceiling, "the store remembered {held} hosts");
}

#[test]
fn an_expired_hsts_entry_makes_room_for_a_new_one() {
    let store = HstsStore::new();
    let now = Instant::now();

    for index in 0..store.limits.max_hsts_entries {
        store.learn(&format!("host{index}.test"), "max-age=1", true, now);
    }

    let later = now + Duration::from_secs(2);
    store.learn("fresh.test", "max-age=31536000", true, later);

    assert!(store.secure("fresh.test", later), "the newest policy was not kept");
    assert!(!store.secure("host0.test", later), "an expired policy still applies");
}

#[test]
fn an_unreachable_hsts_expiry_does_not_overflow_the_clock() {
    let store = HstsStore::new();
    let now = Instant::now();

    store.learn("example.test", &format!("max-age={}", i64::MAX), true, now);
    store.learn("other.test", "max-age=31536000", true, now);

    assert!(store.secure("other.test", now), "an unreachable expiry disturbed the store");
}

#[test]
fn the_field_value_classifier_agrees_with_a_byte_at_a_time_reading() {
    fn naive(text: &[u8]) -> u8 {
        let control = text.iter().any(|octet| (*octet < 0x20 && *octet != b'\t') || *octet == 0x7f);
        let obs_text = text.iter().any(|octet| *octet >= 0x80);

        (control as u8) | (obs_text as u8) << 1
    }

    let mut rng = harness::rng::Rng::new(0x5f3c_11a9_0d27_4e6b);

    for octet in 0..=255u8 {
        for length in 0..24usize {
            for at in 0..length {
                let mut text = vec![b'x'; length];
                text[at] = octet;

                assert_eq!(
                    scan::classify_field_value(&text),
                    naive(&text),
                    "{octet:#04x} at {at} of {length} octets"
                );
            }
        }
    }

    const NEIGHBOURS: &[u8] = &[0x00, 0x08, b'\t', 0x0a, 0x1f, b' ', b'!', b'x', 0x7e, 0x7f, 0x80, 0xc3, 0xff];

    for first in NEIGHBOURS {
        for second in NEIGHBOURS {
            for at in 0..12usize {
                for gap in 1..4usize {
                    let mut text = vec![b'x'; 16];
                    text[at] = *first;
                    text[at + gap] = *second;

                    assert_eq!(
                        scan::classify_field_value(&text),
                        naive(&text),
                        "{first:#04x} at {at} and {second:#04x} {gap} along"
                    );
                }
            }
        }
    }

    for _ in 0..4_000 {
        let text = rng.bytes(64);
        assert_eq!(scan::classify_field_value(&text), naive(&text), "{text:?}");
    }
}

#[test]
fn a_field_value_carrying_obs_text_still_parses() {
    let block = b"x-note: caf\xc3\xa9\r\nx-broken: caf\xe9\r\n";
    let headers = h1::parse_header_block(block, 100).expect("obs-text is allowed in a field value");

    assert_eq!(headers.get("x-note"), Some("café"), "valid UTF-8 obs-text was not kept");
    assert_eq!(headers.get("x-broken"), Some("caf\u{fffd}"), "invalid UTF-8 obs-text was not replaced");
}

#[test]
fn the_octet_class_check_agrees_with_a_byte_at_a_time_reading() {
    let mut table = [0u8; 256];
    for (value, slot) in table.iter_mut().enumerate() {
        let byte = value as u8;
        *slot = (byte.is_ascii_lowercase() as u8) | (byte.is_ascii_alphabetic() as u8) << 1;
    }

    let naive = |text: &[u8], mask: u8| text.iter().all(|octet| table[*octet as usize] & mask != 0);

    assert!(scan::all_in_class(&[], &table, 1), "an empty run was not accepted");
    assert!(scan::all_in_class(&[], &table, 2), "an empty run was not accepted");

    for mask in [1u8, 2] {
        for octet in 0..=255u8 {
            for length in 1..24usize {
                for at in 0..length {
                    let mut text = vec![b'a'; length];
                    text[at] = octet;

                    assert_eq!(
                        scan::all_in_class(&text, &table, mask),
                        naive(&text, mask),
                        "{octet:#04x} at {at} of {length} octets, mask {mask}"
                    );
                }
            }
        }
    }

    let mut rng = harness::rng::Rng::new(0x2c1b_57ea_9048_d3f7);

    for _ in 0..4_000 {
        for length in [1usize, 7, 8, 9, 15, 16, 17, 31, 64] {
            let text = rng.bytes(length);
            assert_eq!(scan::all_in_class(&text, &table, 1), naive(&text, 1), "{text:?}");
        }
    }
}
