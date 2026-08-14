//! What a connection costs before it carries a single request.
//!
//! Certificates and keys are read once per server, contexts are built once per
//! configuration, and an ECH config is parsed once per origin — so none of
//! these is a per-request cost, and every one of them is a cost a server pays
//! before it can answer at all. What they bound is how fast a process comes
//! up, how fast a configuration reloads, and how quickly a client can be
//! pointed at a new origin.
//!
//! What is not here is a handshake. A handshake needs two ends and a socket,
//! and measuring one is measuring a connection rather than a piece of one, so
//! it belongs to `--bench load` — where the `a handshake per request` runs
//! measure exactly that, per version and per transport.
//!
//! ```bash
//! cargo bench --bench security
//! cargo bench --bench security -- ech
//! ```

mod support;

use std::hint::black_box;

use soyokaze::helpers::base64;
use soyokaze::tls::{ECHConfigList, ECHKeys, Format, Identity, TLSConfig};

use support::load::Certificate;
use support::{Figure, Fixtures, Group};

/// The name every fixture certificate and ECH config is issued for.
const NAME: &str = "localhost";

/// A DER blob written out as PEM, which is how a certificate is usually
/// shipped and so the form a server usually reads.
fn armour(der: &[u8], label: &str) -> Vec<u8> {
    let encoded = base64::encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");

    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is not UTF-8"));
        pem.push('\n');
    }

    pem.push_str(&format!("-----END {label}-----\n"));
    pem.into_bytes()
}

/// A PEM blob holding this many certificates, which is how a chain arrives.
fn chain(certificate: &Certificate, length: usize) -> Vec<u8> {
    let one = armour(&certificate.der, "CERTIFICATE");

    (0..length).flat_map(|_| one.clone()).collect()
}

fn formats(certificate: &Certificate) {
    let mut group = Group::new("tls::Format");

    let der = certificate.der.clone();
    let pem = armour(&der, "CERTIFICATE");
    let key_der = certificate.key.clone();
    let key_pem = armour(&key_der, "PRIVATE KEY");

    group.time("of (DER)", || Format::of(black_box(&der)));
    group.time("of (PEM)", || Format::of(black_box(&pem)));

    group.throughput("certificates (one, DER)", der.len(), || Format::certificates(black_box(&der)));
    group.throughput("certificates (one, PEM)", pem.len(), || Format::certificates(black_box(&pem)));
    group.throughput("private_key (DER)", key_der.len(), || Format::private_key(black_box(&key_der)));
    group.throughput("private_key (PEM)", key_pem.len(), || Format::private_key(black_box(&key_pem)));

    group.time("certificate_list (one blob)", || Format::certificate_list(black_box(std::slice::from_ref(&der))));

    // A chain is however long the issuer made it, so reading one must cost
    // what it is long and no more.
    group.growth("certificates, over the chain length", &[1, 2, 4, 8, 16], |length| chain(certificate, length), |pem| {
        Format::certificates(black_box(pem))
    });
}

fn identities(certificate: &Certificate) {
    let mut group = Group::new("tls::Identity");
    let identity = certificate.identity();

    group.time("new", || Identity::new(black_box(vec![certificate.der.clone()]), certificate.key.clone()));
    group.time("chain", || black_box(&identity).chain());
    group.time("private_key", || black_box(&identity).private_key());
}

/// Building the contexts a listener and a dialler are handed.
///
/// Each is built once and then shared by every connection under it, so what
/// these bound is a reload rather than a request. They are the most expensive
/// things in this benchmark by a wide margin, which is exactly why they are
/// built once.
fn contexts(certificate: &Certificate) {
    let mut group = Group::new("tls::TLSConfig");
    let config = TLSConfig::default();
    let identity = certificate.identity();
    let roots = certificate.roots();
    let versions = Fixtures::VERSIONS;

    group.time("client (three versions, one root)", || black_box(&config).client(&roots, versions));
    group.time("client (three versions, platform roots)", || black_box(&config).client(&[], versions));
    group.time("server (three versions)", || black_box(&config).server(&identity, versions, None));
    group.time("quic_client (one root)", || black_box(&config).quic_client(&roots));
    group.time("quic_server", || black_box(&config).quic_server(&identity, None));

    let tuned = TLSConfig {
        ciphers: Some("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256".to_owned()),
        groups: Some("X25519".to_owned()),
        certificate_compression: true,
        ..TLSConfig::default()
    };

    group.time("client (a restricted suite and group list)", || black_box(&tuned).client(&roots, versions));
    group.time("server (certificate compression on)", || black_box(&tuned).server(&identity, versions, None));

    for version in Fixtures::VERSIONS {
        group.time(&format!("client (one version, {version})"), || black_box(&config).client(&roots, std::slice::from_ref(version)));
    }

    group.growth("client, over the roots it trusts", &[1, 2, 4, 8, 16], |count| vec![certificate.der.clone(); count], |roots| {
        black_box(&config).client(roots, versions).is_ok()
    });
}

fn ech(certificate: &Certificate) {
    let mut group = Group::new("tls::ECH");
    let keys = ECHKeys::generate(NAME, 0).expect("no ECH keys were generated");
    let list = keys.config_list();
    let public = vec![0u8; 32];

    group.time("ECHKeys::generate", || ECHKeys::generate(black_box(NAME), 0));
    group.time("ECHKeys::encode", || ECHKeys::encode(black_box(NAME), 0, &public));
    group.time("ECHKeys::config_list", || black_box(&keys).config_list());
    group.throughput("ECHConfigList::parse (one config)", list.len(), || ECHConfigList::parse(black_box(&list)));
    group.time("ECHConfigList::contents", || ECHConfigList::contents(black_box(&keys.config[4..])));

    group.time("ECHConfigList::parse (a list that is too short)", || ECHConfigList::parse(black_box(&[0x00])));
    group.time("ECHConfigList::parse (a length that disagrees)", || ECHConfigList::parse(black_box(&[0x00, 0xff, 0x00, 0x00])));

    // A published list carries every config a server is rotating through, and
    // a client parses the whole list to find the ones it understands.
    group.growth("ECHConfigList::parse, over the configs listed", &[1, 2, 4, 8, 16], published, |list| ECHConfigList::parse(black_box(list)));

    let config = TLSConfig::default();
    let identity = certificate.identity();
    group.time("a server context with ECH installed", || black_box(&config).server(&identity, Fixtures::VERSIONS, Some(&keys)));
    group.time("a QUIC server context with ECH installed", || black_box(&config).quic_server(&identity, Some(&keys)));
}

/// A published `ECHConfigList` carrying this many configs.
fn published(configs: usize) -> Vec<u8> {
    let mut body = Vec::new();

    for index in 0..configs {
        let keys = ECHKeys::generate(NAME, index as u8).expect("no ECH keys were generated");
        body.extend_from_slice(&keys.config);
    }

    let mut list = (body.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&body);
    list
}

/// What every case below was measured against, said once.
fn preamble() {
    println!("a self-signed {NAME} certificate, issued fresh for this run, stands in for whatever a server is really given");
    println!("{}", Figure::many(Fixtures::VERSIONS.len(), "version"));
}

fn main() {
    let certificate = Certificate::localhost();

    if Group::new("tls::Format").wanted() {
        preamble();
    }

    formats(&certificate);
    identities(&certificate);
    contexts(&certificate);
    ech(&certificate);
}
