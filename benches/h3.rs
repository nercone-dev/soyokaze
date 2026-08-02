mod support;

use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;

use soyokaze::helpers::hpack::HeaderField;
use soyokaze::api::common::Limits;
use soyokaze::models::{Body, ConnectionID, Headers, Message, Role, StreamID, Version};
use soyokaze::protocol::h3::{Frame, H3Connection, H3Session, Settings, StreamState};
use support::{opaque, Group};

const BODY: &[u8] = b"Hello, World!";

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

struct Counted;

unsafe impl std::alloc::GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { std::alloc::System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counted = Counted;

fn counted<T>(body: impl FnOnce() -> T) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    opaque(body());
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

fn id() -> ConnectionID {
    ConnectionID(Bytes::from_static(b"bench"))
}

fn server() -> H3Session {
    let mut session = H3Session::new(Role::Origin, id(), Limits::default());
    let settings = Frame::Settings(Settings::default().parameters()).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");
    session
}

fn client() -> H3Session {
    let mut session = H3Session::new(Role::UserAgent, id(), Limits::default());
    let settings = Frame::Settings(Settings::default().parameters()).encode();
    session.on_control_bytes(&settings).expect("the peer settings were refused");
    session
}

fn request_fields() -> Vec<HeaderField> {
    [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "www.example.com"),
        (":path", "/index.html"),
        ("accept", "*/*"),
        ("accept-encoding", "gzip, deflate, br"),
        ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) soyokaze/0.1"),
    ]
    .map(|(name, value)| HeaderField::new(name, value))
    .to_vec()
}

fn response() -> Message {
    let mut response = Message::response(200, Version::V3_0);

    let mut headers = Headers::with_capacity(4);
    headers.append("content-type", "text/plain");
    headers.append("content-length", "13");
    headers.append("server", "soyokaze");
    response.headers = Some(headers);
    response.body = Some(Body::Data(Bytes::from_static(BODY)));

    response
}

fn wire_request(encoder: &mut H3Session, stream_id: u64) -> Bytes {
    let (block, instructions) = encoder.encoder.encode(stream_id, &request_fields());
    let _ = instructions;

    let mut out = bytes::BytesMut::new();
    Frame::Headers(block.into()).encode_into(&mut out);
    out.freeze()
}

fn cycle(session: &mut H3Session, wire: &Bytes, stream_id: u64, response: &Message) {
    let stream = StreamID(stream_id);

    session.on_stream_bytes(stream, wire, true).expect("the request did not parse");
    let request = session.take_ready().expect("the request never completed");
    opaque(request);

    session.encode_message(stream, response).expect("the response did not encode");
    session.retire(stream);
}

fn aged(group: &mut Group, served: u64) {
    let mut peer = client();
    let mut session = server();
    let response = response();

    let mut next = 0u64;
    for _ in 0..served {
        let wire = wire_request(&mut peer, next);
        cycle(&mut session, &wire, next, &response);
        next += 4;
    }

    let wire = wire_request(&mut peer, 1 << 40);
    group.bench(&format!("cycle after {served} requests"), || {
        let stream_id = next;
        next += 4;
        cycle(&mut session, opaque(&wire), stream_id, &response);
    });
}

fn halves(group: &mut Group) {
    let mut peer = client();
    let response = response();

    let mut session = server();
    let mut next = 0u64;
    let wire = wire_request(&mut peer, 0);
    group.throughput("decode request (7 fields)", wire.len(), || {
        let stream = StreamID(next);
        next += 4;
        session.on_stream_bytes(stream, opaque(&wire), true).expect("the request did not parse");
        let request = session.take_ready().expect("the request never completed");
        session.streams.remove(&stream);
        request
    });

    let mut session = server();
    let mut next = 1u64;
    group.bench("encode response (body, 13 B)", || {
        let stream = StreamID(next);
        next += 4;
        let encoded = session.encode_message(stream, opaque(&response)).expect("the response did not encode");
        session.streams.remove(&stream);
        encoded
    });
}

fn deadline(group: &mut Group) {
    for held in [1usize, 100, 1_000, 10_000, 50_000] {
        let mut session = server();
        for index in 0..held {
            session.streams.insert(StreamID(index as u64 * 4), StreamState::default());
        }

        let (_connection, worker) = H3Connection::pair(session, None);
        group.bench(&format!("block_deadline ({held} streams held)"), || opaque(&worker).block_deadline());
    }
}

fn report_allocations(case: &str, rounds: usize, mut body: impl FnMut(usize) -> usize) {
    for round in 0..64 {
        body(round);
    }

    let total: usize = (64..64 + rounds).map(&mut body).sum();
    println!("  {case:<38} {:>12}", format!("{:.2}", total as f64 / rounds as f64));
}

fn allocations() {
    const ROUNDS: usize = 256;

    let response = response();

    let mut peer = client();
    let mut session = server();
    let mut outbound = bytes::BytesMut::new();

    report_allocations("in place (send buffer)", ROUNDS, |round| {
        let stream = StreamID(round as u64 * 4);
        let wire = wire_request(&mut peer, stream.0);

        counted(|| {
            session.on_stream_bytes(stream, &wire, true).expect("the request did not parse");
            let request = session.take_ready().expect("the request never completed");
            opaque(request);

            session.encode_message_into(stream, &response, &mut outbound).expect("the response did not encode");
            outbound.clear();
            session.retire(stream);
        })
    });

    let mut peer = client();
    let mut session = server();
    let mut outbound = bytes::BytesMut::new();

    report_allocations("through a shared handle", ROUNDS, |round| {
        let stream = StreamID(round as u64 * 4);
        let wire = wire_request(&mut peer, stream.0);

        counted(|| {
            session.on_stream_bytes(stream, &wire, true).expect("the request did not parse");
            let request = session.take_ready().expect("the request never completed");
            opaque(request);

            let (bytes, _) = session.encode_message(stream, &response).expect("the response did not encode");
            outbound.extend_from_slice(&bytes);
            outbound.clear();
            session.retire(stream);
        })
    });
}

fn only(name: &str) -> bool {
    match std::env::var("SOYOKAZE_BENCH_ONLY") {
        Ok(wanted) => wanted == name,
        Err(_) => true,
    }
}

fn main() {
    if only("halves") {
        let mut group = Group::new("h3 session halves");
        halves(&mut group);
    }

    if only("allocations") {
        let _ = Group::new("h3 allocator traffic");
        allocations();
    }

    if only("deadline") {
        let mut group = Group::new("h3 worker per-I/O-cycle scan");
        deadline(&mut group);
    }

    if only("age") {
        let mut group = Group::new("h3 per-request cost by connection age");
        for served in [0u64, 1_000, 10_000, 50_000] {
            aged(&mut group, served);
        }
    }
}
