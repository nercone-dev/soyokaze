//! The C ABI in `soyokaze::ffi`, verified against the contract its
//! documentation states rather than against what the current code happens to
//! do.
//!
//! The contract being checked here:
//!
//! - A fallible call returns [`Status::Ok`] or writes an error handle.
//! - A null handle is treated as absent and never dereferenced.
//! - Text out is [`Slice::ABSENT`] when the value was not there, and a non-null
//!   pointer with a length of zero when it was there and empty.
//! - A handle a call is documented as consuming is not freed by the caller.

use std::ffi::c_void;
use std::ptr;

use soyokaze::ffi::api::client::{
    soyokaze_client_fetch, soyokaze_client_free, soyokaze_client_get, soyokaze_client_new, ClientConfig,
};
use soyokaze::ffi::api::common::soyokaze_limits_default;
use soyokaze::ffi::errors::{
    soyokaze_error_free, soyokaze_error_message, soyokaze_error_status, soyokaze_status_message, ErrorHandle, Status,
};
use soyokaze::ffi::models::{
    soyokaze_message_append_header, soyokaze_message_body, soyokaze_message_body_len, soyokaze_message_free,
    soyokaze_message_header, soyokaze_message_header_count, soyokaze_message_header_name, soyokaze_message_header_value,
    soyokaze_message_insert_header, soyokaze_message_is_request, soyokaze_message_is_response, soyokaze_message_method,
    soyokaze_message_remove_header, soyokaze_message_request, soyokaze_message_response, soyokaze_message_set_body_data,
    soyokaze_message_set_body_file, soyokaze_message_set_body_text, soyokaze_message_status_code, soyokaze_message_target,
    soyokaze_message_version, soyokaze_url_authority, soyokaze_url_free, soyokaze_url_host, soyokaze_url_parse,
    soyokaze_url_port, soyokaze_url_scheme, soyokaze_url_secure, soyokaze_url_target, Port, PortKind,
};
use soyokaze::ffi::api::server::{
    soyokaze_response_with_body, soyokaze_server_free, soyokaze_server_handle_close, soyokaze_server_handle_port,
    soyokaze_server_new, soyokaze_server_serve,
};
use soyokaze::ffi::{
    soyokaze_buffer_free, soyokaze_runtime_free, soyokaze_runtime_new, soyokaze_version, Buffer, Runtime, Slice,
};
use soyokaze::models::{Message, Method, Version};

/// The pointer and length a call takes text as.
fn text(value: &str) -> (*const u8, usize) {
    (value.as_ptr(), value.len())
}

/// What a [`Slice`] points at, or `None` when it is absent.
fn read(slice: Slice) -> Option<&'static [u8]> {
    (!slice.is_absent()).then(|| unsafe { std::slice::from_raw_parts(slice.data, slice.len) })
}

/// What a [`Buffer`] holds, released as it is read.
fn take(buffer: Buffer) -> Vec<u8> {
    let octets = match buffer.data.is_null() {
        true => Vec::new(),
        false => unsafe { std::slice::from_raw_parts(buffer.data, buffer.len) }.to_vec(),
    };

    unsafe { soyokaze_buffer_free(buffer) };
    octets
}

#[test]
fn the_library_reports_its_own_version() {
    let version = read(soyokaze_version()).expect("the version is never absent");
    assert_eq!(version, env!("CARGO_PKG_VERSION").as_bytes());
}

#[test]
fn every_status_carries_a_description() {
    let statuses = [
        Status::Ok,
        Status::Closed,
        Status::Protocol,
        Status::Limit,
        Status::Stream,
        Status::Timeout,
        Status::Tls,
        Status::Version,
        Status::Io,
        Status::Invalid,
        Status::Runtime,
    ];

    for status in statuses {
        let message = read(soyokaze_status_message(status)).expect("a status always describes itself");
        assert!(!message.is_empty(), "{status:?} described itself as nothing");
    }
}

#[test]
fn a_null_error_reads_as_invalid_rather_than_faulting() {
    assert_eq!(unsafe { soyokaze_error_status(ptr::null()) }, Status::Invalid);
    assert!(unsafe { soyokaze_error_message(ptr::null()) }.is_absent());
    unsafe { soyokaze_error_free(ptr::null_mut()) };
}

#[test]
fn a_url_is_taken_apart_into_the_pieces_a_request_needs() {
    let (data, len) = text("https://example.test:8443/a/b?q=1");
    let mut url = ptr::null_mut();

    assert_eq!(unsafe { soyokaze_url_parse(data, len, &mut url, ptr::null_mut()) }, Status::Ok);
    assert!(!url.is_null());

    assert_eq!(read(unsafe { soyokaze_url_scheme(url) }), Some(&b"https"[..]));
    assert_eq!(read(unsafe { soyokaze_url_host(url) }), Some(&b"example.test"[..]));
    assert_eq!(read(unsafe { soyokaze_url_target(url) }), Some(&b"/a/b?q=1"[..]));
    assert_eq!(unsafe { soyokaze_url_port(url) }, 8443);
    assert!(unsafe { soyokaze_url_secure(url) });
    assert_eq!(take(unsafe { soyokaze_url_authority(url) }), b"example.test:8443");

    unsafe { soyokaze_url_free(url) };
}

#[test]
fn a_url_that_will_not_parse_reports_rather_than_returning_a_handle() {
    let (data, len) = text("not a url");
    let mut url = ptr::null_mut();
    let mut error: *mut ErrorHandle = ptr::null_mut();

    let status = unsafe { soyokaze_url_parse(data, len, &mut url, &mut error) };

    assert_ne!(status, Status::Ok);
    assert!(url.is_null(), "a failed parse must not hand back a handle");
    assert!(!error.is_null(), "an error out parameter must be filled in");
    assert_eq!(unsafe { soyokaze_error_status(error) }, status);
    assert!(!read(unsafe { soyokaze_error_message(error) }).expect("an error always says something").is_empty());

    unsafe { soyokaze_error_free(error) };
}

#[test]
fn a_null_out_parameter_is_refused_rather_than_written_through() {
    let (data, len) = text("https://example.test/");
    assert_eq!(unsafe { soyokaze_url_parse(data, len, ptr::null_mut(), ptr::null_mut()) }, Status::Invalid);
}

#[test]
fn text_that_is_not_utf8_is_refused() {
    let invalid = [0xff, 0xfe];
    let mut url = ptr::null_mut();

    let status = unsafe { soyokaze_url_parse(invalid.as_ptr(), invalid.len(), &mut url, ptr::null_mut()) };

    assert_eq!(status, Status::Invalid);
    assert!(url.is_null());
}

#[test]
fn a_null_url_reads_as_absent_throughout() {
    assert!(unsafe { soyokaze_url_scheme(ptr::null()) }.is_absent());
    assert!(unsafe { soyokaze_url_host(ptr::null()) }.is_absent());
    assert!(unsafe { soyokaze_url_target(ptr::null()) }.is_absent());
    assert_eq!(unsafe { soyokaze_url_port(ptr::null()) }, 0);
    assert!(!unsafe { soyokaze_url_secure(ptr::null()) });
    assert!(take(unsafe { soyokaze_url_authority(ptr::null()) }).is_empty());
    unsafe { soyokaze_url_free(ptr::null_mut()) };
}

#[test]
fn a_request_and_a_response_each_carry_only_what_belongs_to_them() {
    let (data, len) = text("/index.html");
    let request = unsafe { soyokaze_message_request(Method::GET, data, len, Version::V1_1) };
    assert!(!request.is_null());

    assert!(unsafe { soyokaze_message_is_request(request) });
    assert!(!unsafe { soyokaze_message_is_response(request) });
    assert_eq!(unsafe { soyokaze_message_method(request) }, Method::GET as i32);
    assert_eq!(unsafe { soyokaze_message_status_code(request) }, -1, "a request has no status code");
    assert_eq!(read(unsafe { soyokaze_message_target(request) }), Some(&b"/index.html"[..]));
    assert_eq!(unsafe { soyokaze_message_version(request) }, Version::V1_1);

    let response = soyokaze_message_response(404, Version::V2_0);
    assert!(unsafe { soyokaze_message_is_response(response) });
    assert!(!unsafe { soyokaze_message_is_request(response) });
    assert_eq!(unsafe { soyokaze_message_status_code(response) }, 404);
    assert_eq!(unsafe { soyokaze_message_method(response) }, -1, "a response has no method");
    assert!(unsafe { soyokaze_message_target(response) }.is_absent(), "a response has no target");

    unsafe { soyokaze_message_free(request) };
    unsafe { soyokaze_message_free(response) };
}

#[test]
fn a_target_that_is_not_utf8_yields_no_message() {
    let invalid = [0xff, 0xfe];
    let request = unsafe { soyokaze_message_request(Method::GET, invalid.as_ptr(), invalid.len(), Version::V1_1) };
    assert!(request.is_null());
}

#[test]
fn appending_keeps_every_field_and_inserting_keeps_one() {
    let response = soyokaze_message_response(200, Version::V1_1);
    let (name, name_len) = text("set-cookie");

    for value in ["a=1", "b=2"] {
        let (value, value_len) = text(value);
        assert!(unsafe { soyokaze_message_append_header(response, name, name_len, value, value_len) });
    }

    assert_eq!(unsafe { soyokaze_message_header_count(response) }, 2, "appending must never fold fields together");
    assert_eq!(read(unsafe { soyokaze_message_header(response, name, name_len) }), Some(&b"a=1"[..]));

    let (replacement, replacement_len) = text("c=3");
    assert!(unsafe { soyokaze_message_insert_header(response, name, name_len, replacement, replacement_len) });
    assert_eq!(unsafe { soyokaze_message_header_count(response) }, 1, "inserting must drop what was there");
    assert_eq!(read(unsafe { soyokaze_message_header(response, name, name_len) }), Some(&b"c=3"[..]));

    assert!(unsafe { soyokaze_message_remove_header(response, name, name_len) });
    assert!(!unsafe { soyokaze_message_remove_header(response, name, name_len) }, "removing twice finds nothing");
    assert_eq!(unsafe { soyokaze_message_header_count(response) }, 0);

    unsafe { soyokaze_message_free(response) };
}

#[test]
fn a_field_that_is_absent_is_told_apart_from_one_that_is_empty() {
    let response = soyokaze_message_response(200, Version::V1_1);
    let (name, name_len) = text("x-empty");
    let (value, value_len) = text("");

    assert!(unsafe { soyokaze_message_append_header(response, name, name_len, value, value_len) });

    let empty = unsafe { soyokaze_message_header(response, name, name_len) };
    assert!(!empty.is_absent(), "a field that is there and empty must not read as absent");
    assert_eq!(empty.len, 0);

    let (missing, missing_len) = text("x-missing");
    assert!(unsafe { soyokaze_message_header(response, missing, missing_len) }.is_absent());

    unsafe { soyokaze_message_free(response) };
}

#[test]
fn a_field_is_matched_without_regard_to_case() {
    let response = soyokaze_message_response(200, Version::V1_1);
    let (name, name_len) = text("Content-Type");
    let (value, value_len) = text("text/plain");
    assert!(unsafe { soyokaze_message_append_header(response, name, name_len, value, value_len) });

    for probe in ["content-type", "CONTENT-TYPE", "Content-Type"] {
        let (probe, probe_len) = text(probe);
        assert_eq!(read(unsafe { soyokaze_message_header(response, probe, probe_len) }), Some(&b"text/plain"[..]), "{probe:?}");
    }

    unsafe { soyokaze_message_free(response) };
}

#[test]
fn walking_past_the_last_field_reads_as_absent() {
    let response = soyokaze_message_response(200, Version::V1_1);
    let (name, name_len) = text("x-one");
    let (value, value_len) = text("1");
    assert!(unsafe { soyokaze_message_append_header(response, name, name_len, value, value_len) });

    assert_eq!(read(unsafe { soyokaze_message_header_name(response, 0) }), Some(&b"x-one"[..]));
    assert_eq!(read(unsafe { soyokaze_message_header_value(response, 0) }), Some(&b"1"[..]));
    assert!(unsafe { soyokaze_message_header_name(response, 1) }.is_absent());
    assert!(unsafe { soyokaze_message_header_value(response, 1) }.is_absent());

    unsafe { soyokaze_message_free(response) };
}

#[test]
fn a_null_message_is_refused_rather_than_dereferenced() {
    let (name, name_len) = text("x");
    let (value, value_len) = text("y");

    assert!(!unsafe { soyokaze_message_append_header(ptr::null_mut(), name, name_len, value, value_len) });
    assert!(!unsafe { soyokaze_message_insert_header(ptr::null_mut(), name, name_len, value, value_len) });
    assert!(!unsafe { soyokaze_message_remove_header(ptr::null_mut(), name, name_len) });
    assert!(!unsafe { soyokaze_message_set_body_data(ptr::null_mut(), value, value_len) });
    assert_eq!(unsafe { soyokaze_message_header_count(ptr::null()) }, 0);
    assert_eq!(unsafe { soyokaze_message_method(ptr::null()) }, -1);
    assert_eq!(unsafe { soyokaze_message_status_code(ptr::null()) }, -1);
    assert_eq!(unsafe { soyokaze_message_body_len(ptr::null()) }, -1);
    assert!(unsafe { soyokaze_message_target(ptr::null()) }.is_absent());
    unsafe { soyokaze_message_free(ptr::null_mut()) };
}

#[test]
fn a_body_reads_back_whichever_way_it_was_set() {
    let runtime = soyokaze_runtime_new(1);
    assert!(!runtime.is_null());

    let message = soyokaze_message_response(200, Version::V1_1);
    let mut buffer = Buffer::EMPTY;

    assert_eq!(unsafe { soyokaze_message_body_len(message) }, -1, "a message with no body has no length");
    assert_eq!(unsafe { soyokaze_message_body(runtime, message, &mut buffer, ptr::null_mut()) }, Status::Ok);
    assert!(take(buffer).is_empty(), "a message with no body reads as nothing");

    let (data, len) = text("octets");
    assert!(unsafe { soyokaze_message_set_body_data(message, data, len) });
    assert_eq!(unsafe { soyokaze_message_body_len(message) }, 6);
    buffer = Buffer::EMPTY;
    assert_eq!(unsafe { soyokaze_message_body(runtime, message, &mut buffer, ptr::null_mut()) }, Status::Ok);
    assert_eq!(take(buffer), b"octets");

    let (value, value_len) = text("text");
    assert!(unsafe { soyokaze_message_set_body_text(message, value, value_len) });
    buffer = Buffer::EMPTY;
    assert_eq!(unsafe { soyokaze_message_body(runtime, message, &mut buffer, ptr::null_mut()) }, Status::Ok);
    assert_eq!(take(buffer), b"text");

    unsafe { soyokaze_message_free(message) };
    unsafe { soyokaze_runtime_free(runtime) };
}

#[test]
fn a_body_that_names_a_file_is_read_only_when_it_is_asked_for() {
    let runtime = soyokaze_runtime_new(1);
    let message = soyokaze_message_response(200, Version::V1_1);

    let (path, path_len) = text("tests/ffi.rs");
    assert!(unsafe { soyokaze_message_set_body_file(message, path, path_len) });
    assert_eq!(unsafe { soyokaze_message_body_len(message) }, -1, "a file body has no length until it is read");

    let mut buffer = Buffer::EMPTY;
    assert_eq!(unsafe { soyokaze_message_body(runtime, message, &mut buffer, ptr::null_mut()) }, Status::Ok);
    assert!(!take(buffer).is_empty());

    let (missing, missing_len) = text("tests/does-not-exist");
    assert!(unsafe { soyokaze_message_set_body_file(message, missing, missing_len) });

    let mut error: *mut ErrorHandle = ptr::null_mut();
    buffer = Buffer::EMPTY;
    assert_eq!(unsafe { soyokaze_message_body(runtime, message, &mut buffer, &mut error) }, Status::Io);
    assert!(!error.is_null());
    unsafe { soyokaze_error_free(error) };

    unsafe { soyokaze_message_free(message) };
    unsafe { soyokaze_runtime_free(runtime) };
}

#[test]
fn an_empty_buffer_may_be_freed() {
    unsafe { soyokaze_buffer_free(Buffer::EMPTY) };
}

#[test]
fn a_runtime_is_built_for_any_thread_count() {
    for workers in [0, 1, 4] {
        let runtime: *mut Runtime = soyokaze_runtime_new(workers);
        assert!(!runtime.is_null(), "{workers} workers");
        unsafe { soyokaze_runtime_free(runtime) };
    }

    unsafe { soyokaze_runtime_free(ptr::null_mut()) };
}

#[test]
fn a_client_takes_its_defaults_from_a_null_configuration() {
    let client = unsafe { soyokaze_client_new(ptr::null()) };
    assert!(!client.is_null());
    unsafe { soyokaze_client_free(client) };

    let version = Version::V2_0 as i32;
    let config = ClientConfig { versions: &version, version_count: 1, secure: false, cookies: false, hsts: false, ..ClientConfig::DEFAULT };
    let client = unsafe { soyokaze_client_new(&config) };
    assert!(!client.is_null());
    unsafe { soyokaze_client_free(client) };

    let bogus = 17;
    let config = ClientConfig { versions: &bogus, version_count: 1, ..ClientConfig::DEFAULT };
    assert!(unsafe { soyokaze_client_new(&config) }.is_null(), "a number that names no version is refused");

    unsafe { soyokaze_client_free(ptr::null_mut()) };
}

#[test]
fn a_call_without_a_runtime_is_refused() {
    let client = unsafe { soyokaze_client_new(ptr::null()) };
    let (url, url_len) = text("http://127.0.0.1:1/");
    let mut response = ptr::null_mut();

    let status = unsafe { soyokaze_client_get(ptr::null_mut(), client, url, url_len, &mut response, ptr::null_mut()) };

    assert_eq!(status, Status::Invalid);
    assert!(response.is_null());

    unsafe { soyokaze_client_free(client) };
}

/// Answers every request with its own target, so the round trip proves the
/// request reached the callback intact.
extern "C" fn echo(context: *mut c_void, request: *mut Message) -> *mut Message {
    let seen = unsafe { &*(context as *const std::sync::atomic::AtomicUsize) };
    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let version = unsafe { soyokaze_message_version(request) };
    let target = read(unsafe { soyokaze_message_target(request) }).unwrap_or_default().to_vec();
    unsafe { soyokaze_message_free(request) };

    let response = unsafe { soyokaze_response_with_body(200, version, target.as_ptr(), target.len()) };
    let (name, name_len) = text("x-answered-by");
    let (value, value_len) = text("callback");
    unsafe { soyokaze_message_append_header(response, name, name_len, value, value_len) };

    response
}

/// Answers nothing, which the library turns into a bare `500`.
extern "C" fn refuse(_context: *mut c_void, request: *mut Message) -> *mut Message {
    unsafe { soyokaze_message_free(request) };
    ptr::null_mut()
}

/// Serves `handler` on a kernel-chosen TCP port and hands back what to reach it
/// by, so a round trip can be written without naming a port.
fn serve(runtime: *mut Runtime, handler: soyokaze::ffi::api::server::OnRequest, context: *mut c_void) -> (*mut soyokaze::api::server::Server, *mut soyokaze::api::server::ServerHandle, String) {
    let server = unsafe { soyokaze_server_new(ptr::null()) };
    assert!(!server.is_null());

    let port = Port { kind: PortKind::TCP, number: 0, path: ptr::null(), path_len: 0 };
    let mut handle = ptr::null_mut();
    let mut error: *mut ErrorHandle = ptr::null_mut();

    let status = unsafe { soyokaze_server_serve(runtime, server, handler, None, context, &port, 1, &mut handle, &mut error) };
    assert_eq!(status, Status::Ok, "the server did not bind");
    assert!(!handle.is_null());

    let bound = unsafe { soyokaze_server_handle_port(handle) };
    assert_ne!(bound, 0, "a port of zero must report the one the kernel chose");

    (server, handle, format!("http://127.0.0.1:{bound}"))
}

#[test]
fn a_request_crosses_to_the_callback_and_its_answer_crosses_back() {
    let runtime = soyokaze_runtime_new(0);
    let seen = std::sync::atomic::AtomicUsize::new(0);
    let (server, handle, origin) = serve(runtime, echo, &seen as *const _ as *mut c_void);

    let client = unsafe { soyokaze_client_new(ptr::null()) };
    let url = format!("{origin}/hello");
    let (url_data, url_len) = text(&url);

    let request = unsafe { soyokaze_message_request(Method::GET, url_data, url_len, Version::V1_1) };
    let (name, name_len) = text("x-probe");
    let (value, value_len) = text("sent");
    assert!(unsafe { soyokaze_message_append_header(request, name, name_len, value, value_len) });

    let mut response = ptr::null_mut();
    let mut error: *mut ErrorHandle = ptr::null_mut();
    let status = unsafe { soyokaze_client_fetch(runtime, client, Method::GET, url_data, url_len, request, &mut response, &mut error) };

    assert_eq!(status, Status::Ok, "the exchange failed");
    assert!(!response.is_null());
    assert_eq!(unsafe { soyokaze_message_status_code(response) }, 200);
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1, "the callback ran once");

    let (answered, answered_len) = text("x-answered-by");
    assert_eq!(read(unsafe { soyokaze_message_header(response, answered, answered_len) }), Some(&b"callback"[..]));

    let mut buffer = Buffer::EMPTY;
    assert_eq!(unsafe { soyokaze_message_body(runtime, response, &mut buffer, ptr::null_mut()) }, Status::Ok);
    assert_eq!(take(buffer), b"/hello", "the target the callback saw is what the client asked for");

    unsafe { soyokaze_message_free(response) };
    unsafe { soyokaze_client_free(client) };
    unsafe { soyokaze_server_handle_close(runtime, handle, 5.0) };
    unsafe { soyokaze_server_free(server) };
    unsafe { soyokaze_runtime_free(runtime) };
}

#[test]
fn a_callback_that_answers_nothing_yields_a_bare_failure() {
    let runtime = soyokaze_runtime_new(0);
    let (server, handle, origin) = serve(runtime, refuse, ptr::null_mut());

    let client = unsafe { soyokaze_client_new(ptr::null()) };
    let url = format!("{origin}/");
    let (url_data, url_len) = text(&url);

    let mut response = ptr::null_mut();
    let status = unsafe { soyokaze_client_get(runtime, client, url_data, url_len, &mut response, ptr::null_mut()) };

    assert_eq!(status, Status::Ok);
    assert_eq!(unsafe { soyokaze_message_status_code(response) }, 500, "a null answer is a bare 500");

    unsafe { soyokaze_message_free(response) };
    unsafe { soyokaze_client_free(client) };
    unsafe { soyokaze_server_handle_close(runtime, handle, 5.0) };
    unsafe { soyokaze_server_free(server) };
    unsafe { soyokaze_runtime_free(runtime) };
}

#[test]
fn several_requests_go_over_one_server_in_turn() {
    let runtime = soyokaze_runtime_new(0);
    let seen = std::sync::atomic::AtomicUsize::new(0);
    let (server, handle, origin) = serve(runtime, echo, &seen as *const _ as *mut c_void);

    let client = unsafe { soyokaze_client_new(ptr::null()) };

    for index in 0..4 {
        let url = format!("{origin}/page/{index}");
        let (url_data, url_len) = text(&url);
        let mut response = ptr::null_mut();

        assert_eq!(
            unsafe { soyokaze_client_get(runtime, client, url_data, url_len, &mut response, ptr::null_mut()) },
            Status::Ok,
            "request {index}"
        );

        let mut buffer = Buffer::EMPTY;
        assert_eq!(unsafe { soyokaze_message_body(runtime, response, &mut buffer, ptr::null_mut()) }, Status::Ok);
        assert_eq!(take(buffer), format!("/page/{index}").as_bytes());

        unsafe { soyokaze_message_free(response) };
    }

    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 4);

    unsafe { soyokaze_client_free(client) };
    unsafe { soyokaze_server_handle_close(runtime, handle, 5.0) };
    unsafe { soyokaze_server_free(server) };
    unsafe { soyokaze_runtime_free(runtime) };
}

#[test]
fn a_port_that_names_nothing_usable_is_refused() {
    let runtime = soyokaze_runtime_new(1);
    let server = unsafe { soyokaze_server_new(ptr::null()) };

    let port = Port { kind: PortKind::UDS, number: 0, path: ptr::null(), path_len: 0 };
    let mut handle = ptr::null_mut();

    let status = unsafe { soyokaze_server_serve(runtime, server, echo, None, ptr::null_mut(), &port, 1, &mut handle, ptr::null_mut()) };

    assert_eq!(status, Status::Invalid, "a Unix port with no path names nothing");
    assert!(handle.is_null());

    unsafe { soyokaze_server_free(server) };
    unsafe { soyokaze_runtime_free(runtime) };
}

#[test]
fn closing_a_null_handle_does_nothing() {
    let runtime = soyokaze_runtime_new(1);
    unsafe { soyokaze_server_handle_close(runtime, ptr::null_mut(), 0.0) };
    assert_eq!(unsafe { soyokaze_server_handle_port(ptr::null()) }, 0);
    unsafe { soyokaze_server_free(ptr::null_mut()) };
    unsafe { soyokaze_runtime_free(runtime) };
}

#[test]
fn the_default_limits_cross_field_for_field() {
    let limits = soyokaze_limits_default();
    let reference = soyokaze::Limits::default();

    assert_eq!(limits.max_message_size, reference.max_message_size);
    assert_eq!(limits.max_header_count, reference.max_header_count);
    assert_eq!(limits.read_timeout, reference.read_timeout);
    assert_eq!(limits.ws_max_fragments, reference.ws_max_fragments);
    assert_eq!(limits.max_hsts_entries, reference.max_hsts_entries);
    assert_eq!(limits.parse(), reference, "the round trip through C loses nothing");
}

#[test]
fn trailers_mirror_headers_on_a_message() {
    use soyokaze::ffi::models::{
        soyokaze_message_append_trailer, soyokaze_message_insert_trailer, soyokaze_message_remove_trailer,
        soyokaze_message_trailer, soyokaze_message_trailer_count, soyokaze_message_trailer_name,
        soyokaze_message_trailer_value,
    };

    let message = soyokaze_message_response(200, Version::V1_1);
    let (name, name_len) = text("checksum");

    for value in ["abc", "def"] {
        let (value, value_len) = text(value);
        assert!(unsafe { soyokaze_message_append_trailer(message, name, name_len, value, value_len) });
    }

    assert_eq!(unsafe { soyokaze_message_trailer_count(message) }, 2, "appending must never fold fields together");
    assert_eq!(read(unsafe { soyokaze_message_trailer(message, name, name_len) }), Some(&b"abc"[..]));
    assert_eq!(read(unsafe { soyokaze_message_trailer_name(message, 0) }), Some(&b"checksum"[..]));
    assert_eq!(read(unsafe { soyokaze_message_trailer_value(message, 1) }), Some(&b"def"[..]));

    let (replacement, replacement_len) = text("ghi");
    assert!(unsafe { soyokaze_message_insert_trailer(message, name, name_len, replacement, replacement_len) });
    assert_eq!(unsafe { soyokaze_message_trailer_count(message) }, 1, "inserting must drop what was there");

    assert!(unsafe { soyokaze_message_remove_trailer(message, name, name_len) });
    assert!(!unsafe { soyokaze_message_remove_trailer(message, name, name_len) }, "removing twice finds nothing");

    unsafe { soyokaze_message_free(message) };
}

#[test]
fn the_connection_facts_read_as_absent_until_a_connection_sets_them() {
    use soyokaze::ffi::models::{
        soyokaze_message_connection_id, soyokaze_message_early_data, soyokaze_message_quic,
        soyokaze_message_quic_version, soyokaze_message_set_secure, soyokaze_message_set_stream_id,
        soyokaze_message_stream_id, soyokaze_message_tls, soyokaze_message_tls_cipher, soyokaze_message_tls_group,
        soyokaze_message_tls_version,
    };

    let message = soyokaze_message_response(200, Version::V2_0);

    assert_eq!(unsafe { soyokaze_message_stream_id(message) }, -1);
    assert!(unsafe { soyokaze_message_connection_id(message) }.is_absent());
    assert!(!unsafe { soyokaze_message_early_data(message) });
    assert!(!unsafe { soyokaze_message_tls(message) });
    assert_eq!(unsafe { soyokaze_message_tls_version(message) }, -1);
    assert_eq!(unsafe { soyokaze_message_tls_group(message) }, -1);
    assert_eq!(unsafe { soyokaze_message_tls_cipher(message) }, -1);
    assert!(!unsafe { soyokaze_message_quic(message) });
    assert_eq!(unsafe { soyokaze_message_quic_version(message) }, -1);

    assert!(unsafe { soyokaze_message_set_stream_id(message, 7) });
    assert_eq!(unsafe { soyokaze_message_stream_id(message) }, 7);
    assert!(unsafe { soyokaze_message_set_stream_id(message, -1) }, "a negative stream identifier clears");
    assert_eq!(unsafe { soyokaze_message_stream_id(message) }, -1);

    assert!(unsafe { soyokaze_message_set_secure(message, true) });
    assert!(unsafe { soyokaze::ffi::models::soyokaze_message_secure(message) });

    unsafe { soyokaze_message_free(message) };
}

#[test]
fn each_response_constructor_sets_its_content_type() {
    use soyokaze::ffi::responses::{
        soyokaze_response_content, soyokaze_response_file, soyokaze_response_html, soyokaze_response_json,
        soyokaze_response_markdown, soyokaze_response_redirect, soyokaze_response_text,
    };

    let (content, content_len) = text("payload");
    let (kind, kind_len) = text("content-type");

    let cases: [(*mut Message, &[u8]); 5] = [
        (unsafe { soyokaze_response_text(content, content_len, Version::V1_1) }, b"text/plain"),
        (unsafe { soyokaze_response_html(content, content_len, Version::V1_1) }, b"text/html"),
        (unsafe { soyokaze_response_markdown(content, content_len, Version::V1_1) }, b"text/markdown"),
        (unsafe { soyokaze_response_json(content, content_len, Version::V1_1) }, b"application/json"),
        (unsafe { soyokaze_response_content(kind, kind_len, content, content_len, Version::V1_1) }, b"content-type"),
    ];

    for (response, expected) in cases {
        assert_eq!(unsafe { soyokaze_message_status_code(response) }, 200);
        assert_eq!(read(unsafe { soyokaze_message_header(response, kind, kind_len) }), Some(expected));
        unsafe { soyokaze_message_free(response) };
    }

    let (path, path_len) = text("style.css");
    let file = unsafe { soyokaze_response_file(path, path_len, Version::V1_1) };
    assert_eq!(read(unsafe { soyokaze_message_header(file, kind, kind_len) }), Some(&b"text/css"[..]));
    unsafe { soyokaze_message_free(file) };

    let (target, target_len) = text("/elsewhere");
    let redirect = unsafe { soyokaze_response_redirect(target, target_len, Version::V1_1) };
    assert_eq!(unsafe { soyokaze_message_status_code(redirect) }, 307);
    let (location, location_len) = text("location");
    assert_eq!(read(unsafe { soyokaze_message_header(redirect, location, location_len) }), Some(&b"/elsewhere"[..]));
    unsafe { soyokaze_message_free(redirect) };
}

#[test]
fn a_cookie_field_parses_and_builds() {
    use soyokaze::ffi::headers::{
        soyokaze_cookie_append, soyokaze_cookie_build, soyokaze_cookie_count, soyokaze_cookie_free,
        soyokaze_cookie_get, soyokaze_cookie_name, soyokaze_cookie_parse, soyokaze_cookie_value,
    };

    let (value, value_len) = text("a=1; b=\"quoted\"; malformed; a=repeated");
    let cookie = unsafe { soyokaze_cookie_parse(value, value_len) };
    assert!(!cookie.is_null());

    assert_eq!(unsafe { soyokaze_cookie_count(cookie) }, 2, "junk is skipped and the first repeat wins");
    assert_eq!(read(unsafe { soyokaze_cookie_name(cookie, 0) }), Some(&b"a"[..]));
    assert_eq!(read(unsafe { soyokaze_cookie_value(cookie, 1) }), Some(&b"quoted"[..]), "quotes unwrap");

    let (name, name_len) = text("a");
    assert_eq!(read(unsafe { soyokaze_cookie_get(cookie, name, name_len) }), Some(&b"1"[..]));

    let (extra, extra_len) = text("c");
    let (third, third_len) = text("3");
    assert!(unsafe { soyokaze_cookie_append(cookie, extra, extra_len, third, third_len) });
    assert_eq!(take(unsafe { soyokaze_cookie_build(cookie) }), b"a=1; b=quoted; c=3");

    unsafe { soyokaze_cookie_free(cookie) };
}

#[test]
fn a_setcookie_carries_every_attribute_across() {
    use soyokaze::ffi::headers::{
        soyokaze_setcookie_build, soyokaze_setcookie_domain, soyokaze_setcookie_free, soyokaze_setcookie_httponly,
        soyokaze_setcookie_max_age, soyokaze_setcookie_name, soyokaze_setcookie_parse, soyokaze_setcookie_path,
        soyokaze_setcookie_samesite, soyokaze_setcookie_secure, soyokaze_setcookie_set_max_age,
        soyokaze_setcookie_set_samesite, soyokaze_setcookie_value,
    };

    let (value, value_len) = text("sid=abc; Max-Age=3600; Domain=.example.test; Path=/a; Secure; HttpOnly; SameSite=Lax");
    let mut cookie = ptr::null_mut();
    assert_eq!(unsafe { soyokaze_setcookie_parse(value, value_len, &mut cookie, ptr::null_mut()) }, Status::Ok);

    assert_eq!(read(unsafe { soyokaze_setcookie_name(cookie) }), Some(&b"sid"[..]));
    assert_eq!(read(unsafe { soyokaze_setcookie_value(cookie) }), Some(&b"abc"[..]));

    let mut max_age = 0;
    assert!(unsafe { soyokaze_setcookie_max_age(cookie, &mut max_age) });
    assert_eq!(max_age, 3600);

    assert_eq!(read(unsafe { soyokaze_setcookie_domain(cookie) }), Some(&b".example.test"[..]));
    assert_eq!(read(unsafe { soyokaze_setcookie_path(cookie) }), Some(&b"/a"[..]));
    assert!(unsafe { soyokaze_setcookie_secure(cookie) });
    assert!(unsafe { soyokaze_setcookie_httponly(cookie) });
    assert_eq!(unsafe { soyokaze_setcookie_samesite(cookie) }, 1, "Lax is 1");

    assert!(unsafe { soyokaze_setcookie_set_max_age(cookie, false, 0) });
    assert!(!unsafe { soyokaze_setcookie_max_age(cookie, &mut max_age) }, "clearing leaves nothing to read");
    assert!(unsafe { soyokaze_setcookie_set_samesite(cookie, -1) });
    assert!(!unsafe { soyokaze_setcookie_set_samesite(cookie, 9) }, "a number that names nothing is refused");

    let mut built = Buffer::EMPTY;
    assert_eq!(unsafe { soyokaze_setcookie_build(cookie, &mut built, ptr::null_mut()) }, Status::Ok);
    assert_eq!(take(built), b"sid=abc; Domain=.example.test; Path=/a; Secure; HttpOnly");

    unsafe { soyokaze_setcookie_free(cookie) };
}

#[test]
fn a_setcookie_value_that_could_break_out_is_refused() {
    use soyokaze::ffi::headers::{soyokaze_setcookie_build, soyokaze_setcookie_free, soyokaze_setcookie_new};

    let (name, name_len) = text("sid");
    let (value, value_len) = text("a;b");
    let cookie = unsafe { soyokaze_setcookie_new(name, name_len, value, value_len) };

    let mut built = Buffer::EMPTY;
    let mut error: *mut ErrorHandle = ptr::null_mut();
    assert_eq!(unsafe { soyokaze_setcookie_build(cookie, &mut built, &mut error) }, Status::Protocol);
    assert!(!error.is_null());

    unsafe { soyokaze_error_free(error) };
    unsafe { soyokaze_setcookie_free(cookie) };
}

#[test]
fn a_jar_returns_matching_cookies_and_a_zero_age_deletes() {
    use soyokaze::ffi::headers::{
        soyokaze_cookiejar_cookie, soyokaze_cookiejar_free, soyokaze_cookiejar_learn, soyokaze_cookiejar_new,
        soyokaze_cookiejar_prune,
    };

    let jar = unsafe { soyokaze_cookiejar_new(ptr::null()) };
    let (data, len) = text("https://example.test/a/b");
    let mut url = ptr::null_mut();
    assert_eq!(unsafe { soyokaze_url_parse(data, len, &mut url, ptr::null_mut()) }, Status::Ok);

    let values = [Slice::text("sid=abc; Path=/a"), Slice::text("other=1; Domain=elsewhere.test")];
    assert!(unsafe { soyokaze_cookiejar_learn(jar, url, values.as_ptr(), values.len()) });

    assert_eq!(take(unsafe { soyokaze_cookiejar_cookie(jar, url) }), b"sid=abc", "a cookie for another domain must not be sent");

    let deletion = [Slice::text("sid=abc; Path=/a; Max-Age=0")];
    assert!(unsafe { soyokaze_cookiejar_learn(jar, url, deletion.as_ptr(), deletion.len()) });

    let nothing = unsafe { soyokaze_cookiejar_cookie(jar, url) };
    assert!(nothing.data.is_null(), "no match reads as absent, not empty");
    unsafe { soyokaze_buffer_free(nothing) };

    unsafe { soyokaze_cookiejar_prune(jar) };
    unsafe { soyokaze_url_free(url) };
    unsafe { soyokaze_cookiejar_free(jar) };
}

#[test]
fn an_hsts_policy_and_store_follow_rfc_6797() {
    use soyokaze::ffi::helpers::hsts::{
        soyokaze_hsts_policy_build, soyokaze_hsts_policy_parse, soyokaze_hsts_store_free, soyokaze_hsts_store_learn,
        soyokaze_hsts_store_new, soyokaze_hsts_store_secure, HstsPolicy,
    };

    let (value, value_len) = text("max-age=31536000; includeSubDomains");
    let mut policy = HstsPolicy { max_age: 0, include_subdomains: false, preload: false };
    assert!(unsafe { soyokaze_hsts_policy_parse(value, value_len, &mut policy) });
    assert_eq!(policy.max_age, 31536000);
    assert!(policy.include_subdomains && !policy.preload);

    assert_eq!(take(unsafe { soyokaze_hsts_policy_build(&policy) }), b"max-age=31536000; includeSubDomains");

    let (repeated, repeated_len) = text("max-age=1; max-age=2");
    assert!(!unsafe { soyokaze_hsts_policy_parse(repeated, repeated_len, &mut policy) }, "a repeated directive cannot be trusted");

    let store = unsafe { soyokaze_hsts_store_new(ptr::null()) };
    let (host, host_len) = text("example.test");
    let (sub, sub_len) = text("sub.example.test");

    assert!(unsafe { soyokaze_hsts_store_learn(store, host, host_len, value, value_len, true) });
    assert!(unsafe { soyokaze_hsts_store_secure(store, host, host_len) });
    assert!(unsafe { soyokaze_hsts_store_secure(store, sub, sub_len) }, "includeSubDomains covers children");

    let (plain, plain_len) = text("plain.test");
    assert!(unsafe { soyokaze_hsts_store_learn(store, plain, plain_len, value, value_len, false) });
    assert!(!unsafe { soyokaze_hsts_store_secure(store, plain, plain_len) }, "a policy over plaintext is ignored");

    unsafe { soyokaze_hsts_store_free(store) };
}

#[test]
fn base64_sha1_and_huffman_match_their_rfcs() {
    use soyokaze::ffi::helpers::base64::{soyokaze_base64_decode, soyokaze_base64_encode};
    use soyokaze::ffi::helpers::huffman::{soyokaze_huffman_decode, soyokaze_huffman_encode};
    use soyokaze::ffi::helpers::sha1::soyokaze_sha1;

    let (data, data_len) = text("foobar");
    assert_eq!(take(unsafe { soyokaze_base64_encode(data, data_len) }), b"Zm9vYmFy");

    let (encoded, encoded_len) = text("Zm9vYmFy");
    let mut decoded = Buffer::EMPTY;
    assert!(unsafe { soyokaze_base64_decode(encoded, encoded_len, &mut decoded) });
    assert_eq!(take(decoded), b"foobar");

    let (bad, bad_len) = text("not base64!");
    assert!(!unsafe { soyokaze_base64_decode(bad, bad_len, &mut Buffer::EMPTY) });

    let (abc, abc_len) = text("abc");
    let digest = take(unsafe { soyokaze_sha1(abc, abc_len) });
    assert_eq!(digest.len(), 20);
    assert_eq!(digest[..4], [0xa9, 0x99, 0x3e, 0x36], "RFC 3174's own vector");

    let (www, www_len) = text("www.example.com");
    let huffman = take(unsafe { soyokaze_huffman_encode(www, www_len) });
    assert_eq!(huffman, [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff], "RFC 7541 appendix C");

    let mut back = Buffer::EMPTY;
    assert!(unsafe { soyokaze_huffman_decode(huffman.as_ptr(), huffman.len(), &mut back) });
    assert_eq!(take(back), b"www.example.com");

    let junk = [0xffu8; 5];
    assert!(!unsafe { soyokaze_huffman_decode(junk.as_ptr(), junk.len(), &mut Buffer::EMPTY) });
}

#[test]
fn hpack_round_trips_a_section_through_its_dynamic_tables() {
    use soyokaze::ffi::helpers::hpack::{
        soyokaze_fields_count, soyokaze_fields_free, soyokaze_fields_name, soyokaze_fields_value,
        soyokaze_hpack_decode, soyokaze_hpack_decoder_free, soyokaze_hpack_decoder_new, soyokaze_hpack_encode,
        soyokaze_hpack_encoder_free, soyokaze_hpack_encoder_new, Field,
    };

    let encoder = soyokaze_hpack_encoder_new();
    let decoder = soyokaze_hpack_decoder_new();

    let fields = [
        Field { name: Slice::text(":method"), value: Slice::text("GET") },
        Field { name: Slice::text("x-custom"), value: Slice::text("value") },
    ];

    for round in 0..2 {
        let block = take(unsafe { soyokaze_hpack_encode(encoder, fields.as_ptr(), fields.len()) });

        let mut decoded = ptr::null_mut();
        assert_eq!(
            unsafe { soyokaze_hpack_decode(decoder, block.as_ptr(), block.len(), &mut decoded, ptr::null_mut()) },
            Status::Ok,
            "round {round} must decode, dynamic table and all",
        );

        assert_eq!(unsafe { soyokaze_fields_count(decoded) }, 2);
        assert_eq!(read(unsafe { soyokaze_fields_name(decoded, 1) }), Some(&b"x-custom"[..]));
        assert_eq!(read(unsafe { soyokaze_fields_value(decoded, 0) }), Some(&b"GET"[..]));
        unsafe { soyokaze_fields_free(decoded) };
    }

    let garbage = [0xffu8, 0xff, 0xff];
    let mut decoded = ptr::null_mut();
    let mut error: *mut ErrorHandle = ptr::null_mut();
    assert_eq!(
        unsafe { soyokaze_hpack_decode(decoder, garbage.as_ptr(), garbage.len(), &mut decoded, &mut error) },
        Status::Protocol,
    );
    unsafe { soyokaze_error_free(error) };

    unsafe { soyokaze_hpack_encoder_free(encoder) };
    unsafe { soyokaze_hpack_decoder_free(decoder) };
}

#[test]
fn qpack_round_trips_with_its_instruction_streams() {
    use soyokaze::ffi::helpers::hpack::{soyokaze_fields_count, soyokaze_fields_free, Field};
    use soyokaze::ffi::helpers::qpack::{
        soyokaze_qpack_decode, soyokaze_qpack_decoder_free, soyokaze_qpack_decoder_new,
        soyokaze_qpack_decoder_on_encoder_instructions, soyokaze_qpack_decoder_set_max_capacity, soyokaze_qpack_encode,
        soyokaze_qpack_encoder_free, soyokaze_qpack_encoder_new, soyokaze_qpack_encoder_on_decoder_instructions,
        soyokaze_qpack_encoder_set_capacity, soyokaze_qpack_encoder_set_max_capacity,
    };

    let encoder = soyokaze_qpack_encoder_new();
    let decoder = soyokaze_qpack_decoder_new();

    assert!(unsafe { soyokaze_qpack_encoder_set_max_capacity(encoder, 4096) });
    assert!(unsafe { soyokaze_qpack_decoder_set_max_capacity(decoder, 4096) });

    let mut setup = Buffer::EMPTY;
    assert!(unsafe { soyokaze_qpack_encoder_set_capacity(encoder, 4096, &mut setup) });
    let setup = take(setup);
    assert!(!setup.is_empty(), "announcing capacity rides the encoder stream");

    let mut answer = Buffer::EMPTY;
    assert_eq!(
        unsafe { soyokaze_qpack_decoder_on_encoder_instructions(decoder, setup.as_ptr(), setup.len(), &mut answer, ptr::null_mut()) },
        Status::Ok,
    );
    assert!(take(answer).is_empty(), "a capacity change alone needs no answer");

    let fields = [Field { name: Slice::text("x-custom"), value: Slice::text("value") }];

    let mut block = Buffer::EMPTY;
    let mut instructions = Buffer::EMPTY;
    assert!(unsafe { soyokaze_qpack_encode(encoder, 0, fields.as_ptr(), fields.len(), &mut block, &mut instructions) });
    let block = take(block);
    let instructions = take(instructions);
    assert!(!instructions.is_empty(), "fresh fields are inserted into the dynamic table");

    let mut increment = Buffer::EMPTY;
    assert_eq!(
        unsafe {
            soyokaze_qpack_decoder_on_encoder_instructions(decoder, instructions.as_ptr(), instructions.len(), &mut increment, ptr::null_mut())
        },
        Status::Ok,
    );
    let increment = take(increment);
    assert!(!increment.is_empty(), "insertions are answered with an Insert Count Increment");
    assert_eq!(
        unsafe { soyokaze_qpack_encoder_on_decoder_instructions(encoder, increment.as_ptr(), increment.len(), ptr::null_mut()) },
        Status::Ok,
    );

    let mut decoded = ptr::null_mut();
    let mut ack = Buffer::EMPTY;
    assert_eq!(
        unsafe { soyokaze_qpack_decode(decoder, 0, block.as_ptr(), block.len(), &mut decoded, &mut ack, ptr::null_mut()) },
        Status::Ok,
    );
    assert_eq!(unsafe { soyokaze_fields_count(decoded) }, 1);
    unsafe { soyokaze_fields_free(decoded) };
    unsafe { soyokaze_buffer_free(ack) };

    unsafe { soyokaze_qpack_encoder_free(encoder) };
    unsafe { soyokaze_qpack_decoder_free(decoder) };
}

#[test]
fn ech_keys_publish_a_list_their_parser_reads_back() {
    use soyokaze::ffi::tls::{
        soyokaze_ech_config_list_count, soyokaze_ech_config_list_free, soyokaze_ech_config_list_parse,
        soyokaze_ech_config_maximum_name_length, soyokaze_ech_config_public_name, soyokaze_ech_config_version,
        soyokaze_ech_keys_config, soyokaze_ech_keys_config_list, soyokaze_ech_keys_free, soyokaze_ech_keys_generate,
        soyokaze_ech_keys_new, soyokaze_ech_keys_private_key,
    };

    let (name, name_len) = text("public.example");
    let mut keys = ptr::null_mut();
    assert_eq!(unsafe { soyokaze_ech_keys_generate(name, name_len, 7, &mut keys, ptr::null_mut()) }, Status::Ok);

    let private = read(unsafe { soyokaze_ech_keys_private_key(keys) }).expect("the private key is there");
    assert_eq!(private.len(), 32, "an X25519 private key is 32 octets");

    let config = read(unsafe { soyokaze_ech_keys_config(keys) }).expect("the config is there").to_vec();
    let published = take(unsafe { soyokaze_ech_keys_config_list(keys) });

    let mut list = ptr::null_mut();
    assert_eq!(unsafe { soyokaze_ech_config_list_parse(published.as_ptr(), published.len(), &mut list, ptr::null_mut()) }, Status::Ok);
    assert_eq!(unsafe { soyokaze_ech_config_list_count(list) }, 1);
    assert_eq!(unsafe { soyokaze_ech_config_version(list, 0) }, 0xfe0d);
    assert_eq!(read(unsafe { soyokaze_ech_config_public_name(list, 0) }), Some(&b"public.example"[..]));
    assert_eq!(unsafe { soyokaze_ech_config_maximum_name_length(list, 0) }, 64);
    assert_eq!(unsafe { soyokaze_ech_config_maximum_name_length(list, 1) }, -1, "past the end reads as absent");
    unsafe { soyokaze_ech_config_list_free(list) };

    let rebuilt = unsafe { soyokaze_ech_keys_new(config.as_ptr(), config.len(), private.as_ptr(), private.len()) };
    assert!(!rebuilt.is_null());
    assert_eq!(take(unsafe { soyokaze_ech_keys_config_list(rebuilt) }), published, "keys rebuild from their parts");
    unsafe { soyokaze_ech_keys_free(rebuilt) };

    unsafe { soyokaze_ech_keys_free(keys) };
}

#[test]
fn an_identity_is_built_from_blobs_and_a_bad_pkcs12_is_refused() {
    use soyokaze::ffi::tls::{soyokaze_identity_free, soyokaze_identity_from_pkcs12, soyokaze_identity_new};

    let chain = [Slice::text("not a certificate")];
    let (key, key_len) = text("not a key");
    let identity = unsafe { soyokaze_identity_new(chain.as_ptr(), chain.len(), key, key_len) };
    assert!(!identity.is_null(), "nothing is parsed until a server is built");
    unsafe { soyokaze_identity_free(identity) };

    let (junk, junk_len) = text("not an archive");
    let (passphrase, passphrase_len) = text("");
    let mut parsed = ptr::null_mut();
    let mut error: *mut ErrorHandle = ptr::null_mut();
    assert_eq!(
        unsafe { soyokaze_identity_from_pkcs12(junk, junk_len, passphrase, passphrase_len, &mut parsed, &mut error) },
        Status::Tls,
    );
    unsafe { soyokaze_error_free(error) };
}

#[test]
fn the_http_date_renders_the_imf_fixdate() {
    use soyokaze::ffi::finalizer::soyokaze_http_date;

    assert_eq!(take(soyokaze_http_date(784111777)), b"Sun, 06 Nov 1994 08:49:37 GMT");
    assert_eq!(take(soyokaze_http_date(0)).len(), 29);
}

#[test]
fn a_cluster_answers_and_reports_its_workers() {
    use soyokaze::ffi::api::server::{soyokaze_cluster_close, soyokaze_cluster_port, soyokaze_cluster_workers, soyokaze_server_run};

    let seen = std::sync::atomic::AtomicUsize::new(0);
    let server = unsafe { soyokaze_server_new(ptr::null()) };
    let port = Port { kind: PortKind::TCP, number: 0, path: ptr::null(), path_len: 0 };

    let mut cluster = ptr::null_mut();
    let status = unsafe {
        soyokaze_server_run(server, echo, None, &seen as *const _ as *mut c_void, &port, 1, 2, &mut cluster, ptr::null_mut())
    };
    assert_eq!(status, Status::Ok, "the cluster did not start");
    assert_eq!(unsafe { soyokaze_cluster_workers(cluster) }, 2);

    let bound = unsafe { soyokaze_cluster_port(cluster) };
    assert_ne!(bound, 0);

    let runtime = soyokaze_runtime_new(1);
    let client = unsafe { soyokaze_client_new(ptr::null()) };
    let url = format!("http://127.0.0.1:{bound}/clustered");
    let (url_data, url_len) = text(&url);

    let mut response = ptr::null_mut();
    assert_eq!(unsafe { soyokaze_client_get(runtime, client, url_data, url_len, &mut response, ptr::null_mut()) }, Status::Ok);
    assert_eq!(unsafe { soyokaze_message_status_code(response) }, 200);
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);

    unsafe { soyokaze_message_free(response) };
    unsafe { soyokaze_client_free(client) };
    unsafe { soyokaze_runtime_free(runtime) };
    unsafe { soyokaze_cluster_close(cluster, 5.0) };
    unsafe { soyokaze_server_free(server) };
}

/// Echoes one message back uppercased and closes, from the server side.
extern "C" fn uppercase(_context: *mut c_void, socket: *mut soyokaze::ffi::websocket::WebSocket) {
    use soyokaze::ffi::websocket::{
        soyokaze_websocket_close, soyokaze_websocket_free, soyokaze_websocket_receive_message,
        soyokaze_websocket_send_message,
    };

    let mut opcode = 0u8;
    let mut payload = Buffer::EMPTY;

    if unsafe { soyokaze_websocket_receive_message(socket, &mut opcode, &mut payload, ptr::null_mut()) } == Status::Ok {
        let upper = take(payload).to_ascii_uppercase();
        unsafe { soyokaze_websocket_send_message(socket, opcode, upper.as_ptr(), upper.len(), ptr::null_mut()) };
    }

    let (reason, reason_len) = text("done");
    unsafe { soyokaze_websocket_close(socket, 1000, reason, reason_len) };
    unsafe { soyokaze_websocket_free(socket) };
}

#[test]
fn a_websocket_crosses_from_the_client_to_the_server_callback_and_back() {
    use soyokaze::ffi::api::client::soyokaze_client_websocket;
    use soyokaze::ffi::websocket::{
        soyokaze_websocket_close, soyokaze_websocket_closing, soyokaze_websocket_free,
        soyokaze_websocket_receive_message, soyokaze_websocket_role, soyokaze_websocket_send_message,
    };

    let runtime = soyokaze_runtime_new(0);
    let server = unsafe { soyokaze_server_new(ptr::null()) };
    let port = Port { kind: PortKind::TCP, number: 0, path: ptr::null(), path_len: 0 };

    let mut handle = ptr::null_mut();
    let status = unsafe {
        soyokaze_server_serve(runtime, server, echo, Some(uppercase), ptr::null_mut(), &port, 1, &mut handle, ptr::null_mut())
    };
    assert_eq!(status, Status::Ok);

    let bound = unsafe { soyokaze_server_handle_port(handle) };
    let client = unsafe { soyokaze_client_new(ptr::null()) };
    let url = format!("ws://127.0.0.1:{bound}/chat");
    let (url_data, url_len) = text(&url);

    let mut socket = ptr::null_mut();
    let mut error: *mut ErrorHandle = ptr::null_mut();
    assert_eq!(
        unsafe { soyokaze_client_websocket(runtime, client, url_data, url_len, &mut socket, &mut error) },
        Status::Ok,
        "the handshake failed",
    );

    assert_eq!(unsafe { soyokaze_websocket_role(socket) }, 0, "this end is the client");
    assert!(!unsafe { soyokaze_websocket_closing(socket) });

    let (hello, hello_len) = text("hello");
    assert_eq!(unsafe { soyokaze_websocket_send_message(socket, 0x1, hello, hello_len, ptr::null_mut()) }, Status::Ok);

    let mut opcode = 0u8;
    let mut payload = Buffer::EMPTY;
    assert_eq!(unsafe { soyokaze_websocket_receive_message(socket, &mut opcode, &mut payload, ptr::null_mut()) }, Status::Ok);
    assert_eq!(opcode, 0x1);
    assert_eq!(take(payload), b"HELLO");

    let mut close = Buffer::EMPTY;
    assert_eq!(unsafe { soyokaze_websocket_receive_message(socket, &mut opcode, &mut close, ptr::null_mut()) }, Status::Ok);
    assert_eq!(opcode, 0x8, "the server's close reaches the client");
    unsafe { soyokaze_buffer_free(close) };

    let (reason, reason_len) = text("");
    unsafe { soyokaze_websocket_close(socket, 1000, reason, reason_len) };
    unsafe { soyokaze_websocket_free(socket) };

    unsafe { soyokaze_client_free(client) };
    unsafe { soyokaze_server_handle_close(runtime, handle, 5.0) };
    unsafe { soyokaze_server_free(server) };
    unsafe { soyokaze_runtime_free(runtime) };
}

#[test]
fn a_connection_exposes_the_raw_exchange() {
    use soyokaze::ffi::api::client::{
        soyokaze_client_connect, soyokaze_connection_id, soyokaze_connection_receive, soyokaze_connection_role,
        soyokaze_connection_send,
    };

    let runtime = soyokaze_runtime_new(0);
    let seen = std::sync::atomic::AtomicUsize::new(0);
    let (server, handle, _origin) = serve(runtime, echo, &seen as *const _ as *mut c_void);
    let bound = unsafe { soyokaze_server_handle_port(handle) };

    let config = ClientConfig { secure: false, ..ClientConfig::DEFAULT };
    let client = unsafe { soyokaze_client_new(&config) };

    let (host, host_len) = text("127.0.0.1");
    let port = Port { kind: PortKind::TCP, number: bound, path: ptr::null(), path_len: 0 };
    let mut connection = ptr::null_mut();
    assert_eq!(
        unsafe { soyokaze_client_connect(runtime, client, host, host_len, &port, &mut connection, ptr::null_mut()) },
        Status::Ok,
    );

    assert_eq!(unsafe { soyokaze_connection_role(connection) }, 0, "this end is the client");
    assert!(!take(unsafe { soyokaze_connection_id(connection) }).is_empty());

    let (target, target_len) = text("/raw");
    let request = unsafe { soyokaze_message_request(Method::GET, target, target_len, Version::V1_1) };
    let (name, name_len) = text("host");
    let (value, value_len) = text("127.0.0.1");
    assert!(unsafe { soyokaze_message_append_header(request, name, name_len, value, value_len) });

    assert_eq!(unsafe { soyokaze_connection_send(runtime, connection, request, ptr::null_mut()) }, Status::Ok);

    let mut response = ptr::null_mut();
    assert_eq!(unsafe { soyokaze_connection_receive(runtime, connection, &mut response, ptr::null_mut()) }, Status::Ok);
    assert_eq!(unsafe { soyokaze_message_status_code(response) }, 200);

    let mut body = Buffer::EMPTY;
    assert_eq!(unsafe { soyokaze_message_body(runtime, response, &mut body, ptr::null_mut()) }, Status::Ok);
    assert_eq!(take(body), b"/raw");

    unsafe { soyokaze_message_free(response) };
    unsafe { soyokaze::ffi::api::client::soyokaze_connection_close(runtime, connection) };
    unsafe { soyokaze::ffi::api::client::soyokaze_connection_free(connection) };
    unsafe { soyokaze_client_free(client) };
    unsafe { soyokaze_server_handle_close(runtime, handle, 5.0) };
    unsafe { soyokaze_server_free(server) };
    unsafe { soyokaze_runtime_free(runtime) };
}
