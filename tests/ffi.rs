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

use soyokaze::ffi::client::{
    soyokaze_client_fetch, soyokaze_client_free, soyokaze_client_get, soyokaze_client_new, ClientConfig,
};
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
use soyokaze::ffi::server::{
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

    let config = ClientConfig { version: Version::V2_0 as i32, secure: false, cookies: false, hsts: false };
    let client = unsafe { soyokaze_client_new(&config) };
    assert!(!client.is_null());
    unsafe { soyokaze_client_free(client) };

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
fn serve(
    runtime: *mut Runtime,
    handler: soyokaze::ffi::server::OnRequest,
    context: *mut c_void,
) -> (*mut soyokaze::api::server::Server, *mut soyokaze::api::server::ServerHandle, String) {
    let server = unsafe { soyokaze_server_new(ptr::null()) };
    assert!(!server.is_null());

    let port = Port { kind: PortKind::TCP, number: 0, path: ptr::null(), path_len: 0 };
    let mut handle = ptr::null_mut();
    let mut error: *mut ErrorHandle = ptr::null_mut();

    let status = unsafe { soyokaze_server_serve(runtime, server, handler, context, &port, 1, &mut handle, &mut error) };
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

    let status = unsafe { soyokaze_server_serve(runtime, server, echo, ptr::null_mut(), &port, 1, &mut handle, ptr::null_mut()) };

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
