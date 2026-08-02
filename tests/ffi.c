/*
 * The C half of the FFI tests.
 *
 * `tests/ffi.rs` drives the same surface from Rust, which is what `cargo test`
 * runs. This one links against the shared library through `include/soyokaze.h`
 * the way a C caller does, so it is what proves the header and the library
 * agree — a declaration that has drifted from the Rust side shows up here and
 * nowhere else.
 *
 *   cc -I include tests/ffi.c -L target/release -lsoyokaze -o ffi-test
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "soyokaze.h"

#define LIT(s) ((const uint8_t *)(s)), (strlen(s))

static const char *BODY = "hello from the callback";

static soyokaze_message_t *on_request(void *context, soyokaze_message_t *request) {
    int *seen = (int *)context;

    assert(soyokaze_message_is_request(request));
    assert(soyokaze_message_target(request).data != NULL);

    /* The field the client sent has to survive the crossing. */
    soyokaze_slice_t probe = soyokaze_message_header(request, LIT("x-probe"));
    if (probe.data != NULL && probe.len == 5 && memcmp(probe.data, "value", 5) == 0) {
        *seen = 1;
    }

    soyokaze_version_t version = soyokaze_message_version(request);
    soyokaze_message_free(request);

    soyokaze_message_t *response = soyokaze_response_with_body(200, version, LIT(BODY));
    soyokaze_message_append_header(response, LIT("content-type"), LIT("text/plain"));
    return response;
}

static void check_url(void) {
    soyokaze_url_t *url = NULL;
    assert(soyokaze_url_parse(LIT("https://example.test:8443/a/b?q=1"), &url, NULL) == SOYOKAZE_OK);

    assert(soyokaze_url_port(url) == 8443);
    assert(soyokaze_url_secure(url));

    soyokaze_slice_t host = soyokaze_url_host(url);
    assert(host.len == 12 && memcmp(host.data, "example.test", 12) == 0);

    soyokaze_buffer_t authority = soyokaze_url_authority(url);
    assert(authority.len == 17 && memcmp(authority.data, "example.test:8443", 17) == 0);
    soyokaze_buffer_free(authority);
    soyokaze_url_free(url);

    /* A URL that will not parse reports rather than handing back a handle. */
    soyokaze_url_t *bad = NULL;
    soyokaze_error_t *error = NULL;
    assert(soyokaze_url_parse(LIT("not a url"), &bad, &error) != SOYOKAZE_OK);
    assert(bad == NULL);
    assert(error != NULL);
    assert(soyokaze_error_message(error).data != NULL);
    soyokaze_error_free(error);
}

static void check_null_handles(void) {
    assert(soyokaze_error_status(NULL) == SOYOKAZE_INVALID);
    assert(soyokaze_error_message(NULL).data == NULL);
    assert(soyokaze_url_host(NULL).data == NULL);
    assert(soyokaze_url_port(NULL) == 0);
    assert(soyokaze_message_method(NULL) == -1);
    assert(soyokaze_message_status_code(NULL) == -1);
    assert(soyokaze_message_body_len(NULL) == -1);
    assert(soyokaze_message_header_count(NULL) == 0);
    assert(soyokaze_server_handle_port(NULL) == 0);

    soyokaze_error_free(NULL);
    soyokaze_url_free(NULL);
    soyokaze_message_free(NULL);
    soyokaze_client_free(NULL);
    soyokaze_server_free(NULL);
    soyokaze_runtime_free(NULL);
}

int main(void) {
    soyokaze_slice_t crate = soyokaze_version();
    printf("soyokaze %.*s\n", (int)crate.len, crate.data);
    assert(crate.len > 0);

    check_url();
    check_null_handles();

    soyokaze_runtime_t *runtime = soyokaze_runtime_new(0);
    assert(runtime != NULL);

    /* Serve on a port the kernel picks, so the test names none. */
    int seen_header = 0;
    soyokaze_server_t *server = soyokaze_server_new(NULL);
    assert(server != NULL);

    soyokaze_port_t port = {SOYOKAZE_PORT_TCP, 0, NULL, 0};
    soyokaze_server_handle_t *handle = NULL;
    soyokaze_error_t *error = NULL;

    if (soyokaze_server_serve(runtime, server, on_request, &seen_header, &port, 1, &handle, &error) != SOYOKAZE_OK) {
        soyokaze_slice_t why = soyokaze_error_message(error);
        fprintf(stderr, "serve failed: %.*s\n", (int)why.len, why.data);
        return 1;
    }

    uint16_t bound = soyokaze_server_handle_port(handle);
    assert(bound != 0);

    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/hello", bound);

    soyokaze_client_t *client = soyokaze_client_new(NULL);
    assert(client != NULL);

    soyokaze_message_t *request = soyokaze_message_request(SOYOKAZE_GET, LIT("/hello"), SOYOKAZE_HTTP_1_1);
    assert(request != NULL);
    assert(soyokaze_message_append_header(request, LIT("x-probe"), LIT("value")));

    soyokaze_message_t *response = NULL;
    if (soyokaze_client_fetch(runtime, client, SOYOKAZE_GET, LIT(url), request, &response, &error) != SOYOKAZE_OK) {
        soyokaze_slice_t why = soyokaze_error_message(error);
        fprintf(stderr, "fetch failed: %.*s\n", (int)why.len, why.data);
        return 1;
    }

    assert(soyokaze_message_is_response(response));
    assert(soyokaze_message_status_code(response) == 200);
    assert(soyokaze_message_method(response) == -1);
    assert(seen_header == 1);

    soyokaze_slice_t kind = soyokaze_message_header(response, LIT("content-type"));
    assert(kind.data != NULL && kind.len == 10 && memcmp(kind.data, "text/plain", 10) == 0);

    /* An absent field is told apart from one that is there and empty. */
    assert(soyokaze_message_header(response, LIT("x-nothing")).data == NULL);
    assert(soyokaze_message_header_name(response, soyokaze_message_header_count(response)).data == NULL);

    soyokaze_buffer_t body = {NULL, 0, 0};
    assert(soyokaze_message_body(runtime, response, &body, &error) == SOYOKAZE_OK);
    assert(body.len == strlen(BODY) && memcmp(body.data, BODY, body.len) == 0);
    soyokaze_buffer_free(body);

    soyokaze_message_free(response);
    soyokaze_client_free(client);
    soyokaze_server_handle_close(runtime, handle, 5.0);
    soyokaze_server_free(server);
    soyokaze_runtime_free(runtime);

    printf("ok\n");
    return 0;
}
