/*
 * A server and a client in one process, talking over loopback TCP — the C
 * half of `examples/loopback.rs`.
 *
 * Needs no network access and no certificate, so it is the fastest way to see
 * a request cross the whole stack from C:
 *
 *   cargo build --lib
 *   cc -std=c11 -Iinclude examples/loopback.c -Ltarget/debug -lsoyokaze -o loopback
 *   LD_LIBRARY_PATH=target/debug ./loopback  # DYLD_LIBRARY_PATH=target/debug on macOS
 */

#include <stdio.h>
#include <string.h>

#include "soyokaze.h"

#define LIT(s) ((const uint8_t *)(s)), (strlen(s))

/* Answers every request with a greeting taken from its target.
 *
 * The callback takes the request over, so it frees it, and what it returns is
 * taken over by the library. The response needs no stream id: the library
 * stamps it with the request's own, which is what the Rust example does by
 * hand. */
static soyokaze_message_t *greet(void *context, soyokaze_message_t *request) {
    soyokaze_slice_t target = soyokaze_message_target(request);
    soyokaze_version_t version = soyokaze_message_version(request);

    const uint8_t *name = target.data;
    size_t name_len = target.len;

    while (name_len > 0 && name[0] == '/') {
        name++;
        name_len--;
    }

    if (name_len == 0) {
        name = (const uint8_t *)"World";
        name_len = 5;
    }

    /* The target is borrowed from the request, so the greeting is built while
     * the request is still alive. */
    char greeting[256];
    int written = snprintf(greeting, sizeof(greeting), "Hello, %.*s!", (int)name_len, (const char *)name);
    size_t greeting_len = written < 0 ? 0 : (size_t)written;
    if (greeting_len >= sizeof(greeting)) {
        greeting_len = sizeof(greeting) - 1;
    }

    soyokaze_message_free(request);

    return soyokaze_response_text((const uint8_t *)greeting, greeting_len, version);
}

static int fail(const char *what, soyokaze_error_t *error) {
    soyokaze_slice_t why = soyokaze_error_message(error);
    fprintf(stderr, "%s failed: %.*s\n", what, (int)why.len, why.data);
    soyokaze_error_free(error);
    return 1;
}

int main(void) {
    soyokaze_runtime_t *runtime = soyokaze_runtime_new(0);
    soyokaze_server_t *server = soyokaze_server_new(NULL);
    soyokaze_client_t *client = soyokaze_client_new(NULL);

    if (runtime == NULL || server == NULL || client == NULL) {
        fprintf(stderr, "the runtime or a configuration was refused\n");
        return 1;
    }

    /* A port of zero lets the kernel choose one, so the example names none. */
    soyokaze_port_t port = {SOYOKAZE_PORT_TCP, 0, NULL, 0};
    soyokaze_server_handle_t *handle = NULL;
    soyokaze_error_t *error = NULL;

    if (soyokaze_server_serve(runtime, server, greet, NULL, NULL, &port, 1, &handle, &error) != SOYOKAZE_OK) {
        return fail("serve", error);
    }

    char origin[64];
    snprintf(origin, sizeof(origin), "http://127.0.0.1:%u/", soyokaze_server_handle_port(handle));

    soyokaze_url_t *url = NULL;
    if (soyokaze_url_parse(LIT(origin), &url, &error) != SOYOKAZE_OK) {
        return fail("parse", error);
    }

    soyokaze_connection_t *connection = NULL;
    if (soyokaze_client_open(runtime, client, url, &connection, &error) != SOYOKAZE_OK) {
        return fail("open", error);
    }

    const char *targets[2] = {"/", "/soyokaze"};

    for (size_t index = 0; index < 2; index++) {
        soyokaze_message_t *request = soyokaze_message_request(SOYOKAZE_GET, LIT(targets[index]), soyokaze_connection_version(connection));

        soyokaze_message_t *response = NULL;
        if (soyokaze_client_request(runtime, client, connection, request, &response, &error) != SOYOKAZE_OK) {
            return fail("request", error);
        }

        soyokaze_buffer_t body = {NULL, 0, 0};
        if (soyokaze_message_body(runtime, response, &body, &error) != SOYOKAZE_OK) {
            return fail("body", error);
        }

        printf("%s -> %d %.*s\n", targets[index], soyokaze_message_status_code(response), (int)body.len, body.data);

        soyokaze_buffer_free(body);
        soyokaze_message_free(response);
    }

    soyokaze_connection_close(runtime, connection);
    soyokaze_connection_free(connection);
    soyokaze_url_free(url);
    soyokaze_client_free(client);
    soyokaze_server_handle_close(runtime, handle, 5.0);
    soyokaze_server_free(server);
    soyokaze_runtime_free(runtime);
    return 0;
}
