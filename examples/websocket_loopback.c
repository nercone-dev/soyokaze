/*
 * A WebSocket echo server and a client, in one process over loopback TCP —
 * the C half of `examples/websocket_loopback.rs`.
 *
 * Needs no network access and no certificate:
 *
 *   cargo build --lib
 *   cc -std=c11 -Iinclude examples/websocket_loopback.c -Ltarget/debug -lsoyokaze -o websocket-loopback
 *   LD_LIBRARY_PATH=target/debug ./websocket-loopback  # DYLD_LIBRARY_PATH=target/debug on macOS
 */

#include <stdio.h>
#include <string.h>

#include "soyokaze.h"

#define LIT(s) ((const uint8_t *)(s)), (strlen(s))

/* Opcodes and close codes cross as their wire numbers. */
#define WS_TEXT 0x1
#define WS_NORMAL 1000

/* Answers every request that was not a WebSocket upgrade.
 *
 * The request callback is a function rather than an option, so a server that
 * only wants WebSockets still names one. */
static soyokaze_message_t *decline(void *context, soyokaze_message_t *request) {
    soyokaze_version_t version = soyokaze_message_version(request);
    soyokaze_message_free(request);

    return soyokaze_response_with_body(426, version, LIT("this port speaks WebSocket"));
}

/* Sends every message back the way it came, until the socket ends.
 *
 * The callback takes the socket over and runs on its own blocking thread, so
 * it drives the socket to completion and frees it. These calls take no
 * runtime — the socket carries its own. */
static void echo(void *context, soyokaze_websocket_t *socket) {
    for (;;) {
        uint8_t opcode = 0;
        soyokaze_buffer_t payload = {NULL, 0, 0};

        if (soyokaze_websocket_receive_message(socket, &opcode, &payload, NULL) != SOYOKAZE_OK) {
            break;
        }

        soyokaze_status_t sent = soyokaze_websocket_send_message(socket, opcode, payload.data, payload.len, NULL);
        soyokaze_buffer_free(payload);

        if (sent != SOYOKAZE_OK) {
            break;
        }
    }

    soyokaze_websocket_close(socket, WS_NORMAL, NULL, 0);
    soyokaze_websocket_free(socket);
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

    if (soyokaze_server_serve(runtime, server, decline, echo, NULL, &port, 1, &handle, &error) != SOYOKAZE_OK) {
        return fail("serve", error);
    }

    char url[64];
    snprintf(url, sizeof(url), "ws://127.0.0.1:%u/echo", soyokaze_server_handle_port(handle));

    soyokaze_websocket_t *socket = NULL;
    if (soyokaze_client_websocket(runtime, client, LIT(url), &socket, &error) != SOYOKAZE_OK) {
        return fail("websocket", error);
    }

    const char *messages[2] = {"hello", "soyokaze"};

    for (size_t index = 0; index < 2; index++) {
        if (soyokaze_websocket_send_message(socket, WS_TEXT, LIT(messages[index]), &error) != SOYOKAZE_OK) {
            return fail("send", error);
        }

        uint8_t opcode = 0;
        soyokaze_buffer_t payload = {NULL, 0, 0};
        if (soyokaze_websocket_receive_message(socket, &opcode, &payload, &error) != SOYOKAZE_OK) {
            return fail("receive", error);
        }

        printf("0x%x %.*s\n", opcode, (int)payload.len, payload.data);
        soyokaze_buffer_free(payload);
    }

    soyokaze_websocket_close(socket, WS_NORMAL, NULL, 0);
    soyokaze_websocket_free(socket);
    soyokaze_client_free(client);
    soyokaze_server_handle_close(runtime, handle, 5.0);
    soyokaze_server_free(server);
    soyokaze_runtime_free(runtime);
    return 0;
}
