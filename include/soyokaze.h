/*
 * soyokaze — an HTTP/1, HTTP/2 and HTTP/3 library.
 *
 * The C declarations for the shared library the crate builds as. See the
 * `soyokaze::ffi` module for what each call does.
 *
 * Conventions:
 *
 *  - A fallible call returns a soyokaze_status_t and writes its result through
 *    an out parameter. Passing a non-NULL `error` takes ownership of a
 *    soyokaze_error_t describing the failure, freed with soyokaze_error_free.
 *  - Text and octets go in as a pointer and a length, never NUL-terminated.
 *  - Text and octets come back either as a soyokaze_slice_t, borrowed from a
 *    handle and valid until that handle is freed or modified, or as a
 *    soyokaze_buffer_t, owned by the caller and freed with
 *    soyokaze_buffer_free.
 *  - A handle is freed exactly once, with the `_free` call matching the one
 *    that produced it. A call documented as consuming a handle frees it itself.
 *  - A NULL handle is treated as absent and is never dereferenced.
 */

#ifndef SOYOKAZE_H
#define SOYOKAZE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ common */

typedef struct {
    const uint8_t *data; /* NULL when the value was absent */
    size_t len;
} soyokaze_slice_t;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
} soyokaze_buffer_t;

typedef enum {
    SOYOKAZE_OK = 0,
    SOYOKAZE_CLOSED = 1,
    SOYOKAZE_PROTOCOL = 2,
    SOYOKAZE_LIMIT = 3,
    SOYOKAZE_STREAM = 4,
    SOYOKAZE_TIMEOUT = 5,
    SOYOKAZE_TLS = 6,
    SOYOKAZE_VERSION = 7,
    SOYOKAZE_IO = 8,
    SOYOKAZE_INVALID = 9,
    SOYOKAZE_RUNTIME = 10
} soyokaze_status_t;

typedef enum {
    SOYOKAZE_HTTP_1_0 = 0,
    SOYOKAZE_HTTP_1_1 = 1,
    SOYOKAZE_HTTP_2 = 2,
    SOYOKAZE_HTTP_3 = 3
} soyokaze_version_t;

typedef enum {
    SOYOKAZE_GET = 0,
    SOYOKAZE_HEAD = 1,
    SOYOKAZE_POST = 2,
    SOYOKAZE_PUT = 3,
    SOYOKAZE_DELETE = 4,
    SOYOKAZE_CONNECT = 5,
    SOYOKAZE_OPTIONS = 6,
    SOYOKAZE_TRACE = 7,
    SOYOKAZE_PATCH = 8
} soyokaze_method_t;

typedef enum {
    SOYOKAZE_PORT_UDS = 0,
    SOYOKAZE_PORT_TCP = 1,
    SOYOKAZE_PORT_QUIC = 2
} soyokaze_port_kind_t;

typedef struct {
    soyokaze_port_kind_t kind;
    uint16_t number;      /* read for TCP and QUIC */
    const uint8_t *path;  /* read for UDS */
    size_t path_len;
} soyokaze_port_t;

typedef struct soyokaze_runtime soyokaze_runtime_t;
typedef struct soyokaze_error soyokaze_error_t;
typedef struct soyokaze_url soyokaze_url_t;
typedef struct soyokaze_message soyokaze_message_t;
typedef struct soyokaze_client soyokaze_client_t;
typedef struct soyokaze_connection soyokaze_connection_t;
typedef struct soyokaze_server soyokaze_server_t;
typedef struct soyokaze_server_handle soyokaze_server_handle_t;

void soyokaze_buffer_free(soyokaze_buffer_t buffer);
soyokaze_slice_t soyokaze_version(void);

/* `workers` of 0 uses one thread per core. Returns NULL on failure. */
soyokaze_runtime_t *soyokaze_runtime_new(uint32_t workers);
void soyokaze_runtime_free(soyokaze_runtime_t *runtime);

/* ------------------------------------------------------------------ errors */

void soyokaze_error_free(soyokaze_error_t *error);
soyokaze_status_t soyokaze_error_status(const soyokaze_error_t *error);
soyokaze_slice_t soyokaze_error_message(const soyokaze_error_t *error);
soyokaze_slice_t soyokaze_status_message(soyokaze_status_t status);

/* --------------------------------------------------------------------- url */

soyokaze_status_t soyokaze_url_parse(const uint8_t *url, size_t url_len,
                                     soyokaze_url_t **out,
                                     soyokaze_error_t **error);
void soyokaze_url_free(soyokaze_url_t *url);
soyokaze_slice_t soyokaze_url_scheme(const soyokaze_url_t *url);
soyokaze_slice_t soyokaze_url_host(const soyokaze_url_t *url);
soyokaze_slice_t soyokaze_url_target(const soyokaze_url_t *url);
uint16_t soyokaze_url_port(const soyokaze_url_t *url);
bool soyokaze_url_secure(const soyokaze_url_t *url);
soyokaze_buffer_t soyokaze_url_authority(const soyokaze_url_t *url);

/* ----------------------------------------------------------------- message */

soyokaze_message_t *soyokaze_message_request(soyokaze_method_t method,
                                             const uint8_t *target,
                                             size_t target_len,
                                             soyokaze_version_t version);
soyokaze_message_t *soyokaze_message_response(uint16_t status_code,
                                              soyokaze_version_t version);
void soyokaze_message_free(soyokaze_message_t *message);

soyokaze_version_t soyokaze_message_version(const soyokaze_message_t *message);
int32_t soyokaze_message_method(const soyokaze_message_t *message);      /* -1 on a response */
int32_t soyokaze_message_status_code(const soyokaze_message_t *message); /* -1 on a request */
soyokaze_slice_t soyokaze_message_target(const soyokaze_message_t *message);
bool soyokaze_message_is_request(const soyokaze_message_t *message);
bool soyokaze_message_is_response(const soyokaze_message_t *message);
bool soyokaze_message_is_informational(const soyokaze_message_t *message);
bool soyokaze_message_secure(const soyokaze_message_t *message);

size_t soyokaze_message_header_count(const soyokaze_message_t *message);
soyokaze_slice_t soyokaze_message_header_name(const soyokaze_message_t *message, size_t index);
soyokaze_slice_t soyokaze_message_header_value(const soyokaze_message_t *message, size_t index);
soyokaze_slice_t soyokaze_message_header(const soyokaze_message_t *message,
                                         const uint8_t *name, size_t name_len);
bool soyokaze_message_append_header(soyokaze_message_t *message,
                                    const uint8_t *name, size_t name_len,
                                    const uint8_t *value, size_t value_len);
bool soyokaze_message_insert_header(soyokaze_message_t *message,
                                    const uint8_t *name, size_t name_len,
                                    const uint8_t *value, size_t value_len);
bool soyokaze_message_remove_header(soyokaze_message_t *message,
                                    const uint8_t *name, size_t name_len);

bool soyokaze_message_set_body_data(soyokaze_message_t *message, const uint8_t *data, size_t data_len);
bool soyokaze_message_set_body_text(soyokaze_message_t *message, const uint8_t *text, size_t text_len);
bool soyokaze_message_set_body_file(soyokaze_message_t *message, const uint8_t *path, size_t path_len);
int64_t soyokaze_message_body_len(const soyokaze_message_t *message); /* -1 when unknown */
soyokaze_status_t soyokaze_message_body(soyokaze_runtime_t *runtime,
                                        const soyokaze_message_t *message,
                                        soyokaze_buffer_t *out,
                                        soyokaze_error_t **error);

/* ------------------------------------------------------------------ client */

typedef struct {
    int32_t version; /* a soyokaze_version_t, or -1 to negotiate */
    bool secure;
    bool cookies;
    bool hsts;
} soyokaze_client_config_t;

soyokaze_client_t *soyokaze_client_new(const soyokaze_client_config_t *config);
void soyokaze_client_free(soyokaze_client_t *client);

/* `request`, when given, is consumed: its headers and body are used and the
 * handle is freed by the call. */
soyokaze_status_t soyokaze_client_fetch(soyokaze_runtime_t *runtime,
                                        const soyokaze_client_t *client,
                                        soyokaze_method_t method,
                                        const uint8_t *url, size_t url_len,
                                        soyokaze_message_t *request,
                                        soyokaze_message_t **out,
                                        soyokaze_error_t **error);
soyokaze_status_t soyokaze_client_get(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                      const uint8_t *url, size_t url_len,
                                      soyokaze_message_t **out, soyokaze_error_t **error);
soyokaze_status_t soyokaze_client_head(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                       const uint8_t *url, size_t url_len,
                                       soyokaze_message_t **out, soyokaze_error_t **error);
soyokaze_status_t soyokaze_client_post(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                       const uint8_t *url, size_t url_len,
                                       soyokaze_message_t *request,
                                       soyokaze_message_t **out, soyokaze_error_t **error);
soyokaze_status_t soyokaze_client_put(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                      const uint8_t *url, size_t url_len,
                                      soyokaze_message_t *request,
                                      soyokaze_message_t **out, soyokaze_error_t **error);
soyokaze_status_t soyokaze_client_delete(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                         const uint8_t *url, size_t url_len,
                                         soyokaze_message_t **out, soyokaze_error_t **error);

soyokaze_status_t soyokaze_client_open(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                       const soyokaze_url_t *url,
                                       soyokaze_connection_t **out, soyokaze_error_t **error);
soyokaze_status_t soyokaze_client_connect(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                          const uint8_t *host, size_t host_len,
                                          const soyokaze_port_t *port,
                                          soyokaze_connection_t **out, soyokaze_error_t **error);
/* `request` is consumed. */
soyokaze_status_t soyokaze_client_request(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                          soyokaze_connection_t *connection,
                                          soyokaze_message_t *request,
                                          soyokaze_message_t **out, soyokaze_error_t **error);

soyokaze_version_t soyokaze_connection_version(const soyokaze_connection_t *connection);
bool soyokaze_connection_reusable(const soyokaze_connection_t *connection);
void soyokaze_connection_close(soyokaze_runtime_t *runtime, soyokaze_connection_t *connection);
void soyokaze_connection_free(soyokaze_connection_t *connection);

/* ------------------------------------------------------------------ server */

/* Takes ownership of `request` — free it, or return it as the response. The
 * response returned is taken over by the library. NULL answers with a bare
 * 500. Runs on a runtime thread and may block. */
typedef soyokaze_message_t *(*soyokaze_on_request_t)(void *context, soyokaze_message_t *request);

typedef struct {
    const uint8_t *certificate; /* DER or PEM; NULL serves TCP in plaintext */
    size_t certificate_len;
    const uint8_t *key;
    size_t key_len;
    uint32_t max_connections;        /* 0 is unbounded */
    uint32_t max_connections_per_ip; /* 0 is unbounded */
    bool reuseport;
} soyokaze_server_config_t;

soyokaze_server_t *soyokaze_server_new(const soyokaze_server_config_t *config);
void soyokaze_server_free(soyokaze_server_t *server);

/* Returns once the ports are bound; the accept loops keep running on
 * `runtime`, which must outlive the handle. `context` is reached from more
 * than one thread. */
soyokaze_status_t soyokaze_server_serve(soyokaze_runtime_t *runtime,
                                        const soyokaze_server_t *server,
                                        soyokaze_on_request_t on_request,
                                        void *context,
                                        const soyokaze_port_t *ports, size_t port_count,
                                        soyokaze_server_handle_t **out,
                                        soyokaze_error_t **error);
uint16_t soyokaze_server_handle_port(const soyokaze_server_handle_t *handle);
/* Consumes `handle`. A negative `timeout` waits as long as it takes. */
void soyokaze_server_handle_close(soyokaze_runtime_t *runtime,
                                  soyokaze_server_handle_t *handle,
                                  double timeout);

soyokaze_message_t *soyokaze_response_with_body(uint16_t status_code,
                                                soyokaze_version_t version,
                                                const uint8_t *body, size_t body_len);

#ifdef __cplusplus
}
#endif

#endif /* SOYOKAZE_H */
