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

/* What one end of a connection is doing on it. A user agent and a proxy send
 * requests; an origin and a gateway answer them; a tunnel relays octets
 * without reading the messages inside. */
typedef enum {
    SOYOKAZE_ROLE_USER_AGENT = 0,
    SOYOKAZE_ROLE_ORIGIN = 1,
    SOYOKAZE_ROLE_PROXY = 2,
    SOYOKAZE_ROLE_GATEWAY = 3,
    SOYOKAZE_ROLE_TUNNEL = 4
} soyokaze_role_t;

/* What one connection is allowed to spend on the peer's behalf. Every field
 * is a ceiling; timeouts are in seconds and zero waits forever. Start from
 * soyokaze_limits_default() and adjust. */
typedef struct {
    uint64_t max_message_size;
    uint64_t max_message_body_size;

    uint32_t max_startline_size;
    uint64_t max_headers_size;
    uint16_t max_header_count;
    uint32_t max_chunk_header_size;

    uint64_t read_chunk_size; /* room each read is given, not a cap */
    uint64_t idle_capacity;

    uint32_t max_pending_handshakes;

    double read_timeout;
    double write_timeout;
    double receive_timeout;
    double send_timeout;

    uint64_t inline_body_size;

    uint32_t max_concurrent_streams;
    uint64_t max_connection_buffer_size;
    uint32_t max_premature_resets;
    uint64_t max_encoder_table_size;

    uint32_t max_idle_frames;
    uint64_t output_high_water;

    uint64_t max_requests_per_connection; /* served per connection lifetime; zero serves forever */
    double qpack_block_timeout;
    uint32_t max_peer_uni_streams;
    uint32_t max_outstanding_sections;
    uint32_t max_blocked_streams;
    uint32_t tunnel_backlog;
    uint32_t command_backlog;

    double ws_linger_timeout;
    uint16_t ws_max_fragments;

    uint32_t max_cookies;
    uint16_t max_cookies_per_domain;
    uint32_t max_hsts_entries;
} soyokaze_limits_t;

soyokaze_limits_t soyokaze_limits_default(void);

typedef struct soyokaze_runtime soyokaze_runtime_t;
typedef struct soyokaze_error soyokaze_error_t;
typedef struct soyokaze_url soyokaze_url_t;
typedef struct soyokaze_message soyokaze_message_t;
typedef struct soyokaze_cookie soyokaze_cookie_t;
typedef struct soyokaze_setcookie soyokaze_setcookie_t;
typedef struct soyokaze_cookiejar soyokaze_cookiejar_t;
typedef struct soyokaze_identity soyokaze_identity_t;
typedef struct soyokaze_ech_keys soyokaze_ech_keys_t;
typedef struct soyokaze_ech_config_list soyokaze_ech_config_list_t;
typedef struct soyokaze_client soyokaze_client_t;
typedef struct soyokaze_connection soyokaze_connection_t;
typedef struct soyokaze_websocket soyokaze_websocket_t;
typedef struct soyokaze_server soyokaze_server_t;
typedef struct soyokaze_server_handle soyokaze_server_handle_t;
typedef struct soyokaze_cluster soyokaze_cluster_t;
typedef struct soyokaze_fields soyokaze_fields_t;
typedef struct soyokaze_hpack_encoder soyokaze_hpack_encoder_t;
typedef struct soyokaze_hpack_decoder soyokaze_hpack_decoder_t;
typedef struct soyokaze_qpack_encoder soyokaze_qpack_encoder_t;
typedef struct soyokaze_qpack_decoder soyokaze_qpack_decoder_t;
typedef struct soyokaze_hsts_store soyokaze_hsts_store_t;

void soyokaze_buffer_free(soyokaze_buffer_t buffer);
soyokaze_slice_t soyokaze_version(void);

/* `workers` of 0 uses one thread per core. Returns NULL on failure. */
soyokaze_runtime_t *soyokaze_runtime_new(uint32_t workers);
void soyokaze_runtime_free(soyokaze_runtime_t *runtime);

/* ------------------------------------------------------------------ errors */

void soyokaze_error_free(soyokaze_error_t *error);
soyokaze_status_t soyokaze_error_status(const soyokaze_error_t *error);
soyokaze_slice_t soyokaze_error_message(const soyokaze_error_t *error);

/* Set on a SOYOKAZE_STREAM failure, which names the one stream that failed
 * while the connection itself stays usable; -1 on every other failure. */
int64_t soyokaze_error_stream_id(const soyokaze_error_t *error);
int64_t soyokaze_error_code(const soyokaze_error_t *error);

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

soyokaze_message_t *soyokaze_message_new(soyokaze_version_t version);
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
bool soyokaze_message_set_secure(soyokaze_message_t *message, bool secure);

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

size_t soyokaze_message_trailer_count(const soyokaze_message_t *message);
soyokaze_slice_t soyokaze_message_trailer_name(const soyokaze_message_t *message, size_t index);
soyokaze_slice_t soyokaze_message_trailer_value(const soyokaze_message_t *message, size_t index);
soyokaze_slice_t soyokaze_message_trailer(const soyokaze_message_t *message,
                                          const uint8_t *name, size_t name_len);
bool soyokaze_message_append_trailer(soyokaze_message_t *message,
                                     const uint8_t *name, size_t name_len,
                                     const uint8_t *value, size_t value_len);
bool soyokaze_message_insert_trailer(soyokaze_message_t *message,
                                     const uint8_t *name, size_t name_len,
                                     const uint8_t *value, size_t value_len);
bool soyokaze_message_remove_trailer(soyokaze_message_t *message,
                                     const uint8_t *name, size_t name_len);

int64_t soyokaze_message_stream_id(const soyokaze_message_t *message); /* -1 when none */
bool soyokaze_message_set_stream_id(soyokaze_message_t *message, int64_t stream_id);
soyokaze_slice_t soyokaze_message_connection_id(const soyokaze_message_t *message);

/* What the transport underneath turned out to be. Stamped on every message a
 * connection receives, so these read as absent on one the caller built. A
 * QUIC connection reports TLS 1.3, which is what it carries, but not the
 * cipher suite or group: the QUIC stack does not hand its session out. */
bool soyokaze_message_early_data(const soyokaze_message_t *message);
bool soyokaze_message_tls(const soyokaze_message_t *message);
int32_t soyokaze_message_tls_version(const soyokaze_message_t *message); /* wire code, -1 when none */
int32_t soyokaze_message_tls_group(const soyokaze_message_t *message);   /* wire code, -1 when none */
int32_t soyokaze_message_tls_cipher(const soyokaze_message_t *message);  /* wire code, -1 when none */
bool soyokaze_message_quic(const soyokaze_message_t *message);
int64_t soyokaze_message_quic_version(const soyokaze_message_t *message); /* -1 when none */

bool soyokaze_message_set_body_data(soyokaze_message_t *message, const uint8_t *data, size_t data_len);
bool soyokaze_message_set_body_text(soyokaze_message_t *message, const uint8_t *text, size_t text_len);
bool soyokaze_message_set_body_file(soyokaze_message_t *message, const uint8_t *path, size_t path_len);
int64_t soyokaze_message_body_len(const soyokaze_message_t *message); /* -1 when unknown */
soyokaze_status_t soyokaze_message_body(soyokaze_runtime_t *runtime,
                                        const soyokaze_message_t *message,
                                        soyokaze_buffer_t *out,
                                        soyokaze_error_t **error);

/* --------------------------------------------------------------- responses */

soyokaze_message_t *soyokaze_response_content(const uint8_t *content_type, size_t content_type_len,
                                              const uint8_t *body, size_t body_len,
                                              soyokaze_version_t version);
soyokaze_message_t *soyokaze_response_text(const uint8_t *content, size_t content_len, soyokaze_version_t version);
soyokaze_message_t *soyokaze_response_html(const uint8_t *content, size_t content_len, soyokaze_version_t version);
soyokaze_message_t *soyokaze_response_markdown(const uint8_t *content, size_t content_len, soyokaze_version_t version);
soyokaze_message_t *soyokaze_response_json(const uint8_t *content, size_t content_len, soyokaze_version_t version);
soyokaze_message_t *soyokaze_response_file(const uint8_t *path, size_t path_len, soyokaze_version_t version);
soyokaze_message_t *soyokaze_response_redirect(const uint8_t *target, size_t target_len, soyokaze_version_t version);
soyokaze_status_t soyokaze_message_set_cookie(soyokaze_message_t *message,
                                              const soyokaze_setcookie_t *cookie,
                                              soyokaze_error_t **error);
soyokaze_status_t soyokaze_message_delete_cookie(soyokaze_message_t *message,
                                                 const soyokaze_setcookie_t *cookie,
                                                 soyokaze_error_t **error);

/* ----------------------------------------------------------------- cookies */

soyokaze_cookie_t *soyokaze_cookie_new(void);
soyokaze_cookie_t *soyokaze_cookie_parse(const uint8_t *value, size_t value_len);
void soyokaze_cookie_free(soyokaze_cookie_t *cookie);
size_t soyokaze_cookie_count(const soyokaze_cookie_t *cookie);
soyokaze_slice_t soyokaze_cookie_name(const soyokaze_cookie_t *cookie, size_t index);
soyokaze_slice_t soyokaze_cookie_value(const soyokaze_cookie_t *cookie, size_t index);
soyokaze_slice_t soyokaze_cookie_get(const soyokaze_cookie_t *cookie,
                                     const uint8_t *name, size_t name_len);
bool soyokaze_cookie_append(soyokaze_cookie_t *cookie,
                            const uint8_t *name, size_t name_len,
                            const uint8_t *value, size_t value_len);
soyokaze_buffer_t soyokaze_cookie_build(const soyokaze_cookie_t *cookie);

soyokaze_setcookie_t *soyokaze_setcookie_new(const uint8_t *name, size_t name_len,
                                             const uint8_t *value, size_t value_len);
soyokaze_status_t soyokaze_setcookie_parse(const uint8_t *value, size_t value_len,
                                           soyokaze_setcookie_t **out,
                                           soyokaze_error_t **error);
void soyokaze_setcookie_free(soyokaze_setcookie_t *cookie);
soyokaze_slice_t soyokaze_setcookie_name(const soyokaze_setcookie_t *cookie);
soyokaze_slice_t soyokaze_setcookie_value(const soyokaze_setcookie_t *cookie);
soyokaze_slice_t soyokaze_setcookie_expires(const soyokaze_setcookie_t *cookie);
bool soyokaze_setcookie_max_age(const soyokaze_setcookie_t *cookie, int64_t *out);
soyokaze_slice_t soyokaze_setcookie_domain(const soyokaze_setcookie_t *cookie);
soyokaze_slice_t soyokaze_setcookie_path(const soyokaze_setcookie_t *cookie);
bool soyokaze_setcookie_secure(const soyokaze_setcookie_t *cookie);
bool soyokaze_setcookie_httponly(const soyokaze_setcookie_t *cookie);
int32_t soyokaze_setcookie_samesite(const soyokaze_setcookie_t *cookie); /* 0 Strict, 1 Lax, 2 None, -1 unset */
bool soyokaze_setcookie_set_value(soyokaze_setcookie_t *cookie, const uint8_t *value, size_t value_len);
bool soyokaze_setcookie_set_expires(soyokaze_setcookie_t *cookie, const uint8_t *value, size_t value_len);
bool soyokaze_setcookie_set_max_age(soyokaze_setcookie_t *cookie, bool present, int64_t max_age);
bool soyokaze_setcookie_set_domain(soyokaze_setcookie_t *cookie, const uint8_t *value, size_t value_len);
bool soyokaze_setcookie_set_path(soyokaze_setcookie_t *cookie, const uint8_t *value, size_t value_len);
bool soyokaze_setcookie_set_secure(soyokaze_setcookie_t *cookie, bool secure);
bool soyokaze_setcookie_set_httponly(soyokaze_setcookie_t *cookie, bool httponly);
bool soyokaze_setcookie_set_samesite(soyokaze_setcookie_t *cookie, int32_t samesite);
soyokaze_status_t soyokaze_setcookie_build(const soyokaze_setcookie_t *cookie,
                                           soyokaze_buffer_t *out,
                                           soyokaze_error_t **error);

soyokaze_cookiejar_t *soyokaze_cookiejar_new(const soyokaze_limits_t *limits);
void soyokaze_cookiejar_free(soyokaze_cookiejar_t *jar);
bool soyokaze_cookiejar_learn(const soyokaze_cookiejar_t *jar, const soyokaze_url_t *url,
                              const soyokaze_slice_t *values, size_t value_count);
soyokaze_buffer_t soyokaze_cookiejar_cookie(const soyokaze_cookiejar_t *jar, const soyokaze_url_t *url);
void soyokaze_cookiejar_prune(const soyokaze_cookiejar_t *jar);

/* -------------------------------------------------------------------- hsts */

typedef struct {
    int64_t max_age; /* seconds; zero withdraws the policy */
    bool include_subdomains;
    bool preload;
} soyokaze_hsts_policy_t;

bool soyokaze_hsts_policy_parse(const uint8_t *value, size_t value_len, soyokaze_hsts_policy_t *out);
soyokaze_buffer_t soyokaze_hsts_policy_build(const soyokaze_hsts_policy_t *policy);

soyokaze_hsts_store_t *soyokaze_hsts_store_new(const soyokaze_limits_t *limits);
void soyokaze_hsts_store_free(soyokaze_hsts_store_t *store);
bool soyokaze_hsts_store_learn(const soyokaze_hsts_store_t *store,
                               const uint8_t *host, size_t host_len,
                               const uint8_t *header, size_t header_len,
                               bool secure);
bool soyokaze_hsts_store_secure(const soyokaze_hsts_store_t *store,
                                const uint8_t *host, size_t host_len);

/* --------------------------------------------------------------------- tls */

/* The TLS details a context is built with, beyond its identity and roots.
 * Start from soyokaze_tls_config_default() and adjust. Each string is an
 * OpenSSL list, entries separated by ':' and most preferred first; an absent
 * slice keeps that field's default. BoringSSL keeps its built-in order for
 * the TLS 1.3 suites, so `ciphers` restricts and orders TLS 1.2. */
typedef struct {
    soyokaze_slice_t ciphers;              /* TLS 1.2 and 1.3 in one list */
    soyokaze_slice_t groups;               /* key exchange groups */
    soyokaze_slice_t signature_algorithms; /* ecdsa_secp384r1_sha384 names */
    bool prefer_server_ciphers;
    bool session_tickets;
    bool early_data;
    bool certificate_compression;          /* RFC 8879 zlib */
} soyokaze_tls_config_t;

soyokaze_tls_config_t soyokaze_tls_config_default(void);

soyokaze_identity_t *soyokaze_identity_new(const soyokaze_slice_t *certificates, size_t certificate_count,
                                           const uint8_t *key, size_t key_len);
soyokaze_status_t soyokaze_identity_from_pkcs12(const uint8_t *data, size_t data_len,
                                                const uint8_t *passphrase, size_t passphrase_len,
                                                soyokaze_identity_t **out,
                                                soyokaze_error_t **error);
void soyokaze_identity_free(soyokaze_identity_t *identity);

soyokaze_status_t soyokaze_ech_keys_generate(const uint8_t *public_name, size_t public_name_len,
                                             uint8_t config_id,
                                             soyokaze_ech_keys_t **out,
                                             soyokaze_error_t **error);
soyokaze_ech_keys_t *soyokaze_ech_keys_new(const uint8_t *config, size_t config_len,
                                           const uint8_t *private_key, size_t private_key_len);
void soyokaze_ech_keys_free(soyokaze_ech_keys_t *keys);
soyokaze_slice_t soyokaze_ech_keys_config(const soyokaze_ech_keys_t *keys);
soyokaze_slice_t soyokaze_ech_keys_private_key(const soyokaze_ech_keys_t *keys);
soyokaze_buffer_t soyokaze_ech_keys_config_list(const soyokaze_ech_keys_t *keys);

soyokaze_status_t soyokaze_ech_config_list_parse(const uint8_t *data, size_t data_len,
                                                 soyokaze_ech_config_list_t **out,
                                                 soyokaze_error_t **error);
void soyokaze_ech_config_list_free(soyokaze_ech_config_list_t *list);
size_t soyokaze_ech_config_list_count(const soyokaze_ech_config_list_t *list);
uint16_t soyokaze_ech_config_version(const soyokaze_ech_config_list_t *list, size_t index);
soyokaze_slice_t soyokaze_ech_config_public_name(const soyokaze_ech_config_list_t *list, size_t index);
int32_t soyokaze_ech_config_maximum_name_length(const soyokaze_ech_config_list_t *list, size_t index);

/* ------------------------------------------------------------------ client */

/* The limits a client applies on top of the per-message ones. Start from
 * soyokaze_client_limits_default() and adjust. */
typedef struct {
    soyokaze_limits_t message;
    double connection_timeout; /* seconds; zero waits forever */
} soyokaze_client_limits_t;

soyokaze_client_limits_t soyokaze_client_limits_default(void);

/* One host's ECH configuration list; a host of "*" applies wherever no exact
 * entry matches. */
typedef struct {
    soyokaze_slice_t host;
    soyokaze_slice_t config_list;
} soyokaze_ech_entry_t;

/* NULL wherever a config is asked for takes every default; a NULL pointer
 * inside the struct takes that field's default the same way. */
typedef struct {
    const int32_t *versions; /* soyokaze_version_t values, most preferred first */
    size_t version_count;
    const soyokaze_client_limits_t *limits;
    bool secure;
    bool cookies;
    bool hsts;
    const soyokaze_slice_t *roots; /* each DER or PEM; NULL keeps the platform store */
    size_t root_count;
    const soyokaze_tls_config_t *tls; /* NULL takes every default */
    const soyokaze_ech_entry_t *ech;
    size_t ech_count;
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
soyokaze_status_t soyokaze_client_websocket(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                            const uint8_t *url, size_t url_len,
                                            soyokaze_websocket_t **out, soyokaze_error_t **error);

soyokaze_version_t soyokaze_connection_version(const soyokaze_connection_t *connection);
soyokaze_role_t soyokaze_connection_role(const soyokaze_connection_t *connection);
soyokaze_buffer_t soyokaze_connection_id(const soyokaze_connection_t *connection);
bool soyokaze_connection_reusable(const soyokaze_connection_t *connection);
/* `message` is consumed. */
soyokaze_status_t soyokaze_connection_send(soyokaze_runtime_t *runtime,
                                           soyokaze_connection_t *connection,
                                           soyokaze_message_t *message,
                                           soyokaze_error_t **error);
soyokaze_status_t soyokaze_connection_receive(soyokaze_runtime_t *runtime,
                                              soyokaze_connection_t *connection,
                                              soyokaze_message_t **out,
                                              soyokaze_error_t **error);
/* `connection` is consumed, whether the handshake succeeds or not. */
soyokaze_status_t soyokaze_connection_open_websocket(soyokaze_runtime_t *runtime,
                                                     soyokaze_connection_t *connection,
                                                     const uint8_t *authority, size_t authority_len,
                                                     const uint8_t *target, size_t target_len,
                                                     const soyokaze_limits_t *limits,
                                                     soyokaze_websocket_t **out,
                                                     soyokaze_error_t **error);
void soyokaze_connection_close(soyokaze_runtime_t *runtime, soyokaze_connection_t *connection);
void soyokaze_connection_free(soyokaze_connection_t *connection);

/* --------------------------------------------------------------- websocket */

/* Opcodes and close codes cross as their wire numbers: opcodes 0x0
 * continuation, 0x1 text, 0x2 binary, 0x8 close, 0x9 ping, 0xa pong; close
 * codes 1000-1011 as defined. These calls take no runtime — the socket
 * carries its own, so they may be made from a server callback. */
void soyokaze_websocket_free(soyokaze_websocket_t *socket);
soyokaze_role_t soyokaze_websocket_role(const soyokaze_websocket_t *socket);
bool soyokaze_websocket_closing(const soyokaze_websocket_t *socket);
soyokaze_buffer_t soyokaze_websocket_id(const soyokaze_websocket_t *socket);
soyokaze_status_t soyokaze_websocket_send(soyokaze_websocket_t *socket,
                                          bool fin, uint8_t opcode,
                                          const uint8_t *payload, size_t payload_len,
                                          soyokaze_error_t **error);
soyokaze_status_t soyokaze_websocket_receive(soyokaze_websocket_t *socket,
                                             bool *fin, uint8_t *opcode,
                                             soyokaze_buffer_t *out,
                                             soyokaze_error_t **error);
soyokaze_status_t soyokaze_websocket_send_message(soyokaze_websocket_t *socket,
                                                  uint8_t opcode,
                                                  const uint8_t *payload, size_t payload_len,
                                                  soyokaze_error_t **error);
soyokaze_status_t soyokaze_websocket_receive_message(soyokaze_websocket_t *socket,
                                                     uint8_t *opcode,
                                                     soyokaze_buffer_t *out,
                                                     soyokaze_error_t **error);
bool soyokaze_websocket_close(soyokaze_websocket_t *socket, uint16_t code,
                              const uint8_t *reason, size_t reason_len);

/* ------------------------------------------------------------------ server */

/* Takes ownership of `request` — free it, or return it as the response. The
 * response returned is taken over by the library. NULL answers with a bare
 * 500. Runs on a runtime thread and may block. */
typedef soyokaze_message_t *(*soyokaze_on_request_t)(void *context, soyokaze_message_t *request);

/* Takes ownership of `socket` — drive it, then free it with
 * soyokaze_websocket_free. Runs on its own blocking thread. */
typedef void (*soyokaze_on_websocket_t)(void *context, soyokaze_websocket_t *socket);

/* One sliding-window rate limit: `count` connections per `period` seconds. */
typedef struct {
    double period;
    uint32_t count;
} soyokaze_rate_t;

/* The limits a server applies on top of the per-message ones. Start from
 * soyokaze_server_limits_default() and adjust. */
typedef struct {
    soyokaze_limits_t message;
    uint32_t backlog;                /* the listen backlog for a TCP socket */
    uint32_t max_connections;        /* 0 is unbounded */
    uint32_t max_connections_per_ip; /* 0 is unbounded */
    const soyokaze_rate_t *max_connection_rate; /* NULL means none */
    size_t rate_count;
    size_t max_connection_history;
    size_t worker_stack_size;        /* the stack size for a worker thread */
} soyokaze_server_limits_t;

soyokaze_server_limits_t soyokaze_server_limits_default(void);

uint32_t soyokaze_cores(void);

/* NULL wherever a config is asked for takes every default. The identity and
 * ECH handles are borrowed: the server copies what it needs. */
typedef struct {
    const int32_t *versions; /* soyokaze_version_t values; NULL offers every one */
    size_t version_count;
    const soyokaze_server_limits_t *limits;
    const soyokaze_identity_t *identity;   /* takes precedence over certificate/key */
    soyokaze_slice_t certificate;          /* DER or PEM; absent serves TCP in plaintext */
    soyokaze_slice_t key;
    const soyokaze_tls_config_t *tls;      /* NULL takes every default */
    const soyokaze_ech_keys_t *ech;
    const soyokaze_hsts_policy_t *hsts;
    bool reuseport;
} soyokaze_server_config_t;

soyokaze_server_t *soyokaze_server_new(const soyokaze_server_config_t *config);
void soyokaze_server_free(soyokaze_server_t *server);

/* Returns once the ports are bound; the accept loops keep running on
 * `runtime`, which must outlive the handle. `context` is reached from more
 * than one thread. A NULL `on_websocket` hands upgrade requests to
 * `on_request` like any other. */
soyokaze_status_t soyokaze_server_serve(soyokaze_runtime_t *runtime,
                                        const soyokaze_server_t *server,
                                        soyokaze_on_request_t on_request,
                                        soyokaze_on_websocket_t on_websocket,
                                        void *context,
                                        const soyokaze_port_t *ports, size_t port_count,
                                        soyokaze_server_handle_t **out,
                                        soyokaze_error_t **error);
uint16_t soyokaze_server_handle_port(const soyokaze_server_handle_t *handle);
size_t soyokaze_server_handle_address_count(const soyokaze_server_handle_t *handle);
uint16_t soyokaze_server_handle_port_at(const soyokaze_server_handle_t *handle, size_t index);
/* Consumes `handle`. A negative `timeout` waits as long as it takes. */
void soyokaze_server_handle_close(soyokaze_runtime_t *runtime,
                                  soyokaze_server_handle_t *handle,
                                  double timeout);

/* The multi-worker counterpart of soyokaze_server_serve: each worker brings
 * its own runtime. A `workers` of 0 takes one per core. */
soyokaze_status_t soyokaze_server_run(const soyokaze_server_t *server,
                                      soyokaze_on_request_t on_request,
                                      soyokaze_on_websocket_t on_websocket,
                                      void *context,
                                      const soyokaze_port_t *ports, size_t port_count,
                                      uint32_t workers,
                                      soyokaze_cluster_t **out,
                                      soyokaze_error_t **error);
uint16_t soyokaze_cluster_port(const soyokaze_cluster_t *cluster);
size_t soyokaze_cluster_address_count(const soyokaze_cluster_t *cluster);
uint16_t soyokaze_cluster_port_at(const soyokaze_cluster_t *cluster, size_t index);
uint32_t soyokaze_cluster_workers(const soyokaze_cluster_t *cluster);
/* Consumes `cluster` and blocks until the workers finish. A negative
 * `timeout` waits as long as it takes. */
void soyokaze_cluster_close(soyokaze_cluster_t *cluster, double timeout);

soyokaze_message_t *soyokaze_response_with_body(uint16_t status_code,
                                                soyokaze_version_t version,
                                                const uint8_t *body, size_t body_len);

/* --------------------------------------------------------------- finalizer */

/* The IMF-fixdate for a Unix timestamp; always 29 octets. */
soyokaze_buffer_t soyokaze_http_date(uint64_t unix_seconds);

/* ----------------------------------------------------------------- helpers */

soyokaze_buffer_t soyokaze_base64_encode(const uint8_t *data, size_t data_len);
bool soyokaze_base64_decode(const uint8_t *text, size_t text_len, soyokaze_buffer_t *out);

/* Always 20 octets. */
soyokaze_buffer_t soyokaze_sha1(const uint8_t *data, size_t data_len);

soyokaze_buffer_t soyokaze_huffman_encode(const uint8_t *data, size_t data_len);
bool soyokaze_huffman_decode(const uint8_t *data, size_t data_len, soyokaze_buffer_t *out);

/* Fields, the vocabulary HPACK and QPACK share. One field goes into an
 * encoder as a soyokaze_field_t; a decoded section comes back out as a
 * soyokaze_fields_t. */
typedef struct {
    soyokaze_slice_t name;
    soyokaze_slice_t value;
} soyokaze_field_t;

void soyokaze_fields_free(soyokaze_fields_t *fields);
size_t soyokaze_fields_count(const soyokaze_fields_t *fields);
soyokaze_slice_t soyokaze_fields_name(const soyokaze_fields_t *fields, size_t index);
soyokaze_slice_t soyokaze_fields_value(const soyokaze_fields_t *fields, size_t index);

/* HPACK. An encoder and a decoder are stateful; feed blocks in order. */
soyokaze_hpack_encoder_t *soyokaze_hpack_encoder_new(void);
void soyokaze_hpack_encoder_free(soyokaze_hpack_encoder_t *encoder);
bool soyokaze_hpack_encoder_set_max_capacity(soyokaze_hpack_encoder_t *encoder, size_t max_capacity);
bool soyokaze_hpack_encoder_set_capacity_limit(soyokaze_hpack_encoder_t *encoder, size_t capacity_limit);
soyokaze_buffer_t soyokaze_hpack_encode(soyokaze_hpack_encoder_t *encoder,
                                        const soyokaze_field_t *fields, size_t field_count);
soyokaze_hpack_decoder_t *soyokaze_hpack_decoder_new(void);
void soyokaze_hpack_decoder_free(soyokaze_hpack_decoder_t *decoder);
bool soyokaze_hpack_decoder_set_max_decoded_size(soyokaze_hpack_decoder_t *decoder, size_t max_size);
bool soyokaze_hpack_decoder_set_max_capacity(soyokaze_hpack_decoder_t *decoder, size_t max_capacity);
soyokaze_status_t soyokaze_hpack_decode(soyokaze_hpack_decoder_t *decoder,
                                        const uint8_t *block, size_t block_len,
                                        soyokaze_fields_t **out,
                                        soyokaze_error_t **error);

/* QPACK. Instruction streams cross as raw octets, exactly as they travel. */
soyokaze_qpack_encoder_t *soyokaze_qpack_encoder_new(void);
void soyokaze_qpack_encoder_free(soyokaze_qpack_encoder_t *encoder);
bool soyokaze_qpack_encoder_set_max_capacity(soyokaze_qpack_encoder_t *encoder, size_t max_capacity,
                                             soyokaze_buffer_t *instructions);
bool soyokaze_qpack_encoder_set_capacity_limit(soyokaze_qpack_encoder_t *encoder, size_t capacity_limit,
                                               soyokaze_buffer_t *instructions);
bool soyokaze_qpack_encoder_set_max_outstanding_sections(soyokaze_qpack_encoder_t *encoder, size_t max_sections);
bool soyokaze_qpack_encoder_set_max_instruction_size(soyokaze_qpack_encoder_t *encoder, size_t max_size);
bool soyokaze_qpack_encode(soyokaze_qpack_encoder_t *encoder, uint64_t stream_id,
                           const soyokaze_field_t *fields, size_t field_count,
                           soyokaze_buffer_t *block, soyokaze_buffer_t *instructions);
soyokaze_status_t soyokaze_qpack_encoder_on_decoder_instructions(soyokaze_qpack_encoder_t *encoder,
                                                                 const uint8_t *data, size_t data_len,
                                                                 soyokaze_error_t **error);
bool soyokaze_qpack_encoder_cancel(soyokaze_qpack_encoder_t *encoder, uint64_t stream_id);
soyokaze_qpack_decoder_t *soyokaze_qpack_decoder_new(void);
void soyokaze_qpack_decoder_free(soyokaze_qpack_decoder_t *decoder);
bool soyokaze_qpack_decoder_set_max_decoded_size(soyokaze_qpack_decoder_t *decoder, size_t max_size);
bool soyokaze_qpack_decoder_set_max_capacity(soyokaze_qpack_decoder_t *decoder, size_t max_capacity);
bool soyokaze_qpack_decoder_set_max_instruction_size(soyokaze_qpack_decoder_t *decoder, size_t max_size);
bool soyokaze_qpack_decoder_set_max_blocked_streams(soyokaze_qpack_decoder_t *decoder, size_t max_streams);
soyokaze_status_t soyokaze_qpack_decoder_on_encoder_instructions(soyokaze_qpack_decoder_t *decoder,
                                                                 const uint8_t *data, size_t data_len,
                                                                 soyokaze_buffer_t *instructions,
                                                                 soyokaze_error_t **error);
soyokaze_status_t soyokaze_qpack_decode(soyokaze_qpack_decoder_t *decoder, uint64_t stream_id,
                                        const uint8_t *block, size_t block_len,
                                        soyokaze_fields_t **out,
                                        soyokaze_buffer_t *instructions,
                                        soyokaze_error_t **error);

#ifdef __cplusplus
}
#endif

#endif /* SOYOKAZE_H */
