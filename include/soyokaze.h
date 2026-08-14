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
 *  - An enumeration value outside the ones named here is refused rather than
 *    acted on. Every call reads the number it was given before it stands for
 *    anything, and answers as it would for an absent argument: false, zero,
 *    an absent slice, an empty buffer, NULL, or SOYOKAZE_INVALID, whichever
 *    the return type can say. Nothing is ever taken for a value it is not.
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

/* What a port or a version runs over. Nothing keys on a particular version
 * number: a port carries exactly the versions whose transport matches its own,
 * so a future version is routed by what it runs over rather than by name. */
typedef enum {
    SOYOKAZE_TRANSPORT_STREAM = 0,
    SOYOKAZE_TRANSPORT_QUIC = 1
} soyokaze_transport_kind_t;

/* How field names are cased on the way out. Names are always stored lowercase
 * and re-cased as they are written. */
typedef enum {
    SOYOKAZE_HEADER_CASE_TITLE = 0,
    SOYOKAZE_HEADER_CASE_LOWER = 1
} soyokaze_header_case_t;

/* Which kind of body a message carries. */
typedef enum {
    SOYOKAZE_BODY_NONE = 0,
    SOYOKAZE_BODY_DATA = 1,
    SOYOKAZE_BODY_TEXT = 2,
    SOYOKAZE_BODY_FILE = 3
} soyokaze_body_kind_t;

/* One sliding-window rate limit: `count` connections per `period` seconds. */
typedef struct {
    double period;
    uint32_t count;
} soyokaze_rate_t;

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

/* A content coding a message body may be carried in. SOYOKAZE_COMPRESSION_AUTO
 * names nothing on the wire: it is a choice, settled against what the peer said
 * it accepts just before the body goes out. Wherever a coding may be absent it
 * crosses as -1. */
typedef enum {
    SOYOKAZE_COMPRESSION_AUTO = 0,
    SOYOKAZE_COMPRESSION_ZSTD = 1,
    SOYOKAZE_COMPRESSION_BROTLI = 2,
    SOYOKAZE_COMPRESSION_GZIP = 3,
    SOYOKAZE_COMPRESSION_DEFLATE = 4
} soyokaze_compression_t;

/* What one connection is allowed to spend on the peer's behalf. Every field
 * is a ceiling; timeouts are in seconds and zero waits forever. Start from
 * soyokaze_limits_default() and adjust. */
typedef struct {
    uint64_t max_message_size;
    uint64_t max_message_body_size;
    uint64_t max_decompressed_body_size; /* what a received body may reach once decoded */

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
typedef struct soyokaze_gate soyokaze_gate_t;
typedef struct soyokaze_permit soyokaze_permit_t;
typedef struct soyokaze_raw_socket soyokaze_raw_socket_t;
typedef struct soyokaze_headers soyokaze_headers_t;
typedef struct soyokaze_text soyokaze_text_t;
typedef struct soyokaze_sha1 soyokaze_sha1_t;
typedef struct soyokaze_static_index soyokaze_static_index_t;
typedef struct soyokaze_fields soyokaze_fields_t;
typedef struct soyokaze_hpack_table soyokaze_hpack_table_t;
typedef struct soyokaze_hpack_encoder soyokaze_hpack_encoder_t;
typedef struct soyokaze_hpack_decoder soyokaze_hpack_decoder_t;
typedef struct soyokaze_qpack_table soyokaze_qpack_table_t;
typedef struct soyokaze_qpack_encoder soyokaze_qpack_encoder_t;
typedef struct soyokaze_qpack_decoder soyokaze_qpack_decoder_t;
typedef struct soyokaze_qpack_encoder_instruction soyokaze_qpack_encoder_instruction_t;
typedef struct soyokaze_qpack_decoder_instruction soyokaze_qpack_decoder_instruction_t;
typedef struct soyokaze_hsts_store soyokaze_hsts_store_t;
typedef struct soyokaze_date_cache soyokaze_date_cache_t;
typedef struct soyokaze_request_finalizer soyokaze_request_finalizer_t;
typedef struct soyokaze_response_finalizer soyokaze_response_finalizer_t;

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
/* What went wrong without the prefix the message carries. */
soyokaze_slice_t soyokaze_error_reason(const soyokaze_error_t *error);

/* Raising a failure of your own, so it reads exactly like one the crate
 * raised. A SOYOKAZE_STREAM built by soyokaze_error_new names stream zero and
 * code zero; soyokaze_error_stream names them properly. */
soyokaze_error_t *soyokaze_error_new(soyokaze_status_t status, const uint8_t *reason, size_t reason_len);
soyokaze_error_t *soyokaze_error_stream(uint64_t stream_id, uint64_t code,
                                        const uint8_t *reason, size_t reason_len);
soyokaze_error_t *soyokaze_error_tls(const uint8_t *reason, size_t reason_len);
soyokaze_error_t *soyokaze_error_quic(const uint8_t *reason, size_t reason_len);
/* Consumes `error`. A protocol or limit failure becomes a stream one, so the
 * stream is reset instead of the connection; everything else comes back
 * unchanged. */
soyokaze_error_t *soyokaze_error_on_stream(soyokaze_error_t *error, uint64_t stream_id, uint64_t code);

/* ------------------------------------------------------------- vocabulary */

/* Ports, versions and what runs over what. A port carries exactly the versions
 * whose transport matches its own. */
soyokaze_transport_kind_t soyokaze_port_transport(const soyokaze_port_t *port);
bool soyokaze_port_carries(const soyokaze_port_t *port, soyokaze_version_t version);
/* Writes at most `count` versions through `out` and returns how many there
 * were; a NULL `out` counts without writing. */
size_t soyokaze_port_offers(const soyokaze_port_t *port,
                            const soyokaze_version_t *versions, size_t count,
                            soyokaze_version_t *out);

soyokaze_slice_t soyokaze_version_alpn(soyokaze_version_t version);
/* -1 when the identifier names no version. */
int32_t soyokaze_version_from_alpn(const uint8_t *alpn, size_t alpn_len);
uint8_t soyokaze_version_major(soyokaze_version_t version);
soyokaze_transport_kind_t soyokaze_version_transport(soyokaze_version_t version);
soyokaze_slice_t soyokaze_version_name(soyokaze_version_t version);
/* -1 when the name spells no version. */
int32_t soyokaze_version_parse(const uint8_t *name, size_t name_len);

/* The ALPN protocol list, each identifier preceded by its length. */
soyokaze_buffer_t soyokaze_alpn_wire(const soyokaze_version_t *versions, size_t count);
/* Borrowed from `client`; absent when nothing matched. */
soyokaze_slice_t soyokaze_alpn_select(const soyokaze_version_t *versions, size_t count,
                                      const uint8_t *client, size_t client_len);
/* A NULL `alpn` stands for a handshake that agreed on nothing. */
soyokaze_status_t soyokaze_alpn_negotiated(const uint8_t *alpn, size_t alpn_len,
                                           const soyokaze_version_t *versions, size_t count,
                                           soyokaze_version_t *out,
                                           soyokaze_error_t **error);

soyokaze_slice_t soyokaze_method_name(soyokaze_method_t method);
/* -1 when the name spells no method. */
int32_t soyokaze_method_parse(const uint8_t *name, size_t name_len);
bool soyokaze_method_safe(soyokaze_method_t method);
bool soyokaze_method_idempotent(soyokaze_method_t method);

bool soyokaze_role_is_client(soyokaze_role_t role);
bool soyokaze_role_is_server(soyokaze_role_t role);

soyokaze_header_case_t soyokaze_header_case_from_version(soyokaze_version_t version);
soyokaze_buffer_t soyokaze_header_case_apply(soyokaze_header_case_t header_case,
                                             const uint8_t *name, size_t name_len);
bool soyokaze_header_case_apply_in_place(soyokaze_header_case_t header_case,
                                         uint8_t *name, size_t name_len);

/* ----------------------------------------------------------------- headers */

/* A field section on its own. One borrowed from a message belongs to that
 * message and must not be freed. */
uint32_t soyokaze_headers_well_known(const uint8_t *name, size_t name_len);
uint32_t soyokaze_headers_bit(bool matched, uint32_t index);
bool soyokaze_headers_named(const uint8_t *stored, size_t stored_len,
                            const uint8_t *name, size_t name_len);
soyokaze_headers_t *soyokaze_headers_new(void);

/* Room is an optimisation: a section grows past `fields` as fields are added,
 * and an ask larger than any section could hold is taken as the ceiling rather
 * than made into an allocation the machine would refuse. */
soyokaze_headers_t *soyokaze_headers_with_capacity(size_t fields);

/* Only a section from soyokaze_headers_new or soyokaze_headers_with_capacity
 * is freed this way; one borrowed from a message belongs to that message. */
void soyokaze_headers_free(soyokaze_headers_t *headers);
size_t soyokaze_headers_len(const soyokaze_headers_t *headers);
bool soyokaze_headers_is_empty(const soyokaze_headers_t *headers);
soyokaze_slice_t soyokaze_headers_name(const soyokaze_headers_t *headers, size_t index);
soyokaze_slice_t soyokaze_headers_value(const soyokaze_headers_t *headers, size_t index);
bool soyokaze_headers_contains(const soyokaze_headers_t *headers, const uint8_t *name, size_t name_len);
bool soyokaze_headers_absent(const soyokaze_headers_t *headers, const uint8_t *name, size_t name_len);
soyokaze_slice_t soyokaze_headers_get(const soyokaze_headers_t *headers, const uint8_t *name, size_t name_len);
size_t soyokaze_headers_get_all_count(const soyokaze_headers_t *headers, const uint8_t *name, size_t name_len);
soyokaze_slice_t soyokaze_headers_get_all(const soyokaze_headers_t *headers,
                                          const uint8_t *name, size_t name_len, size_t index);
bool soyokaze_headers_append(soyokaze_headers_t *headers,
                             const uint8_t *name, size_t name_len,
                             const uint8_t *value, size_t value_len);
/* The name must already be lowercase, or no lookup will ever find it. */
bool soyokaze_headers_append_lowercase(soyokaze_headers_t *headers,
                                       const uint8_t *name, size_t name_len,
                                       const uint8_t *value, size_t value_len);
bool soyokaze_headers_insert(soyokaze_headers_t *headers,
                             const uint8_t *name, size_t name_len,
                             const uint8_t *value, size_t value_len);
bool soyokaze_headers_remove(soyokaze_headers_t *headers, const uint8_t *name, size_t name_len);

/* --------------------------------------------------------------------- url */

uint16_t soyokaze_url_default_port(const uint8_t *scheme, size_t scheme_len);
soyokaze_buffer_t soyokaze_url_authority_of(const uint8_t *scheme, size_t scheme_len,
                                            const uint8_t *host, size_t host_len,
                                            uint16_t port);
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

bool soyokaze_message_set_version(soyokaze_message_t *message, soyokaze_version_t version);
/* A negative `method` or `status_code`, or a NULL `target`, clears it. */
bool soyokaze_message_set_method(soyokaze_message_t *message, int32_t method);
bool soyokaze_message_set_target(soyokaze_message_t *message, const uint8_t *target, size_t target_len);
bool soyokaze_message_set_status_code(soyokaze_message_t *message, int32_t status_code);
/* `method` is the request method a response is read against; -1 when none. */
bool soyokaze_message_tunneling(const soyokaze_message_t *message, int32_t method);

/* Borrowed from the message, built empty when it has none yet. Belongs to the
 * message: do not free it, and do not hold it past the message. */
soyokaze_headers_t *soyokaze_message_headers(soyokaze_message_t *message);
soyokaze_headers_t *soyokaze_message_trailers(soyokaze_message_t *message);

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
/* A NULL `id` clears it. */
bool soyokaze_message_set_connection_id(soyokaze_message_t *message, const uint8_t *id, size_t id_len);

/* The address the request was received from, and its port, as text. Empty on a
 * response, on a message the caller built, and over a Unix socket, whose
 * accepted address names nothing. Free with soyokaze_buffer_free. */
soyokaze_buffer_t soyokaze_message_client(const soyokaze_message_t *message);

/* The content coding the body is to go out in. Set it before sending to have
 * the body coded on the way out; on a message that was received it reads as
 * what the coding the connection took off the body. This is Content-Encoding
 * and nothing else: Transfer-Encoding frames a body rather than codes it. */
int32_t soyokaze_message_compression(const soyokaze_message_t *message); /* -1 when none */
bool soyokaze_message_set_compression(soyokaze_message_t *message, int32_t compression); /* -1 clears it */
/* Whether the body is currently carried compressed, per Content-Encoding. */
bool soyokaze_message_compressed(const soyokaze_message_t *message);
/* The best coding the message's Accept-Encoding permits. */
int32_t soyokaze_message_accepted(const soyokaze_message_t *message); /* -1 when none */

/* Reads a body that is still a file into memory, so it can be coded. */
soyokaze_status_t soyokaze_message_materialize(soyokaze_message_t *message,
                                               const soyokaze_runtime_t *runtime,
                                               soyokaze_error_t **error);
/* Codes the body in soyokaze_message_compression. `accepted` is the coding the
 * exchange permits, which is what SOYOKAZE_COMPRESSION_AUTO settles on; -1
 * permits none. The body must already be in memory. */
soyokaze_status_t soyokaze_message_compress(soyokaze_message_t *message, int32_t accepted, soyokaze_error_t **error);
/* Decodes a body that arrived coded and takes Content-Encoding off it. `max`
 * bounds what the decoded body may reach; passing it is SOYOKAZE_STATUS_LIMIT. */
soyokaze_status_t soyokaze_message_decompress(soyokaze_message_t *message, uint64_t max, soyokaze_error_t **error);

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
bool soyokaze_message_clear_body(soyokaze_message_t *message);
soyokaze_body_kind_t soyokaze_message_body_kind(const soyokaze_message_t *message);
bool soyokaze_message_body_is_empty(const soyokaze_message_t *message);
/* Borrowed from the message; absent for a file that has not been read. */
soyokaze_slice_t soyokaze_message_body_inline(const soyokaze_message_t *message);
soyokaze_slice_t soyokaze_message_body_path(const soyokaze_message_t *message);
int64_t soyokaze_message_body_len(const soyokaze_message_t *message); /* -1 when unknown */
soyokaze_status_t soyokaze_message_body(soyokaze_runtime_t *runtime,
                                        const soyokaze_message_t *message,
                                        soyokaze_buffer_t *out,
                                        soyokaze_error_t **error);

/* --------------------------------------------------------------- responses */

soyokaze_message_t *soyokaze_response_with_body(uint16_t status_code,
                                                soyokaze_version_t version,
                                                const uint8_t *body, size_t body_len);
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

/* The reason phrase a status code is conventionally sent with, and the media
 * type a path's extension names. Both borrowed from the library. */
soyokaze_slice_t soyokaze_status_reason(uint16_t status_code);
soyokaze_slice_t soyokaze_content_type(const uint8_t *path, size_t path_len);
/* `request` is read, not consumed. */
soyokaze_message_t *soyokaze_response_upgrade_required(const soyokaze_message_t *request,
                                                       soyokaze_version_t version,
                                                       const uint8_t *protocol, size_t protocol_len);

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

/* A stored cookie, as a jar holds it. The text points into a buffer handed
 * back through `storage`, which the caller frees once it is done with the
 * entry. `expires_in` is -1 when the cookie lasts the session. */
typedef struct {
    soyokaze_slice_t name;
    soyokaze_slice_t value;
    soyokaze_slice_t domain;
    bool host_only;
    soyokaze_slice_t path;
    bool secure;
    double expires_in;
} soyokaze_stored_cookie_t;

uint32_t soyokaze_cookie_default_max_cookies(void);
uint16_t soyokaze_cookie_default_max_cookies_per_domain(void);
bool soyokaze_cookie_is_separator(uint8_t octet);
soyokaze_slice_t soyokaze_samesite_name(int32_t samesite);
/* -1 when the name spells no attribute. */
int32_t soyokaze_samesite_parse(const uint8_t *name, size_t name_len);
bool soyokaze_setcookie_age(const uint8_t *text, size_t text_len, int64_t *out);
bool soyokaze_cookie_path_matches(const uint8_t *target, size_t target_len,
                                  const uint8_t *path, size_t path_len);
soyokaze_buffer_t soyokaze_cookie_default_path(const uint8_t *target, size_t target_len);
size_t soyokaze_cookiejar_count(const soyokaze_cookiejar_t *jar);
uint32_t soyokaze_cookiejar_max_cookies(const soyokaze_cookiejar_t *jar);
uint16_t soyokaze_cookiejar_max_cookies_per_domain(const soyokaze_cookiejar_t *jar);
bool soyokaze_cookiejar_entry(const soyokaze_cookiejar_t *jar, size_t index,
                              soyokaze_stored_cookie_t *out, soyokaze_buffer_t *storage);

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
void soyokaze_hsts_store_prune(const soyokaze_hsts_store_t *store);

uint32_t soyokaze_hsts_default_max_entries(void);
soyokaze_hsts_policy_t soyokaze_hsts_policy_new(int64_t max_age);
/* Empty with a NULL pointer for an empty name and for an IP address, since
 * HSTS applies to host names only. */
soyokaze_buffer_t soyokaze_hsts_normalize(const uint8_t *host, size_t host_len);
size_t soyokaze_hsts_store_len(const soyokaze_hsts_store_t *store);
uint32_t soyokaze_hsts_store_max_entries(const soyokaze_hsts_store_t *store);

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

/* Which encoding a certificate or key blob is in. One DER blob holds exactly
 * one object; one PEM blob holds as many as were concatenated into it. */
typedef enum {
    SOYOKAZE_FORMAT_DER = 0,
    SOYOKAZE_FORMAT_PEM = 1
} soyokaze_format_t;

/* What a connection turned out to be underneath. A -1 stands for a value the
 * handshake did not settle. A QUIC connection reports TLS 1.3, which is what
 * it carries, but not the cipher suite or group. */
typedef struct {
    bool secure;
    bool early_data;
    bool tls;
    int32_t tls_version;
    int32_t tls_group;
    int32_t tls_cipher;
    bool quic;
    int64_t quic_version;
} soyokaze_security_t;

uint16_t soyokaze_tls_version_1_3(void);
uint8_t soyokaze_format_sequence(void);
soyokaze_format_t soyokaze_format_of(const uint8_t *raw, size_t raw_len);
/* -1 when the blob will not parse. */
ptrdiff_t soyokaze_format_certificate_count(const uint8_t *raw, size_t raw_len);
soyokaze_buffer_t soyokaze_format_certificate(const uint8_t *raw, size_t raw_len, size_t index);
soyokaze_buffer_t soyokaze_format_private_key(const uint8_t *raw, size_t raw_len);
soyokaze_security_t soyokaze_security_default(void);
soyokaze_security_t soyokaze_security_quic(int64_t quic_version);
bool soyokaze_security_apply(const soyokaze_security_t *security, soyokaze_message_t *message);
soyokaze_security_t soyokaze_message_security(const soyokaze_message_t *message);
uint16_t soyokaze_ech_config_supported_version(void);
uint16_t soyokaze_ech_kem_x25519_hkdf_sha256(void);
uint16_t soyokaze_ech_kdf_hkdf_sha256(void);
uint16_t soyokaze_ech_aead_aes_128_gcm(void);
uint8_t soyokaze_ech_maximum_name_length(void);
soyokaze_buffer_t soyokaze_ech_keys_encode(const uint8_t *public_name, size_t public_name_len,
                                           uint8_t config_id,
                                           const uint8_t *public_key, size_t public_key_len);
/* -1 when the chain will not parse. */
ptrdiff_t soyokaze_identity_certificate_count(const soyokaze_identity_t *identity);
soyokaze_buffer_t soyokaze_identity_certificate(const soyokaze_identity_t *identity, size_t index);
soyokaze_buffer_t soyokaze_identity_private_key(const soyokaze_identity_t *identity);

/* --------------------------------------------------------------------- api */

/* The versions offered when nothing narrows them, newest first. */
size_t soyokaze_versions_count(void);
int32_t soyokaze_versions_at(size_t index); /* -1 past the end */
const soyokaze_version_t *soyokaze_versions(void);

/* The server's admission control. A server builds its own from its limits, so
 * nothing here needs calling for an ordinary server; it is for a caller that
 * admits connections itself, and for reading what a running gate is doing.
 * An admitted connection holds a permit until it is freed. */
soyokaze_gate_t *soyokaze_gate_new(uint32_t max_connections, uint32_t max_connections_per_ip,
                                   const soyokaze_rate_t *rates, size_t rate_count,
                                   size_t max_connection_history);
void soyokaze_gate_free(soyokaze_gate_t *gate);
uint32_t soyokaze_gate_count(const soyokaze_gate_t *gate);
uint32_t soyokaze_gate_max_connections(const soyokaze_gate_t *gate);
uint32_t soyokaze_gate_max_connections_per_ip(const soyokaze_gate_t *gate);
size_t soyokaze_gate_max_connection_history(const soyokaze_gate_t *gate);
size_t soyokaze_gate_rate_count(const soyokaze_gate_t *gate);
soyokaze_rate_t soyokaze_gate_rate(const soyokaze_gate_t *gate, size_t index);
double soyokaze_gate_window(const soyokaze_gate_t *gate);
/* `ip` is an address in its text form; NULL counts the connections admitted
 * without one. */
uint32_t soyokaze_gate_count_for(const soyokaze_gate_t *gate, const uint8_t *ip, size_t ip_len);
/* NULL when the connection is turned away. */
soyokaze_permit_t *soyokaze_gate_admit(const soyokaze_gate_t *gate, const uint8_t *ip, size_t ip_len);
void soyokaze_gate_sweep(const soyokaze_gate_t *gate);
void soyokaze_permit_free(soyokaze_permit_t *permit);
soyokaze_buffer_t soyokaze_permit_address(const soyokaze_permit_t *permit);
/* A handle of its own, freed with soyokaze_gate_free. */
soyokaze_gate_t *soyokaze_permit_gate(const soyokaze_permit_t *permit);

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
/* What a client would use for a host and port, without dialing anything. */
soyokaze_buffer_t soyokaze_client_id(const soyokaze_client_t *client,
                                     const uint8_t *host, size_t host_len,
                                     const soyokaze_port_t *target);
soyokaze_buffer_t soyokaze_client_authority(const soyokaze_client_t *client,
                                            const uint8_t *host, size_t host_len,
                                            const soyokaze_port_t *target);
soyokaze_slice_t soyokaze_client_ech(const soyokaze_client_t *client,
                                     const uint8_t *host, size_t host_len);
soyokaze_status_t soyokaze_client_prior_version(const soyokaze_client_t *client,
                                                soyokaze_version_t *out,
                                                soyokaze_error_t **error);
bool soyokaze_client_only_quic(const soyokaze_client_t *client);
size_t soyokaze_client_version_count(const soyokaze_client_t *client);
int32_t soyokaze_client_version_at(const soyokaze_client_t *client, size_t index);
/* Borrowed from the client: do not free, and do not hold past the client. */
const soyokaze_cookiejar_t *soyokaze_client_jar(const soyokaze_client_t *client);
const soyokaze_hsts_store_t *soyokaze_client_store(const soyokaze_client_t *client);
bool soyokaze_client_apply_hsts(const soyokaze_client_t *client, soyokaze_url_t *url);
/* Freed with soyokaze_request_finalizer_free. */
soyokaze_request_finalizer_t *soyokaze_client_request_finalizer(const soyokaze_client_t *client,
                                                                const uint8_t *authority, size_t authority_len);

soyokaze_status_t soyokaze_client_websocket(soyokaze_runtime_t *runtime, const soyokaze_client_t *client,
                                            const uint8_t *url, size_t url_len,
                                            soyokaze_websocket_t **out, soyokaze_error_t **error);

soyokaze_version_t soyokaze_connection_version(const soyokaze_connection_t *connection);
soyokaze_role_t soyokaze_connection_role(const soyokaze_connection_t *connection);
soyokaze_buffer_t soyokaze_connection_id(const soyokaze_connection_t *connection);
/* The address the peer connected from, and its port, as text. Empty on a client
 * connection and over a Unix socket. Free with soyokaze_buffer_free. */
soyokaze_buffer_t soyokaze_connection_client(const soyokaze_connection_t *connection);
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

/* The framing and the handshake underneath a WebSocket connection, for a
 * caller driving one by hand. The head of a frame, with `masked` standing for
 * the mask being present. */
typedef struct {
    bool fin;
    uint8_t opcode;
    bool masked;
    uint8_t mask[4];
    size_t start;
    size_t length;
} soyokaze_websocket_frame_head_t;

/* What one WebSocket connection may spend on the peer's behalf. Derived from a
 * soyokaze_limits_t when a connection is built. */
typedef struct {
    uint64_t max_message_size;
    uint16_t ws_max_fragments;
    double ws_linger_timeout;
    double read_timeout;
    double write_timeout;
    uint64_t read_chunk_size;
    uint64_t idle_capacity;
} soyokaze_websocket_limits_t;

soyokaze_slice_t soyokaze_websocket_guid(void);
soyokaze_slice_t soyokaze_websocket_version(void);
soyokaze_slice_t soyokaze_websocket_protocol(void);
size_t soyokaze_websocket_maximum_control_payload(void);
bool soyokaze_websocket_opcode_known(uint8_t opcode);
bool soyokaze_websocket_opcode_control(uint8_t opcode);
bool soyokaze_websocket_close_code_known(uint16_t code);
bool soyokaze_websocket_close_code_permitted(uint16_t code);
bool soyokaze_websocket_random(uint8_t *out, size_t out_len);
/* Four octets; empty with a NULL pointer when no randomness was reachable. */
soyokaze_buffer_t soyokaze_websocket_masking_key(void);
/* `mask` is four octets; the payload is masked in place. */
bool soyokaze_websocket_apply_mask(const uint8_t *mask, uint8_t *payload, size_t payload_len);
/* SOYOKAZE_CLOSED when more octets are needed. */
soyokaze_status_t soyokaze_websocket_frame_head(const uint8_t *data, size_t data_len,
                                                soyokaze_websocket_frame_head_t *out,
                                                soyokaze_error_t **error);
/* A NULL `mask` writes an unmasked frame, which is what a server sends. */
soyokaze_buffer_t soyokaze_websocket_frame_encode(bool fin, uint8_t opcode, const uint8_t *mask,
                                                  const uint8_t *payload, size_t payload_len);
soyokaze_status_t soyokaze_websocket_frame_decode(const uint8_t *data, size_t data_len,
                                                  soyokaze_websocket_frame_head_t *out,
                                                  soyokaze_buffer_t *payload, size_t *read,
                                                  soyokaze_error_t **error);
soyokaze_buffer_t soyokaze_websocket_accept_key(const uint8_t *key, size_t key_len);
soyokaze_buffer_t soyokaze_websocket_nonce(void);
soyokaze_message_t *soyokaze_websocket_upgrade_request(const uint8_t *host, size_t host_len,
                                                       const uint8_t *target, size_t target_len,
                                                       const uint8_t *key, size_t key_len,
                                                       soyokaze_version_t version);
soyokaze_message_t *soyokaze_websocket_upgrade_response(const uint8_t *key, size_t key_len,
                                                        soyokaze_version_t version);
soyokaze_status_t soyokaze_websocket_verify_upgrade_request(const soyokaze_message_t *request,
                                                            soyokaze_buffer_t *key,
                                                            soyokaze_error_t **error);
soyokaze_status_t soyokaze_websocket_verify_upgrade_response(const soyokaze_message_t *response,
                                                             const uint8_t *key, size_t key_len,
                                                             soyokaze_error_t **error);
soyokaze_message_t *soyokaze_websocket_connect_request(const uint8_t *authority, size_t authority_len,
                                                       const uint8_t *target, size_t target_len,
                                                       soyokaze_version_t version);
soyokaze_message_t *soyokaze_websocket_connect_response(soyokaze_version_t version);
soyokaze_status_t soyokaze_websocket_verify_connect_request(const soyokaze_message_t *request,
                                                            soyokaze_error_t **error);
soyokaze_status_t soyokaze_websocket_verify_connect_response(const soyokaze_message_t *response,
                                                             soyokaze_error_t **error);
bool soyokaze_websocket_requested(const soyokaze_message_t *request);
soyokaze_status_t soyokaze_websocket_verify(const soyokaze_message_t *request, soyokaze_error_t **error);
soyokaze_message_t *soyokaze_websocket_refusal(const soyokaze_message_t *request, soyokaze_version_t version);
bool soyokaze_websocket_token_present(const soyokaze_headers_t *headers,
                                      const uint8_t *name, size_t name_len,
                                      const uint8_t *token, size_t token_len);
soyokaze_websocket_limits_t soyokaze_websocket_limits_default(void);
soyokaze_websocket_limits_t soyokaze_websocket_limits_of(const soyokaze_limits_t *limits);
soyokaze_websocket_limits_t soyokaze_websocket_limits(const soyokaze_websocket_t *socket);

/* ------------------------------------------------------------------ server */

/* Takes ownership of `request` — free it, or return it as the response. The
 * response returned is taken over by the library. NULL answers with a bare
 * 500. Runs on a runtime thread and may block. */
typedef soyokaze_message_t *(*soyokaze_on_request_t)(void *context, soyokaze_message_t *request);

/* Takes ownership of `socket` — drive it, then free it with
 * soyokaze_websocket_free. Runs on its own blocking thread. */
typedef void (*soyokaze_on_websocket_t)(void *context, soyokaze_websocket_t *socket);

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
    uint32_t uds_mode;                     /* a unix socket's mode; 0 leaves it to the umask */
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
soyokaze_buffer_t soyokaze_server_handle_address_at(const soyokaze_server_handle_t *handle, size_t index);
size_t soyokaze_server_version_count(const soyokaze_server_t *server);
int32_t soyokaze_server_version_at(const soyokaze_server_t *server, size_t index);
bool soyokaze_server_reuseport(const soyokaze_server_t *server);
uint32_t soyokaze_server_uds_mode(const soyokaze_server_t *server);
/* The admission gate these limits describe, freed with soyokaze_gate_free. */
soyokaze_gate_t *soyokaze_server_limits_gate(const soyokaze_server_limits_t *limits);

/* Binding a port without starting anything on it, for a caller that wants to
 * drop privileges after binding or hand a socket to another process. The
 * handle owns the descriptor: freeing it closes it. */
soyokaze_status_t soyokaze_server_open(const soyokaze_server_t *server, const soyokaze_port_t *target,
                                       soyokaze_raw_socket_t **out, soyokaze_error_t **error);
void soyokaze_raw_socket_free(soyokaze_raw_socket_t *socket);
soyokaze_buffer_t soyokaze_raw_socket_address(const soyokaze_raw_socket_t *socket);
uint16_t soyokaze_raw_socket_port(const soyokaze_raw_socket_t *socket);
soyokaze_status_t soyokaze_raw_socket_share(const soyokaze_raw_socket_t *socket,
                                            soyokaze_raw_socket_t **out, soyokaze_error_t **error);
int32_t soyokaze_raw_socket_descriptor(const soyokaze_raw_socket_t *socket);

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
soyokaze_buffer_t soyokaze_cluster_address_at(const soyokaze_cluster_t *cluster, size_t index);
/* Consumes `cluster` and blocks until the workers finish. A negative
 * `timeout` waits as long as it takes. */
void soyokaze_cluster_close(soyokaze_cluster_t *cluster, double timeout);

/* --------------------------------------------------------------- finalizer */

/* The IMF-fixdate for a Unix timestamp; always 29 octets. */
soyokaze_buffer_t soyokaze_http_date(uint64_t unix_seconds);

size_t soyokaze_date_length(void);
soyokaze_slice_t soyokaze_day_name(size_t index);   /* Sunday first */
soyokaze_slice_t soyokaze_month_name(size_t index); /* January first */
void soyokaze_civil_from_days(int64_t days, int64_t *year, uint32_t *month, uint32_t *day);

/* A cache renders at most once a second and hands the same date back in
 * between, which is what a busy server wants. A NULL cache uses the shared
 * one. */
soyokaze_date_cache_t *soyokaze_date_cache_new(void);
void soyokaze_date_cache_free(soyokaze_date_cache_t *cache);
soyokaze_buffer_t soyokaze_date_cache_now(const soyokaze_date_cache_t *cache);

/* The two halves that put the finishing fields on a message before it goes
 * out. A connection runs both itself, so nothing here needs calling for an
 * ordinary exchange. */
soyokaze_response_finalizer_t *soyokaze_response_finalizer_new(const soyokaze_hsts_policy_t *hsts);
void soyokaze_response_finalizer_free(soyokaze_response_finalizer_t *finalizer);
bool soyokaze_response_finalizer_finalize(const soyokaze_response_finalizer_t *finalizer,
                                          soyokaze_role_t role, bool secure,
                                          soyokaze_message_t *message);
soyokaze_request_finalizer_t *soyokaze_request_finalizer_new(const uint8_t *authority, size_t authority_len);
void soyokaze_request_finalizer_free(soyokaze_request_finalizer_t *finalizer);
soyokaze_slice_t soyokaze_request_finalizer_authority(const soyokaze_request_finalizer_t *finalizer);
bool soyokaze_request_finalizer_finalize(const soyokaze_request_finalizer_t *finalizer,
                                         soyokaze_role_t role, soyokaze_message_t *message);
bool soyokaze_message_finalize_response(soyokaze_message_t *message,
                                        const soyokaze_date_cache_t *cache,
                                        const soyokaze_hsts_policy_t *hsts);
bool soyokaze_message_finalize_request(soyokaze_message_t *message,
                                       const uint8_t *authority, size_t authority_len);

/* ---------------------------------------------------------------- protocol */

/* The wire format each version is written in — frames, field sections, start
 * lines, chunks — on its own. Nothing here touches a connection: a connection
 * is reached through the client and server sections above, as one kind of
 * handle whichever version framed it. */

typedef struct soyokaze_read_buffer soyokaze_read_buffer_t;
typedef struct soyokaze_h2_frame soyokaze_h2_frame_t;
typedef struct soyokaze_h3_frame soyokaze_h3_frame_t;

/* --- common. The read buffer a connection fills from its transport, and the
 * pseudo-field vocabulary HTTP/2 and HTTP/3 turn a message into and back. */
size_t soyokaze_read_buffer_default_chunk_size(void);
size_t soyokaze_read_buffer_chunk_ramp(void);
bool soyokaze_read_buffer_oversized(size_t capacity, size_t len, size_t idle_capacity);
soyokaze_read_buffer_t *soyokaze_read_buffer_new(void);
soyokaze_read_buffer_t *soyokaze_read_buffer_with_chunk_size(size_t chunk_size);
void soyokaze_read_buffer_free(soyokaze_read_buffer_t *buffer);
size_t soyokaze_read_buffer_chunk_size(const soyokaze_read_buffer_t *buffer);
bool soyokaze_read_buffer_set_chunk_size(soyokaze_read_buffer_t *buffer, size_t chunk_size);
size_t soyokaze_read_buffer_len(const soyokaze_read_buffer_t *buffer);
bool soyokaze_read_buffer_is_empty(const soyokaze_read_buffer_t *buffer);
bool soyokaze_read_buffer_eof(const soyokaze_read_buffer_t *buffer);
size_t soyokaze_read_buffer_capacity(const soyokaze_read_buffer_t *buffer);
soyokaze_slice_t soyokaze_read_buffer_bytes(const soyokaze_read_buffer_t *buffer);
bool soyokaze_read_buffer_extend(soyokaze_read_buffer_t *buffer, const uint8_t *data, size_t data_len);
bool soyokaze_read_buffer_consume(soyokaze_read_buffer_t *buffer, size_t count);
soyokaze_buffer_t soyokaze_read_buffer_take(soyokaze_read_buffer_t *buffer, size_t count);
bool soyokaze_read_buffer_reclaim(soyokaze_read_buffer_t *buffer, size_t idle_capacity);

size_t soyokaze_pseudo_request_count(void);
soyokaze_slice_t soyokaze_pseudo_request_name(size_t index);
size_t soyokaze_pseudo_response_count(void);
soyokaze_slice_t soyokaze_pseudo_response_name(size_t index);
size_t soyokaze_connection_specific_count(void);
soyokaze_slice_t soyokaze_connection_specific_name(size_t index);
bool soyokaze_connection_specific(const uint8_t *name, size_t name_len);
soyokaze_buffer_t soyokaze_pseudo_status(uint16_t status_code);
soyokaze_status_t soyokaze_fields_of_message(const soyokaze_message_t *message,
                                             soyokaze_fields_t **out,
                                             soyokaze_error_t **error);
/* `fields` is read, not consumed. */
soyokaze_status_t soyokaze_fields_to_message(const soyokaze_fields_t *fields,
                                             soyokaze_version_t version,
                                             soyokaze_message_t **out,
                                             soyokaze_error_t **error);

/* --- quic. What HTTP/3 needs of QUIC and nothing more. */
uint64_t soyokaze_varint_maximum(void);
size_t soyokaze_varint_max_size(void);
size_t soyokaze_varint_len(uint64_t value);
soyokaze_buffer_t soyokaze_varint_encode(uint64_t value);
bool soyokaze_varint_decode(const uint8_t *data, size_t data_len, uint64_t *out, size_t *read);
soyokaze_status_t soyokaze_varint_only(const uint8_t *payload, size_t payload_len,
                                       const uint8_t *name, size_t name_len,
                                       uint64_t *out, soyokaze_error_t **error);
uint64_t soyokaze_quic_stream_step(void);
bool soyokaze_quic_stream_is_bidi(uint64_t stream_id);
bool soyokaze_quic_stream_is_uni(uint64_t stream_id);
bool soyokaze_quic_stream_client_initiated(uint64_t stream_id);
uint64_t soyokaze_quic_stream_first_bidi(soyokaze_role_t role);
uint64_t soyokaze_quic_stream_first_uni(soyokaze_role_t role);
soyokaze_status_t soyokaze_quic_handshake_negotiated(const uint8_t *alpn, size_t alpn_len,
                                                     const soyokaze_version_t *versions, size_t count,
                                                     soyokaze_version_t *out,
                                                     soyokaze_error_t **error);
soyokaze_security_t soyokaze_quic_handshake_security(uint32_t quic_version);

/* --- h1. The start line, one field, one chunk, and how a body is framed. */

/* What one HTTP/1.x connection may spend. Derived from a soyokaze_limits_t. */
typedef struct {
    uint64_t max_message_size;
    uint64_t max_message_body_size;
    uint64_t max_decompressed_body_size;
    uint32_t max_startline_size;
    uint64_t max_headers_size;
    uint16_t max_header_count;
    uint32_t max_chunk_header_size;
    uint64_t inline_body_size;
    uint32_t max_concurrent_streams;
    uint64_t read_chunk_size;
    uint64_t idle_capacity;
    double read_timeout;
    double write_timeout;
    double receive_timeout;
    double send_timeout;
} soyokaze_h1_limits_t;

/* How the length of a message body is determined. */
typedef enum {
    SOYOKAZE_H1_BODY_NONE = 0,
    SOYOKAZE_H1_BODY_CHUNKED = 1,
    SOYOKAZE_H1_BODY_FIXED = 2,
    SOYOKAZE_H1_BODY_CLOSE = 3
} soyokaze_h1_body_kind_t;

soyokaze_h1_limits_t soyokaze_h1_limits_default(void);
soyokaze_h1_limits_t soyokaze_h1_limits_of(const soyokaze_limits_t *limits);
uint8_t soyokaze_h1_token(void);
uint8_t soyokaze_h1_field(void);
/* Always 256 octets. */
soyokaze_slice_t soyokaze_h1_octet_table(void);
bool soyokaze_h1_is_control(uint8_t octet);
bool soyokaze_h1_is_token(const uint8_t *text, size_t text_len);
bool soyokaze_h1_keep_alive(const soyokaze_headers_t *headers, soyokaze_version_t version);
soyokaze_buffer_t soyokaze_h1_start_line_encode(const soyokaze_message_t *message);
soyokaze_status_t soyokaze_h1_start_line_parse(const uint8_t *line, size_t line_len,
                                               soyokaze_message_t **out,
                                               soyokaze_error_t **error);
uint16_t soyokaze_h1_start_line_error_status(const uint8_t *line, size_t line_len);
soyokaze_status_t soyokaze_h1_version_parse(const uint8_t *text, size_t text_len,
                                            soyokaze_version_t *out,
                                            soyokaze_error_t **error);
soyokaze_buffer_t soyokaze_h1_field_encode(const uint8_t *name, size_t name_len,
                                           const uint8_t *value, size_t value_len,
                                           soyokaze_header_case_t header_case);
soyokaze_buffer_t soyokaze_h1_field_encode_all(const soyokaze_headers_t *headers,
                                               soyokaze_header_case_t header_case);
uint64_t soyokaze_h1_field_size(const soyokaze_headers_t *headers);
soyokaze_status_t soyokaze_h1_field_parse(const uint8_t *line, size_t line_len,
                                          soyokaze_buffer_t *name, soyokaze_buffer_t *value,
                                          soyokaze_error_t **error);
soyokaze_status_t soyokaze_h1_field_parse_block(const uint8_t *block, size_t block_len,
                                                size_t max_count,
                                                soyokaze_headers_t **out,
                                                soyokaze_error_t **error);
/* `fields_end` is where the field lines stop and `section_end` where the
 * section as a whole ends, the blank line included. `searched` carries how far
 * a previous call already looked; feed it back so repeated calls stay
 * linear. */
bool soyokaze_h1_field_block_end(const uint8_t *data, size_t data_len,
                                 size_t *searched, size_t *fields_end, size_t *section_end);
soyokaze_buffer_t soyokaze_h1_chunk_encode(const uint8_t *data, size_t data_len);
/* SOYOKAZE_CLOSED when more octets are needed. */
soyokaze_status_t soyokaze_h1_chunk_parse_size(const uint8_t *data, size_t data_len,
                                               size_t *size, size_t *read,
                                               soyokaze_error_t **error);
soyokaze_status_t soyokaze_h1_chunk_decode(const uint8_t *data, size_t data_len,
                                           size_t *start, size_t *end, size_t *read,
                                           soyokaze_error_t **error);
/* `method` is the method of the request a response answers; -1 for a request. */
soyokaze_status_t soyokaze_h1_body_length(const soyokaze_message_t *message, int32_t method,
                                          soyokaze_h1_body_kind_t *kind, uint64_t *length,
                                          soyokaze_error_t **error);
soyokaze_status_t soyokaze_h1_content_length(const uint8_t *value, size_t value_len,
                                             uint64_t *out, soyokaze_error_t **error);
soyokaze_buffer_t soyokaze_h1_decimal(uint64_t value);
soyokaze_buffer_t soyokaze_h1_hexadecimal(uint64_t value);

/* --- h2. The preface, the frame header, every frame, and the settings. */

typedef struct {
    uint64_t max_message_size;
    uint64_t max_message_body_size;
    uint64_t max_decompressed_body_size;
    uint64_t max_headers_size;
    uint16_t max_header_count;
    uint32_t max_concurrent_streams;
    uint64_t max_connection_buffer_size;
    uint32_t max_premature_resets;
    uint32_t max_idle_frames;
    uint64_t output_high_water;
    uint64_t max_encoder_table_size;
    uint64_t read_chunk_size;
    uint64_t idle_capacity;
    double read_timeout;
    double write_timeout;
    double receive_timeout;
    double send_timeout;
} soyokaze_h2_limits_t;

typedef enum {
    SOYOKAZE_H2_NO_ERROR = 0x0,
    SOYOKAZE_H2_PROTOCOL_ERROR = 0x1,
    SOYOKAZE_H2_INTERNAL_ERROR = 0x2,
    SOYOKAZE_H2_FLOW_CONTROL_ERROR = 0x3,
    SOYOKAZE_H2_SETTINGS_TIMEOUT = 0x4,
    SOYOKAZE_H2_STREAM_CLOSED = 0x5,
    SOYOKAZE_H2_FRAME_SIZE_ERROR = 0x6,
    SOYOKAZE_H2_REFUSED_STREAM = 0x7,
    SOYOKAZE_H2_CANCEL = 0x8,
    SOYOKAZE_H2_COMPRESSION_ERROR = 0x9,
    SOYOKAZE_H2_CONNECT_ERROR = 0xa,
    SOYOKAZE_H2_ENHANCE_YOUR_CALM = 0xb,
    SOYOKAZE_H2_INADEQUATE_SECURITY = 0xc,
    SOYOKAZE_H2_HTTP_1_1_REQUIRED = 0xd
} soyokaze_h2_error_code_t;

typedef enum {
    SOYOKAZE_H2_DATA = 0x0,
    SOYOKAZE_H2_HEADERS = 0x1,
    SOYOKAZE_H2_PRIORITY = 0x2,
    SOYOKAZE_H2_RST_STREAM = 0x3,
    SOYOKAZE_H2_SETTINGS = 0x4,
    SOYOKAZE_H2_PUSH_PROMISE = 0x5,
    SOYOKAZE_H2_PING = 0x6,
    SOYOKAZE_H2_GOAWAY = 0x7,
    SOYOKAZE_H2_WINDOW_UPDATE = 0x8,
    SOYOKAZE_H2_CONTINUATION = 0x9
} soyokaze_h2_frame_kind_t;

typedef struct {
    uint32_t length;
    soyokaze_h2_frame_kind_t kind;
    uint8_t flags;
    uint64_t stream_id;
} soyokaze_h2_frame_header_t;

typedef struct {
    uint16_t id;
    uint32_t value;
} soyokaze_h2_parameter_t;

/* A -1 stands for a parameter the peer left unset. */
typedef struct {
    uint32_t header_table_size;
    bool enable_push;
    int64_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    int64_t max_header_list_size;
    bool enable_connect_protocol;
} soyokaze_h2_settings_t;

soyokaze_h2_limits_t soyokaze_h2_limits_default(void);
soyokaze_h2_limits_t soyokaze_h2_limits_of(const soyokaze_limits_t *limits);
soyokaze_slice_t soyokaze_h2_preface(void);
uint8_t soyokaze_h2_flag_end_stream(void);
uint8_t soyokaze_h2_flag_ack(void);
uint8_t soyokaze_h2_flag_end_headers(void);
uint8_t soyokaze_h2_flag_padded(void);
uint8_t soyokaze_h2_flag_priority(void);
bool soyokaze_h2_frame_type_known(uint8_t code);
/* 1 for a frame that must name a stream, 0 for one that must not, -1 either. */
int32_t soyokaze_h2_frame_type_streamed(soyokaze_h2_frame_kind_t kind);
size_t soyokaze_h2_header_size(void);
soyokaze_buffer_t soyokaze_h2_header_encode(soyokaze_h2_frame_header_t header);
/* `length` is written even for a frame kind this library does not know, so a
 * caller can skip past one it cannot read. */
bool soyokaze_h2_header_decode(const uint8_t *data, size_t data_len,
                               soyokaze_h2_frame_header_t *out, uint32_t *length);
soyokaze_h2_frame_t *soyokaze_h2_frame_data(uint64_t stream_id, bool end_stream,
                                            const uint8_t *data, size_t data_len);
soyokaze_h2_frame_t *soyokaze_h2_frame_headers(uint64_t stream_id, bool end_stream, bool end_headers,
                                               const uint8_t *block, size_t block_len);
soyokaze_h2_frame_t *soyokaze_h2_frame_priority(uint64_t stream_id, uint64_t dependency,
                                                bool exclusive, uint8_t weight);
soyokaze_h2_frame_t *soyokaze_h2_frame_rst_stream(uint64_t stream_id, uint32_t error_code);
soyokaze_h2_frame_t *soyokaze_h2_frame_settings(bool ack, const soyokaze_h2_parameter_t *params, size_t count);
soyokaze_h2_frame_t *soyokaze_h2_frame_push_promise(uint64_t stream_id, uint64_t promised_stream_id,
                                                    const uint8_t *block, size_t block_len);
/* `payload` is exactly eight octets. */
soyokaze_h2_frame_t *soyokaze_h2_frame_ping(bool ack, const uint8_t *payload);
soyokaze_h2_frame_t *soyokaze_h2_frame_goaway(uint64_t last_stream_id, uint32_t error_code,
                                              const uint8_t *debug_data, size_t debug_data_len);
soyokaze_h2_frame_t *soyokaze_h2_frame_window_update(uint64_t stream_id, uint32_t increment);
soyokaze_h2_frame_t *soyokaze_h2_frame_continuation(uint64_t stream_id, bool end_headers,
                                                    const uint8_t *block, size_t block_len);
void soyokaze_h2_frame_free(soyokaze_h2_frame_t *frame);
soyokaze_h2_frame_kind_t soyokaze_h2_frame_kind(const soyokaze_h2_frame_t *frame);
uint64_t soyokaze_h2_frame_stream_id(const soyokaze_h2_frame_t *frame);
uint8_t soyokaze_h2_frame_flags(const soyokaze_h2_frame_t *frame);
soyokaze_slice_t soyokaze_h2_frame_bytes(const soyokaze_h2_frame_t *frame);
int64_t soyokaze_h2_frame_error_code(const soyokaze_h2_frame_t *frame);
int64_t soyokaze_h2_frame_other_stream_id(const soyokaze_h2_frame_t *frame);
int64_t soyokaze_h2_frame_increment(const soyokaze_h2_frame_t *frame);
int32_t soyokaze_h2_frame_weight(const soyokaze_h2_frame_t *frame);
bool soyokaze_h2_frame_exclusive(const soyokaze_h2_frame_t *frame);
size_t soyokaze_h2_frame_parameter_count(const soyokaze_h2_frame_t *frame);
soyokaze_h2_parameter_t soyokaze_h2_frame_parameter(const soyokaze_h2_frame_t *frame, size_t index);
soyokaze_buffer_t soyokaze_h2_frame_encode(const soyokaze_h2_frame_t *frame);
soyokaze_buffer_t soyokaze_h2_frame_payload(const soyokaze_h2_frame_t *frame);
/* SOYOKAZE_CLOSED when more octets are needed; a non-zero `read` alongside it
 * means a frame kind this library does not know was skipped. */
soyokaze_status_t soyokaze_h2_frame_decode(const uint8_t *data, size_t data_len, uint32_t max_frame_size,
                                           soyokaze_h2_frame_t **out, size_t *read,
                                           soyokaze_error_t **error);
soyokaze_h2_settings_t soyokaze_h2_settings_default(void);
soyokaze_h2_settings_t soyokaze_h2_settings_peer(void);
size_t soyokaze_h2_settings_parameter_count(const soyokaze_h2_settings_t *settings);
soyokaze_h2_parameter_t soyokaze_h2_settings_parameter(const soyokaze_h2_settings_t *settings, size_t index);
/* `window_delta` is how much every open stream's window moves as a result. */
soyokaze_status_t soyokaze_h2_settings_apply(soyokaze_h2_settings_t *settings, uint16_t id, uint32_t value,
                                             int64_t *window_delta, soyokaze_error_t **error);
uint16_t soyokaze_h2_setting_header_table_size(void);
uint16_t soyokaze_h2_setting_enable_push(void);
uint16_t soyokaze_h2_setting_max_concurrent_streams(void);
uint16_t soyokaze_h2_setting_initial_window_size(void);
uint16_t soyokaze_h2_setting_max_frame_size(void);
uint16_t soyokaze_h2_setting_max_header_list_size(void);
uint16_t soyokaze_h2_setting_enable_connect_protocol(void);
uint32_t soyokaze_h2_default_initial_window_size(void);
uint32_t soyokaze_h2_default_max_frame_size(void);
uint32_t soyokaze_h2_maximum_frame_size(void);
uint32_t soyokaze_h2_maximum_window_size(void);
soyokaze_slice_t soyokaze_h2_error_code_name(uint32_t code);

/* --- h3. Every frame, the unidirectional stream kinds, and the settings. */

typedef struct {
    uint64_t max_message_size;
    uint64_t max_message_body_size;
    uint64_t max_decompressed_body_size;
    uint64_t max_headers_size;
    uint16_t max_header_count;
    uint32_t max_concurrent_streams;
    uint64_t max_connection_buffer_size;
    uint32_t max_premature_resets;
    uint64_t max_requests_per_connection;
    uint64_t max_encoder_table_size;
    double qpack_block_timeout;
    uint32_t max_peer_uni_streams;
    uint32_t max_outstanding_sections;
    uint32_t max_blocked_streams;
    uint32_t tunnel_backlog;
    uint32_t command_backlog;
    uint64_t idle_capacity;
    double receive_timeout;
    double send_timeout;
} soyokaze_h3_limits_t;

typedef enum {
    SOYOKAZE_H3_STREAM_CONTROL = 0x00,
    SOYOKAZE_H3_STREAM_PUSH = 0x01,
    SOYOKAZE_H3_STREAM_QPACK_ENCODER = 0x02,
    SOYOKAZE_H3_STREAM_QPACK_DECODER = 0x03,
    SOYOKAZE_H3_STREAM_REQUEST = 0x04
} soyokaze_h3_stream_kind_t;

typedef enum {
    SOYOKAZE_H3_DATA = 0x00,
    SOYOKAZE_H3_HEADERS = 0x01,
    SOYOKAZE_H3_CANCEL_PUSH = 0x03,
    SOYOKAZE_H3_SETTINGS = 0x04,
    SOYOKAZE_H3_PUSH_PROMISE = 0x05,
    SOYOKAZE_H3_GOAWAY = 0x07,
    SOYOKAZE_H3_MAX_PUSH_ID = 0x0d
} soyokaze_h3_frame_kind_t;

typedef struct {
    uint64_t id;
    uint64_t value;
} soyokaze_h3_parameter_t;

/* A -1 stands for a parameter the peer left unset. */
typedef struct {
    uint64_t qpack_max_table_capacity;
    uint64_t qpack_blocked_streams;
    int64_t max_field_section_size;
    bool enable_connect_protocol;
} soyokaze_h3_settings_t;

soyokaze_h3_limits_t soyokaze_h3_limits_default(void);
soyokaze_h3_limits_t soyokaze_h3_limits_of(const soyokaze_limits_t *limits);
/* -1 for a request stream, which is bidirectional and announces nothing. */
int64_t soyokaze_h3_stream_kind_code(soyokaze_h3_stream_kind_t kind);
int32_t soyokaze_h3_stream_kind_from_code(uint64_t code);
bool soyokaze_h3_frame_type_known(uint64_t code);
size_t soyokaze_h3_reserved_frame_count(void);
int64_t soyokaze_h3_reserved_frame(size_t index);
soyokaze_h3_frame_t *soyokaze_h3_frame_data(const uint8_t *data, size_t data_len);
soyokaze_h3_frame_t *soyokaze_h3_frame_headers(const uint8_t *block, size_t block_len);
soyokaze_h3_frame_t *soyokaze_h3_frame_cancel_push(uint64_t push_id);
soyokaze_h3_frame_t *soyokaze_h3_frame_settings(const soyokaze_h3_parameter_t *params, size_t count);
soyokaze_h3_frame_t *soyokaze_h3_frame_push_promise(uint64_t push_id, const uint8_t *block, size_t block_len);
soyokaze_h3_frame_t *soyokaze_h3_frame_goaway(uint64_t id);
soyokaze_h3_frame_t *soyokaze_h3_frame_max_push_id(uint64_t push_id);
void soyokaze_h3_frame_free(soyokaze_h3_frame_t *frame);
soyokaze_h3_frame_kind_t soyokaze_h3_frame_kind(const soyokaze_h3_frame_t *frame);
soyokaze_slice_t soyokaze_h3_frame_bytes(const soyokaze_h3_frame_t *frame);
int64_t soyokaze_h3_frame_id(const soyokaze_h3_frame_t *frame);
size_t soyokaze_h3_frame_parameter_count(const soyokaze_h3_frame_t *frame);
soyokaze_h3_parameter_t soyokaze_h3_frame_parameter(const soyokaze_h3_frame_t *frame, size_t index);
size_t soyokaze_h3_frame_payload_len(const soyokaze_h3_frame_t *frame);
soyokaze_buffer_t soyokaze_h3_frame_encode(const soyokaze_h3_frame_t *frame);
soyokaze_buffer_t soyokaze_h3_frame_payload(const soyokaze_h3_frame_t *frame);
soyokaze_status_t soyokaze_h3_frame_decode(const uint8_t *data, size_t data_len,
                                           soyokaze_h3_frame_t **out, size_t *read,
                                           soyokaze_error_t **error);
soyokaze_h3_settings_t soyokaze_h3_settings_default(void);
soyokaze_h3_settings_t soyokaze_h3_settings_peer(void);
size_t soyokaze_h3_settings_parameter_count(const soyokaze_h3_settings_t *settings);
soyokaze_h3_parameter_t soyokaze_h3_settings_parameter(const soyokaze_h3_settings_t *settings, size_t index);
soyokaze_status_t soyokaze_h3_settings_apply(soyokaze_h3_settings_t *settings, uint64_t id, uint64_t value,
                                             soyokaze_error_t **error);
uint64_t soyokaze_h3_setting_qpack_max_table_capacity(void);
uint64_t soyokaze_h3_setting_max_field_section_size(void);
uint64_t soyokaze_h3_setting_qpack_blocked_streams(void);
uint64_t soyokaze_h3_setting_enable_connect_protocol(void);
size_t soyokaze_h3_reserved_setting_count(void);
int64_t soyokaze_h3_reserved_setting(size_t index);
soyokaze_slice_t soyokaze_h3_error_code_name(uint64_t code);

/* ----------------------------------------------------------------- helpers */

/* --- text. The compact string the crate holds field names and values in.
 * Text goes in as a pointer and a length everywhere else, so a C caller rarely
 * needs one; the crate's own surface is written in terms of it, so it crosses
 * whole. */
size_t soyokaze_text_inline(void);
soyokaze_text_t *soyokaze_text_new(void);
soyokaze_text_t *soyokaze_text_from_utf8(const uint8_t *data, size_t data_len);
soyokaze_text_t *soyokaze_text_from_utf8_lossy(const uint8_t *data, size_t data_len);
soyokaze_text_t *soyokaze_text_from_ascii(const uint8_t *data, size_t data_len);
soyokaze_text_t *soyokaze_text_from_ascii_lowercase(const uint8_t *data, size_t data_len);
bool soyokaze_text_copy_inline(const uint8_t *data, size_t data_len, uint8_t *out);
/* The caller promises every octet is ASCII; anything else is undefined. */
soyokaze_text_t *soyokaze_text_from_verified_ascii(const uint8_t *data, size_t data_len);
soyokaze_text_t *soyokaze_text_from_verified_ascii_lowercase(const uint8_t *data, size_t data_len);
void soyokaze_text_free(soyokaze_text_t *text);
soyokaze_slice_t soyokaze_text_bytes(const soyokaze_text_t *text);
size_t soyokaze_text_len(const soyokaze_text_t *text);
bool soyokaze_text_is_empty(const soyokaze_text_t *text);
bool soyokaze_text_is_inline(const soyokaze_text_t *text);
bool soyokaze_text_make_ascii_lowercase(soyokaze_text_t *text);
/* Consumes `text`. */
soyokaze_buffer_t soyokaze_text_into_bytes(soyokaze_text_t *text);
bool soyokaze_text_equals(const soyokaze_text_t *text, const soyokaze_text_t *other);
int32_t soyokaze_text_compare(const soyokaze_text_t *text, const soyokaze_text_t *other);

/* --- scan. The word-at-a-time primitives the parsers are built out of. */
size_t soyokaze_scan_lanes(void);
uint64_t soyokaze_scan_low(void);
uint64_t soyokaze_scan_high(void);
uint64_t soyokaze_scan_holds_zero(uint64_t word);
uint64_t soyokaze_scan_holds_less(uint64_t word, uint64_t bound);
uint64_t soyokaze_scan_marks_zero(uint64_t word);
uint64_t soyokaze_scan_word_at(const uint8_t *data, size_t data_len, size_t offset);
/* -1 when the needle does not appear. */
ptrdiff_t soyokaze_scan_find(const uint8_t *data, size_t data_len, uint8_t needle);
bool soyokaze_scan_copy(uint8_t *destination, size_t destination_len,
                        const uint8_t *source, size_t source_len);
bool soyokaze_scan_same(const uint8_t *left, size_t left_len,
                        const uint8_t *right, size_t right_len);
uint8_t soyokaze_scan_value_control(void);
uint8_t soyokaze_scan_value_obs_text(void);
uint8_t soyokaze_scan_classify_field_value(const uint8_t *data, size_t data_len);
bool soyokaze_scan_is_field_value(const uint8_t *data, size_t data_len);
/* `table` is 256 octets. */
bool soyokaze_scan_all_in_class(const uint8_t *data, size_t data_len, const uint8_t *table, uint8_t mask);

/* --- sync. What a timeout in seconds means, as the soyokaze_limits_t fields
 * describe it. Zero, negative and non-finite values all disable the timeout. */
bool soyokaze_timeout_armed(double seconds);
/* -1 when the timeout arms no deadline. */
int64_t soyokaze_timeout_nanos(double seconds);
soyokaze_buffer_t soyokaze_elapsed_message(double seconds);
soyokaze_status_t soyokaze_elapsed_status(void);

/* --- compression. The content codings a message body may be carried in. */

/* The coding's token, as Content-Encoding spells it. Empty for
 * SOYOKAZE_COMPRESSION_AUTO, which names no coding, and for a code that names
 * none. Borrowed from the library. */
soyokaze_slice_t soyokaze_compression_name(int32_t compression);
/* The coding a token names, ignoring case. Never answers AUTO. */
int32_t soyokaze_compression_parse(const uint8_t *token, size_t token_len); /* -1 when none */

/* Every coding that names something, in the order one is preferred over the
 * next, and that list written as an Accept-Encoding value. */
size_t soyokaze_compression_count(void);
int32_t soyokaze_compression_coding(size_t index); /* -1 past the end */
soyokaze_slice_t soyokaze_compression_accepted_field(void);

/* What a field section says about coding: the best coding its Accept-Encoding
 * permits, the coding its Content-Encoding applied, and whether the body is
 * coded at all -- which stays true for a coding this library does not decode. */
int32_t soyokaze_compression_accepted(const soyokaze_headers_t *headers); /* -1 when none */
int32_t soyokaze_compression_applied(const soyokaze_headers_t *headers); /* -1 when none */
bool soyokaze_compression_encoded(const soyokaze_headers_t *headers);

/* The quality one entry of a coding list carries; an entry with no q parameter
 * is fully acceptable and reads as 1. -1 when the entry is unreadable. */
float soyokaze_compression_quality(const uint8_t *entry, size_t entry_len);

/* The quality a qvalue text names on its own, as RFC 9110 12.4.2 writes one.
 * -1 when the text is outside that grammar. */
float soyokaze_compression_qvalue(const uint8_t *text, size_t text_len);

/* Codes octets, and undoes it. Encoding refuses SOYOKAZE_COMPRESSION_AUTO,
 * which names no coding. Decoding produces at most `max` octets; passing it is
 * SOYOKAZE_STATUS_LIMIT and produces nothing. Free `out` with
 * soyokaze_buffer_free. */
soyokaze_status_t soyokaze_compression_encode(int32_t compression,
                                              const uint8_t *data, size_t data_len,
                                              soyokaze_buffer_t *out, soyokaze_error_t **error);
soyokaze_status_t soyokaze_compression_decode(int32_t compression,
                                              const uint8_t *data, size_t data_len, uint64_t max,
                                              soyokaze_buffer_t *out, soyokaze_error_t **error);

/* --- base64. The standard alphabet, always padded, decoded strictly. */

/* Why a base64 string would not decode. SOYOKAZE_BASE64_INVALID_LENGTH and
 * SOYOKAZE_BASE64_INVALID_SYMBOL write the length or the symbol through the
 * `detail` out parameter. */
typedef enum {
    SOYOKAZE_BASE64_OK = 0,
    SOYOKAZE_BASE64_INVALID_LENGTH = 1,
    SOYOKAZE_BASE64_INVALID_SYMBOL = 2,
    SOYOKAZE_BASE64_INVALID_PADDING = 3,
    SOYOKAZE_BASE64_INVALID = 4
} soyokaze_base64_error_t;

soyokaze_slice_t soyokaze_base64_error_message(soyokaze_base64_error_t error);
/* Always 64 octets. */
soyokaze_slice_t soyokaze_base64_alphabet(void);
uint8_t soyokaze_base64_pad(void);
uint8_t soyokaze_base64_invalid(void);
/* Always 256 octets. */
soyokaze_slice_t soyokaze_base64_values(void);
uint8_t soyokaze_base64_symbol(uint8_t value);
/* -1 when the symbol is outside the alphabet. */
int32_t soyokaze_base64_value(uint8_t symbol);
size_t soyokaze_base64_encoded_len(const uint8_t *data, size_t data_len);
bool soyokaze_base64_sextets(const uint8_t *group, size_t group_len, uint32_t *out,
                             soyokaze_base64_error_t *error, uint64_t *detail);
soyokaze_buffer_t soyokaze_base64_encode(const uint8_t *data, size_t data_len);
bool soyokaze_base64_decode(const uint8_t *text, size_t text_len, soyokaze_buffer_t *out,
                            soyokaze_base64_error_t *error, uint64_t *detail);

/* --- sha1. Here because the WebSocket handshake needs it; not a
 * general-purpose hash to build anything new on. */
size_t soyokaze_sha1_block_size(void);
size_t soyokaze_sha1_digest_size(void);
/* Five words. */
const uint32_t *soyokaze_sha1_initial_state(void);
/* Four words. */
const uint32_t *soyokaze_sha1_constants(void);
/* Always 20 octets. */
soyokaze_buffer_t soyokaze_sha1(const uint8_t *data, size_t data_len);
soyokaze_sha1_t *soyokaze_sha1_new(void);
void soyokaze_sha1_free(soyokaze_sha1_t *hash);
bool soyokaze_sha1_update(soyokaze_sha1_t *hash, const uint8_t *data, size_t data_len);
/* `block` is exactly soyokaze_sha1_block_size() octets, and its length is not
 * counted towards the padding; soyokaze_sha1_update is what an ordinary caller
 * wants. */
bool soyokaze_sha1_compress(soyokaze_sha1_t *hash, const uint8_t *block, size_t block_len);
/* Consumes `hash`. */
bool soyokaze_sha1_finish(soyokaze_sha1_t *hash, soyokaze_buffer_t *out);

/* --- huffman. One code serves both compression formats. */

typedef enum {
    SOYOKAZE_HUFFMAN_OK = 0,
    SOYOKAZE_HUFFMAN_INVALID_PADDING = 1,
    SOYOKAZE_HUFFMAN_UNKNOWN_SYMBOL = 2,
    SOYOKAZE_HUFFMAN_INVALID = 3
} soyokaze_huffman_error_t;

/* One code word: `length` bits, right-aligned in `code`. */
typedef struct {
    uint32_t code;
    uint8_t length;
} soyokaze_huffman_symbol_t;

/* One step of the decoding automaton, for one state and one four-bit input.
 * `flags` is the or of soyokaze_huffman_emit(), soyokaze_huffman_fail() and
 * soyokaze_huffman_ended(). */
typedef struct {
    uint16_t next;
    uint8_t symbol;
    uint8_t flags;
} soyokaze_huffman_transition_t;

/* What following one bit out of a node reaches. */
typedef enum {
    SOYOKAZE_HUFFMAN_BRANCH_NONE = 0,
    SOYOKAZE_HUFFMAN_BRANCH_NODE = 1,
    SOYOKAZE_HUFFMAN_BRANCH_SYMBOL = 2
} soyokaze_huffman_branch_t;

soyokaze_slice_t soyokaze_huffman_error_message(soyokaze_huffman_error_t error);
uint16_t soyokaze_huffman_eos(void);
size_t soyokaze_huffman_table_len(void);
soyokaze_huffman_symbol_t soyokaze_huffman_symbol(size_t index);
uint8_t soyokaze_huffman_length(size_t index);
size_t soyokaze_huffman_nibble(void);
uint8_t soyokaze_huffman_emit(void);
uint8_t soyokaze_huffman_fail(void);
uint8_t soyokaze_huffman_ended(void);
size_t soyokaze_huffman_states(void);
size_t soyokaze_huffman_nodes(void);
soyokaze_huffman_transition_t soyokaze_huffman_transition(size_t state, uint8_t nibble);
bool soyokaze_huffman_accepting(size_t state);
soyokaze_huffman_branch_t soyokaze_huffman_step(size_t node, bool bit, uint32_t *value);
size_t soyokaze_huffman_encoded_len(const uint8_t *data, size_t data_len);
soyokaze_buffer_t soyokaze_huffman_encode(const uint8_t *data, size_t data_len);
bool soyokaze_huffman_decode(const uint8_t *data, size_t data_len, soyokaze_buffer_t *out,
                             soyokaze_huffman_error_t *error);
bool soyokaze_huffman_decode_ascii(const uint8_t *data, size_t data_len, soyokaze_buffer_t *out,
                                   bool *ascii, soyokaze_huffman_error_t *error);

/* --- fields. The vocabulary HPACK and QPACK share. One field goes into an
 * encoder as a soyokaze_field_t; a decoded section comes back out as a
 * soyokaze_fields_t. */

typedef enum {
    SOYOKAZE_FIELDS_OK = 0,
    SOYOKAZE_FIELDS_INTEGER_OVERFLOW = 1,
    SOYOKAZE_FIELDS_INCOMPLETE = 2,
    SOYOKAZE_FIELDS_HUFFMAN_INVALID_PADDING = 3,
    SOYOKAZE_FIELDS_HUFFMAN_UNKNOWN_SYMBOL = 4,
    SOYOKAZE_FIELDS_INVALID = 5
} soyokaze_fields_error_t;

typedef struct {
    soyokaze_slice_t name;
    soyokaze_slice_t value;
} soyokaze_field_t;

soyokaze_slice_t soyokaze_fields_error_message(soyokaze_fields_error_t error);
size_t soyokaze_field_overhead(void);
size_t soyokaze_field_sensitive_count(void);
soyokaze_slice_t soyokaze_field_sensitive_name(size_t index);
size_t soyokaze_field_size(const uint8_t *name, size_t name_len,
                           const uint8_t *value, size_t value_len);
bool soyokaze_field_is_sensitive(const uint8_t *name, size_t name_len);
soyokaze_fields_t *soyokaze_fields_new(void);
bool soyokaze_fields_append(soyokaze_fields_t *fields,
                            const uint8_t *name, size_t name_len,
                            const uint8_t *value, size_t value_len);
void soyokaze_fields_free(soyokaze_fields_t *fields);
size_t soyokaze_fields_count(const soyokaze_fields_t *fields);
soyokaze_slice_t soyokaze_fields_name(const soyokaze_fields_t *fields, size_t index);
soyokaze_slice_t soyokaze_fields_value(const soyokaze_fields_t *fields, size_t index);

/* The prefixed integer and the string literal both formats are built out of. */
uint64_t soyokaze_integer_limit(uint8_t prefix_bits);
soyokaze_buffer_t soyokaze_integer_encode(uint64_t value, uint8_t prefix_bits, uint8_t flags);
bool soyokaze_integer_decode(const uint8_t *data, size_t data_len, uint8_t prefix_bits,
                             uint64_t *out, size_t *read, soyokaze_fields_error_t *error);
bool soyokaze_string_prefers_huffman(const uint8_t *data, size_t data_len);

/* The bit just above a string literal's prefix carries the Huffman mark, so a
 * `prefix_bits` past `soyokaze_string_max_prefix_bits()` names no
 * representation. The encoders answer with an empty buffer and the decoder
 * with SOYOKAZE_FIELDS_INVALID. */
uint8_t soyokaze_string_max_prefix_bits(void);
soyokaze_buffer_t soyokaze_string_encode(const uint8_t *data, size_t data_len,
                                         uint8_t prefix_bits, uint8_t flags, bool huffman);
soyokaze_buffer_t soyokaze_string_encode_shorter(const uint8_t *data, size_t data_len,
                                                 uint8_t prefix_bits, uint8_t flags);
bool soyokaze_string_decode(const uint8_t *data, size_t data_len, uint8_t prefix_bits,
                            soyokaze_buffer_t *out, size_t *read, soyokaze_fields_error_t *error);

/* A reverse index over a static table, borrowed from the library and never
 * freed. `name_index` and `exact` come back -1 when there is none. */
bool soyokaze_static_index_lookup(const soyokaze_static_index_t *index,
                                  const uint8_t *name, size_t name_len,
                                  const uint8_t *value, size_t value_len,
                                  int64_t *name_index, int64_t *exact);

/* --- hpack. An encoder and a decoder are stateful; feed blocks in order.
 * Indices are the wire ones, numbered from soyokaze_hpack_static_base(). */
size_t soyokaze_hpack_default_capacity(void);
size_t soyokaze_hpack_default_capacity_limit(void);
size_t soyokaze_hpack_default_max_decoded_size(void);
size_t soyokaze_hpack_static_count(void);
size_t soyokaze_hpack_static_base(void);
soyokaze_slice_t soyokaze_hpack_static_name(size_t index);
soyokaze_slice_t soyokaze_hpack_static_value(size_t index);
const soyokaze_static_index_t *soyokaze_hpack_static_index(void);
bool soyokaze_hpack_static_find(const uint8_t *name, size_t name_len,
                                const uint8_t *value, size_t value_len,
                                size_t *out, bool *exact);
size_t soyokaze_hpack_table_size(const soyokaze_hpack_table_t *table);
size_t soyokaze_hpack_table_capacity(const soyokaze_hpack_table_t *table);
size_t soyokaze_hpack_table_len(const soyokaze_hpack_table_t *table);
bool soyokaze_hpack_table_is_empty(const soyokaze_hpack_table_t *table);
soyokaze_slice_t soyokaze_hpack_table_name(const soyokaze_hpack_table_t *table, size_t index);
soyokaze_slice_t soyokaze_hpack_table_value(const soyokaze_hpack_table_t *table, size_t index);
bool soyokaze_hpack_table_find(const soyokaze_hpack_table_t *table,
                               const uint8_t *name, size_t name_len,
                               const uint8_t *value, size_t value_len,
                               size_t *out, bool *exact);
soyokaze_hpack_encoder_t *soyokaze_hpack_encoder_new(void);
void soyokaze_hpack_encoder_free(soyokaze_hpack_encoder_t *encoder);
bool soyokaze_hpack_encoder_set_max_capacity(soyokaze_hpack_encoder_t *encoder, size_t max_capacity);
bool soyokaze_hpack_encoder_set_capacity_limit(soyokaze_hpack_encoder_t *encoder, size_t capacity_limit);
size_t soyokaze_hpack_encoder_capacity_limit(const soyokaze_hpack_encoder_t *encoder);
size_t soyokaze_hpack_encoder_max_capacity(const soyokaze_hpack_encoder_t *encoder);
const soyokaze_hpack_table_t *soyokaze_hpack_encoder_table(const soyokaze_hpack_encoder_t *encoder);
bool soyokaze_hpack_encoder_reference(const soyokaze_hpack_encoder_t *encoder,
                                      const uint8_t *name, size_t name_len,
                                      const uint8_t *value, size_t value_len,
                                      size_t *out, bool *exact);
soyokaze_buffer_t soyokaze_hpack_encode(soyokaze_hpack_encoder_t *encoder,
                                        const soyokaze_field_t *fields, size_t field_count);
soyokaze_buffer_t soyokaze_hpack_encode_field(soyokaze_hpack_encoder_t *encoder,
                                              const uint8_t *name, size_t name_len,
                                              const uint8_t *value, size_t value_len);
soyokaze_hpack_decoder_t *soyokaze_hpack_decoder_new(void);
void soyokaze_hpack_decoder_free(soyokaze_hpack_decoder_t *decoder);
bool soyokaze_hpack_decoder_set_max_decoded_size(soyokaze_hpack_decoder_t *decoder, size_t max_size);
bool soyokaze_hpack_decoder_set_max_capacity(soyokaze_hpack_decoder_t *decoder, size_t max_capacity);
const soyokaze_hpack_table_t *soyokaze_hpack_decoder_table(const soyokaze_hpack_decoder_t *decoder);
bool soyokaze_hpack_decoder_resolve(const soyokaze_hpack_decoder_t *decoder, uint64_t index,
                                    soyokaze_slice_t *name, soyokaze_slice_t *value);
soyokaze_status_t soyokaze_hpack_decode(soyokaze_hpack_decoder_t *decoder,
                                        const uint8_t *block, size_t block_len,
                                        soyokaze_fields_t **out,
                                        soyokaze_error_t **error);

/* --- qpack. Instruction streams cross either as raw octets, exactly as they
 * travel, or one instruction at a time as a handle. Indices into the static
 * table are numbered from soyokaze_qpack_static_base(); indices into a dynamic
 * table are absolute unless the call says otherwise. */

typedef enum {
    SOYOKAZE_QPACK_SET_DYNAMIC_TABLE_CAPACITY = 0,
    SOYOKAZE_QPACK_INSERT_WITH_NAME_REFERENCE = 1,
    SOYOKAZE_QPACK_INSERT_WITH_LITERAL_NAME = 2,
    SOYOKAZE_QPACK_DUPLICATE = 3
} soyokaze_qpack_encoder_instruction_kind_t;

typedef enum {
    SOYOKAZE_QPACK_SECTION_ACKNOWLEDGMENT = 0,
    SOYOKAZE_QPACK_STREAM_CANCELLATION = 1,
    SOYOKAZE_QPACK_INSERT_COUNT_INCREMENT = 2
} soyokaze_qpack_decoder_instruction_kind_t;

size_t soyokaze_qpack_default_capacity(void);
size_t soyokaze_qpack_default_capacity_limit(void);
size_t soyokaze_qpack_default_max_outstanding_sections(void);
size_t soyokaze_qpack_default_max_instruction_size(void);
size_t soyokaze_qpack_default_idle_capacity(void);
size_t soyokaze_qpack_default_max_capacity(void);
size_t soyokaze_qpack_default_max_decoded_size(void);
size_t soyokaze_qpack_default_max_blocked_streams(void);
size_t soyokaze_qpack_static_count(void);
size_t soyokaze_qpack_static_base(void);
soyokaze_slice_t soyokaze_qpack_static_name(size_t index);
soyokaze_slice_t soyokaze_qpack_static_value(size_t index);
const soyokaze_static_index_t *soyokaze_qpack_static_index(void);
bool soyokaze_qpack_static_find(const uint8_t *name, size_t name_len,
                                const uint8_t *value, size_t value_len,
                                uint64_t *out, bool *exact);
size_t soyokaze_qpack_table_size(const soyokaze_qpack_table_t *table);
size_t soyokaze_qpack_table_capacity(const soyokaze_qpack_table_t *table);
size_t soyokaze_qpack_table_len(const soyokaze_qpack_table_t *table);
bool soyokaze_qpack_table_is_empty(const soyokaze_qpack_table_t *table);
uint64_t soyokaze_qpack_table_inserted_count(const soyokaze_qpack_table_t *table);
soyokaze_slice_t soyokaze_qpack_table_name(const soyokaze_qpack_table_t *table, uint64_t absolute_index);
soyokaze_slice_t soyokaze_qpack_table_value(const soyokaze_qpack_table_t *table, uint64_t absolute_index);
bool soyokaze_qpack_table_fits(const soyokaze_qpack_table_t *table,
                               const uint8_t *name, size_t name_len,
                               const uint8_t *value, size_t value_len);
/* -1 when the index names no live entry. */
int64_t soyokaze_qpack_table_relative(const soyokaze_qpack_table_t *table, uint64_t index);
int64_t soyokaze_qpack_table_indexed(const soyokaze_qpack_table_t *table, uint64_t base, uint64_t index);
int64_t soyokaze_qpack_table_post_base(const soyokaze_qpack_table_t *table, uint64_t base, uint64_t index);
bool soyokaze_qpack_table_find(const soyokaze_qpack_table_t *table,
                               const uint8_t *name, size_t name_len,
                               const uint8_t *value, size_t value_len,
                               uint64_t *out, bool *exact);
bool soyokaze_qpack_table_probe(const soyokaze_qpack_table_t *table,
                                const uint8_t *name, size_t name_len,
                                const uint8_t *value, size_t value_len, uint64_t below,
                                uint64_t *out, bool *exact, bool *blocked);

uint64_t soyokaze_qpack_prefix_max_entries(size_t max_capacity);
uint64_t soyokaze_qpack_prefix_relative(uint64_t base, uint64_t absolute);
uint64_t soyokaze_qpack_prefix_encode_insert_count(uint64_t required, size_t max_capacity);
bool soyokaze_qpack_prefix_decode_insert_count(uint64_t encoded, uint64_t inserted,
                                               size_t max_capacity, uint64_t *out);

soyokaze_qpack_encoder_instruction_t *soyokaze_qpack_encoder_instruction_set_capacity(size_t capacity);
soyokaze_qpack_encoder_instruction_t *soyokaze_qpack_encoder_instruction_insert_with_name_reference(
    bool from_static, uint64_t name_index, const uint8_t *value, size_t value_len);
soyokaze_qpack_encoder_instruction_t *soyokaze_qpack_encoder_instruction_insert_with_literal_name(
    const uint8_t *name, size_t name_len, const uint8_t *value, size_t value_len);
soyokaze_qpack_encoder_instruction_t *soyokaze_qpack_encoder_instruction_duplicate(uint64_t index);
void soyokaze_qpack_encoder_instruction_free(soyokaze_qpack_encoder_instruction_t *instruction);
soyokaze_qpack_encoder_instruction_kind_t soyokaze_qpack_encoder_instruction_kind(
    const soyokaze_qpack_encoder_instruction_t *instruction);
size_t soyokaze_qpack_encoder_instruction_capacity(const soyokaze_qpack_encoder_instruction_t *instruction);
bool soyokaze_qpack_encoder_instruction_from_static(const soyokaze_qpack_encoder_instruction_t *instruction);
uint64_t soyokaze_qpack_encoder_instruction_index(const soyokaze_qpack_encoder_instruction_t *instruction);
soyokaze_slice_t soyokaze_qpack_encoder_instruction_name(const soyokaze_qpack_encoder_instruction_t *instruction);
soyokaze_slice_t soyokaze_qpack_encoder_instruction_value(const soyokaze_qpack_encoder_instruction_t *instruction);
soyokaze_buffer_t soyokaze_qpack_encoder_instruction_encode(const soyokaze_qpack_encoder_instruction_t *instruction);
soyokaze_status_t soyokaze_qpack_encoder_instruction_decode(const uint8_t *data, size_t data_len,
                                                            soyokaze_qpack_encoder_instruction_t **out,
                                                            size_t *read, soyokaze_error_t **error);

soyokaze_qpack_decoder_instruction_t *soyokaze_qpack_decoder_instruction_section_acknowledgment(uint64_t stream_id);
soyokaze_qpack_decoder_instruction_t *soyokaze_qpack_decoder_instruction_stream_cancellation(uint64_t stream_id);
soyokaze_qpack_decoder_instruction_t *soyokaze_qpack_decoder_instruction_insert_count_increment(uint64_t increment);
void soyokaze_qpack_decoder_instruction_free(soyokaze_qpack_decoder_instruction_t *instruction);
soyokaze_qpack_decoder_instruction_kind_t soyokaze_qpack_decoder_instruction_kind(
    const soyokaze_qpack_decoder_instruction_t *instruction);
uint64_t soyokaze_qpack_decoder_instruction_stream_id(const soyokaze_qpack_decoder_instruction_t *instruction);
uint64_t soyokaze_qpack_decoder_instruction_increment(const soyokaze_qpack_decoder_instruction_t *instruction);
soyokaze_buffer_t soyokaze_qpack_decoder_instruction_encode(const soyokaze_qpack_decoder_instruction_t *instruction);
soyokaze_status_t soyokaze_qpack_decoder_instruction_decode(const uint8_t *data, size_t data_len,
                                                            soyokaze_qpack_decoder_instruction_t **out,
                                                            size_t *read, soyokaze_error_t **error);

soyokaze_qpack_encoder_t *soyokaze_qpack_encoder_new(void);
void soyokaze_qpack_encoder_free(soyokaze_qpack_encoder_t *encoder);
bool soyokaze_qpack_encoder_set_max_capacity(soyokaze_qpack_encoder_t *encoder, size_t max_capacity,
                                             soyokaze_buffer_t *instructions);
bool soyokaze_qpack_encoder_set_capacity_limit(soyokaze_qpack_encoder_t *encoder, size_t capacity_limit,
                                               soyokaze_buffer_t *instructions);
bool soyokaze_qpack_encoder_set_max_outstanding_sections(soyokaze_qpack_encoder_t *encoder, size_t max_sections);
bool soyokaze_qpack_encoder_set_max_instruction_size(soyokaze_qpack_encoder_t *encoder, size_t max_size);
bool soyokaze_qpack_encoder_set_idle_capacity(soyokaze_qpack_encoder_t *encoder, size_t idle_capacity);
size_t soyokaze_qpack_encoder_capacity_limit(const soyokaze_qpack_encoder_t *encoder);
size_t soyokaze_qpack_encoder_max_capacity(const soyokaze_qpack_encoder_t *encoder);
size_t soyokaze_qpack_encoder_outstanding(const soyokaze_qpack_encoder_t *encoder);
uint64_t soyokaze_qpack_encoder_known_received_count(const soyokaze_qpack_encoder_t *encoder);
const soyokaze_qpack_table_t *soyokaze_qpack_encoder_table(const soyokaze_qpack_encoder_t *encoder);
bool soyokaze_qpack_encoder_reference(const soyokaze_qpack_encoder_t *encoder,
                                      const uint8_t *name, size_t name_len,
                                      const uint8_t *value, size_t value_len,
                                      bool *from_static, uint64_t *out, bool *exact);
/* Consumes every instruction in `instructions`. */
bool soyokaze_qpack_encoder_queue(soyokaze_qpack_encoder_t *encoder,
                                  soyokaze_qpack_encoder_instruction_t **instructions, size_t count);
soyokaze_slice_t soyokaze_qpack_encoder_stream(const soyokaze_qpack_encoder_t *encoder);
soyokaze_buffer_t soyokaze_qpack_encoder_take_stream(soyokaze_qpack_encoder_t *encoder);
/* Consumes `buffer`. */
bool soyokaze_qpack_encoder_reclaim_stream(soyokaze_qpack_encoder_t *encoder, soyokaze_buffer_t buffer);
bool soyokaze_qpack_encode(soyokaze_qpack_encoder_t *encoder, uint64_t stream_id,
                           const soyokaze_field_t *fields, size_t field_count,
                           soyokaze_buffer_t *block, soyokaze_buffer_t *instructions);
soyokaze_status_t soyokaze_qpack_encoder_on_decoder_instructions(soyokaze_qpack_encoder_t *encoder,
                                                                 const uint8_t *data, size_t data_len,
                                                                 soyokaze_error_t **error);
/* Consumes `instruction`. */
bool soyokaze_qpack_encoder_on_decoder_instruction(soyokaze_qpack_encoder_t *encoder,
                                                   soyokaze_qpack_decoder_instruction_t *instruction);
bool soyokaze_qpack_encoder_cancel(soyokaze_qpack_encoder_t *encoder, uint64_t stream_id);

soyokaze_qpack_decoder_t *soyokaze_qpack_decoder_new(void);
void soyokaze_qpack_decoder_free(soyokaze_qpack_decoder_t *decoder);
bool soyokaze_qpack_decoder_set_max_decoded_size(soyokaze_qpack_decoder_t *decoder, size_t max_size);
bool soyokaze_qpack_decoder_set_max_capacity(soyokaze_qpack_decoder_t *decoder, size_t max_capacity);
bool soyokaze_qpack_decoder_set_max_instruction_size(soyokaze_qpack_decoder_t *decoder, size_t max_size);
bool soyokaze_qpack_decoder_set_max_blocked_streams(soyokaze_qpack_decoder_t *decoder, size_t max_streams);
bool soyokaze_qpack_decoder_set_idle_capacity(soyokaze_qpack_decoder_t *decoder, size_t idle_capacity);
size_t soyokaze_qpack_decoder_blocked(const soyokaze_qpack_decoder_t *decoder);
/* One stream identifier per eight octets, in native order. */
soyokaze_buffer_t soyokaze_qpack_decoder_unblocked(const soyokaze_qpack_decoder_t *decoder);
bool soyokaze_qpack_decoder_cancel(soyokaze_qpack_decoder_t *decoder, uint64_t stream_id);
const soyokaze_qpack_table_t *soyokaze_qpack_decoder_table(const soyokaze_qpack_decoder_t *decoder);
bool soyokaze_qpack_decoder_resolve(const soyokaze_qpack_decoder_t *decoder, bool from_static,
                                    uint64_t base, uint64_t index,
                                    soyokaze_buffer_t *name, soyokaze_buffer_t *value);
soyokaze_buffer_t soyokaze_qpack_decoder_resolve_name(const soyokaze_qpack_decoder_t *decoder, bool from_static,
                                                      uint64_t base, uint64_t index);
/* Consumes every instruction in `instructions`. */
bool soyokaze_qpack_decoder_queue(soyokaze_qpack_decoder_t *decoder,
                                  soyokaze_qpack_decoder_instruction_t **instructions, size_t count);
soyokaze_slice_t soyokaze_qpack_decoder_stream(const soyokaze_qpack_decoder_t *decoder);
soyokaze_buffer_t soyokaze_qpack_decoder_take_stream(soyokaze_qpack_decoder_t *decoder);
/* Consumes `buffer`. */
bool soyokaze_qpack_decoder_reclaim_stream(soyokaze_qpack_decoder_t *decoder, soyokaze_buffer_t buffer);
soyokaze_status_t soyokaze_qpack_decoder_on_encoder_instructions(soyokaze_qpack_decoder_t *decoder,
                                                                 const uint8_t *data, size_t data_len,
                                                                 soyokaze_buffer_t *instructions,
                                                                 soyokaze_error_t **error);
/* Consumes `instruction`. `out` is left NULL when the decoder owes nothing. */
soyokaze_status_t soyokaze_qpack_decoder_on_encoder_instruction(soyokaze_qpack_decoder_t *decoder,
                                                                soyokaze_qpack_encoder_instruction_t *instruction,
                                                                soyokaze_qpack_decoder_instruction_t **out,
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
