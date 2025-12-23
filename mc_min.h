#pragma once

// --- mc_types.h ---
typedef unsigned long      mc_usize;
typedef long               mc_isize;
typedef unsigned long long mc_u64;
typedef long long          mc_i64;
typedef unsigned int       mc_u32;
typedef int                mc_i32;
typedef unsigned short     mc_u16;
typedef short              mc_i16;
typedef unsigned char      mc_u8;
typedef signed char        mc_i8;
typedef long               mc_intptr;
typedef unsigned long      mc_uintptr;
typedef int mc_bool;
#define mc_true 1
#define mc_false 0
#define MC_NULL ((void *)0)

// --- mc_syscall.h ---
#define MC_SYS_read 0
#define MC_SYS_write 1
#define MC_SYS_openat 257
#define MC_SYS_close 3
#define MC_SYS_getrandom 318
#define MC_SYS_exit 60
#define MC_SYS_socket 41
#define MC_SYS_connect 42
#define MC_SYS_sendto 44
#define MC_SYS_recvfrom 45
#define MC_SYS_poll 7
#define MC_SYS_fcntl 72
#define MC_SYS_clock_gettime 228
#define MC_SYS_getsockopt 55

#define MC_AT_FDCWD (-100)
#define MC_O_RDONLY 0
#define MC_O_CLOEXEC 02000000
#define MC_CLOCK_MONOTONIC 1

#define MC_F_GETFL 3
#define MC_F_SETFL 4
#define MC_O_NONBLOCK 00004000

#define MC_EINVAL 22
#define MC_EINPROGRESS 115

struct mc_pollfd {
	mc_i32 fd;
	mc_i16 events;
	mc_i16 revents;
};
#define MC_POLLIN 0x0001
#define MC_POLLOUT 0x0004
#define MC_POLLERR 0x0008
#define MC_POLLHUP 0x0010

struct mc_timespec {
    mc_i64 tv_sec;
    mc_i64 tv_nsec;
};

static inline mc_i64 mc_syscall1(mc_i64 n, mc_i64 a1) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
	return ret;
}
static inline mc_i64 mc_syscall2(mc_i64 n, mc_i64 a1, mc_i64 a2) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
	return ret;
}
static inline mc_i64 mc_syscall3(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
	return ret;
}
static inline mc_i64 mc_syscall4(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4) {
	mc_i64 ret;
	register mc_i64 r10 __asm__("r10") = a4;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
	return ret;
}
static inline mc_i64 mc_syscall5(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5) {
    mc_i64 ret;
    register mc_i64 r10 __asm__("r10") = a4;
    register mc_i64 r8 __asm__("r8") = a5;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
    return ret;
}
static inline mc_i64 mc_syscall6(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5, mc_i64 a6) {
    mc_i64 ret;
    register mc_i64 r10 __asm__("r10") = a4;
    register mc_i64 r8 __asm__("r8") = a5;
    register mc_i64 r9 __asm__("r9") = a6;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}

// --- mc_net.h ---
#define MC_AF_INET6 10
#define MC_SOCK_STREAM 1
#define MC_SOCK_DGRAM 2
#define MC_SOCK_CLOEXEC 02000000
#define MC_IPPROTO_TCP 6
#define MC_IPPROTO_UDP 17
#define MC_SOL_SOCKET 1
#define MC_SO_ERROR 4

struct mc_in6_addr {
	mc_u8 s6_addr[16];
};
struct mc_sockaddr_in6 {
	mc_u16 sin6_family;
	mc_u16 sin6_port;
	mc_u32 sin6_flowinfo;
	struct mc_in6_addr sin6_addr;
	mc_u32 sin6_scope_id;
};

// --- mc.h ---
#define MC_NORETURN __attribute__((noreturn))
MC_NORETURN void mc_exit(mc_i32 code);
mc_usize mc_strlen(const char *s);
int mc_streq(const char *a, const char *b);
void *mc_memcpy(void *dst, const void *src, mc_usize n);
void *mc_memmove(void *dst, const void *src, mc_usize n);
void *mc_memset(void *dst, int c, mc_usize n);
int mc_memcmp(const void *a, const void *b, mc_usize n);
mc_i64 mc_write_str(mc_i32 fd, const char *s);
mc_i64 mc_write_all(mc_i32 fd, const void *buf, mc_usize len);
void mc_die_errno(const char *argv0, const char *ctx, mc_i64 err_neg);
#define MC_SYS_exit_group 231
#define MC_ENOENT 2
#define MC_ENOTDIR 20
#define MC_INLINE static inline __attribute__((always_inline))

typedef int (*mc_dirent_cb)(void *ctx, const char *name, mc_u8 d_type);

int mc_has_slash(const char *s);
const char *mc_getenv_kv(char **envp, const char *key_eq);
mc_i64 mc_for_each_dirent(mc_i32 dirfd, mc_dirent_cb cb, void *ctx);

mc_i64 mc_sys_execve(const char *pathname, char *const argv[], char *const envp[]);
mc_i64 mc_execvp(const char *file, char **argv, char **envp);
int mc_is_dot_or_dotdot(const char *name);

int mc_strcmp(const char *a, const char *b);
int mc_strncmp(const char *a, const char *b, mc_usize n);
char *mc_strchr(const char *s, int c);
char *mc_strrchr(const char *s, int c);
void mc_set_start_envp(char **envp);

#define MC_SYS_getdents64 217
struct mc_dirent64 {
	mc_u64 d_ino;
	mc_i64 d_off;
	mc_u16 d_reclen;
	mc_u8 d_type;
	char d_name[];
} __attribute__((packed));

static inline mc_i64 mc_sys_read(mc_i32 fd, void *buf, mc_usize len) {
	return mc_syscall3(MC_SYS_read, (mc_i64)fd, (mc_i64)buf, (mc_i64)len);
}
static inline mc_i64 mc_sys_getdents64(mc_i32 fd, void *dirp, mc_u32 count) {
	return mc_syscall3(MC_SYS_getdents64, (mc_i64)fd, (mc_i64)dirp, (mc_i64)count);
}
static inline mc_i64 mc_sys_write(mc_i32 fd, const void *buf, mc_usize len) {
	return mc_syscall3(MC_SYS_write, (mc_i64)fd, (mc_i64)buf, (mc_i64)len);
}
static inline mc_i64 mc_sys_getrandom(void *buf, mc_usize buflen, mc_u32 flags) {
    return mc_syscall3(MC_SYS_getrandom, (mc_i64)buf, (mc_i64)buflen, (mc_i64)flags);
}
static inline mc_i64 mc_sys_socket(mc_i32 domain, mc_i32 type, mc_i32 protocol) {
    return mc_syscall3(MC_SYS_socket, (mc_i64)domain, (mc_i64)type, (mc_i64)protocol);
}
static inline mc_i64 mc_sys_connect(mc_i32 sockfd, const void *addr, mc_u32 addrlen) {
    return mc_syscall3(MC_SYS_connect, (mc_i64)sockfd, (mc_i64)addr, (mc_i64)addrlen);
}
static inline mc_i64 mc_sys_sendto(mc_i32 sockfd, const void *buf, mc_usize len, mc_i32 flags, const void *dest_addr, mc_u32 addrlen) {
    return mc_syscall6(MC_SYS_sendto, (mc_i64)sockfd, (mc_i64)buf, (mc_i64)len, (mc_i64)flags, (mc_i64)dest_addr, (mc_i64)addrlen);
}
static inline mc_i64 mc_sys_recvfrom(mc_i32 sockfd, void *buf, mc_usize len, mc_i32 flags, void *src_addr, mc_u32 *addrlen_inout) {
    return mc_syscall6(MC_SYS_recvfrom, (mc_i64)sockfd, (mc_i64)buf, (mc_i64)len, (mc_i64)flags, (mc_i64)src_addr, (mc_i64)addrlen_inout);
}
static inline mc_i64 mc_sys_poll(void *fds, mc_u64 nfds, mc_i32 timeout_ms) {
    return mc_syscall3(MC_SYS_poll, (mc_i64)fds, (mc_i64)nfds, (mc_i64)timeout_ms);
}
static inline mc_i64 mc_sys_fcntl(mc_i32 fd, mc_i32 cmd, mc_i64 arg) {
    return mc_syscall3(MC_SYS_fcntl, (mc_i64)fd, (mc_i64)cmd, (mc_i64)arg);
}
static inline mc_i64 mc_sys_close(mc_i32 fd) {
    return mc_syscall1(MC_SYS_close, (mc_i64)fd);
}
static inline mc_i64 mc_sys_clock_gettime(mc_i32 clockid, struct mc_timespec *tp) {
    return mc_syscall2(MC_SYS_clock_gettime, (mc_i64)clockid, (mc_i64)tp);
}
static inline mc_i64 mc_sys_openat(mc_i32 dirfd, const char *path, mc_i32 flags, mc_u32 mode) {
    return mc_syscall4(MC_SYS_openat, (mc_i64)dirfd, (mc_i64)path, (mc_i64)flags, (mc_i64)mode);
}
static inline mc_i64 mc_sys_getsockopt(mc_i32 sockfd, mc_i32 level, mc_i32 optname, void *optval, mc_u32 *optlen_inout) {
    return mc_syscall5(MC_SYS_getsockopt, (mc_i64)sockfd, (mc_i64)level, (mc_i64)optname, (mc_i64)optval, (mc_i64)optlen_inout);
}

// --- mc_aes.h ---
#define MC_AES128_KEY_SIZE 16u
#define MC_AES128_BLOCK_SIZE 16u
#define MC_AES128_ROUNDS 10u
typedef struct {
	mc_u32 rk[44];
} mc_aes128_ctx;
void mc_aes128_init(mc_aes128_ctx *ctx, const mc_u8 key[MC_AES128_KEY_SIZE]);
void mc_aes128_encrypt_block(const mc_aes128_ctx *ctx, const mc_u8 in[MC_AES128_BLOCK_SIZE], mc_u8 out[MC_AES128_BLOCK_SIZE]);

// --- mc_sha256.h ---
#define MC_SHA256_BLOCK_SIZE 64u
#define MC_SHA256_DIGEST_SIZE 32u
typedef struct {
	mc_u32 state[8];
	mc_u64 count_bytes;
	mc_u8 buffer[MC_SHA256_BLOCK_SIZE];
	mc_u32 buffer_len;
} mc_sha256_ctx;
void mc_sha256_init(mc_sha256_ctx *ctx);
void mc_sha256_update(mc_sha256_ctx *ctx, const void *data, mc_usize len);
void mc_sha256_final(mc_sha256_ctx *ctx, mc_u8 out[MC_SHA256_DIGEST_SIZE]);
void mc_sha256(const void *data, mc_usize len, mc_u8 out[MC_SHA256_DIGEST_SIZE]);

// --- mc_hmac.h ---
typedef struct {
	mc_sha256_ctx inner;
	mc_u8 opad[MC_SHA256_BLOCK_SIZE];
} mc_hmac_sha256_ctx;
void mc_hmac_sha256_init(mc_hmac_sha256_ctx *ctx, const mc_u8 *key, mc_usize key_len);
void mc_hmac_sha256_update(mc_hmac_sha256_ctx *ctx, const void *data, mc_usize len);
void mc_hmac_sha256_final(mc_hmac_sha256_ctx *ctx, mc_u8 out[MC_SHA256_DIGEST_SIZE]);
void mc_hmac_sha256(const mc_u8 *key, mc_usize key_len, const void *data, mc_usize data_len, mc_u8 out[MC_SHA256_DIGEST_SIZE]);

// --- mc_hkdf.h ---
void mc_hkdf_extract(const mc_u8 *salt, mc_usize salt_len, const mc_u8 *ikm, mc_usize ikm_len, mc_u8 prk[MC_SHA256_DIGEST_SIZE]);
void mc_hkdf_expand(const mc_u8 prk[MC_SHA256_DIGEST_SIZE], const mc_u8 *info, mc_usize info_len, mc_u8 *okm, mc_usize okm_len);
int mc_tls13_derive_secret(const mc_u8 secret[MC_SHA256_DIGEST_SIZE], const char *label, const mc_u8 transcript_hash[MC_SHA256_DIGEST_SIZE], mc_u8 out[MC_SHA256_DIGEST_SIZE]);
int mc_tls13_hkdf_expand_label(const mc_u8 secret[MC_SHA256_DIGEST_SIZE], const char *label, const mc_u8 *context, mc_usize context_len, mc_u8 *out, mc_usize out_len);
int mc_tls13_finished_key(const mc_u8 base_key[MC_SHA256_DIGEST_SIZE], mc_u8 out[MC_SHA256_DIGEST_SIZE]);
void mc_tls13_finished_verify_data(const mc_u8 finished_key[MC_SHA256_DIGEST_SIZE], const mc_u8 transcript_hash[MC_SHA256_DIGEST_SIZE], mc_u8 out[MC_SHA256_DIGEST_SIZE]);


// --- mc_gcm.h ---
#define MC_GCM_TAG_SIZE 16
#define MC_GCM_IV_SIZE 12
int mc_aes128_gcm_encrypt(const mc_u8 key[16], const mc_u8 iv[MC_GCM_IV_SIZE], const mc_u8 *aad, mc_usize aad_len, const mc_u8 *plaintext, mc_usize pt_len, mc_u8 *ciphertext, mc_u8 tag[MC_GCM_TAG_SIZE]);
int mc_aes128_gcm_decrypt(const mc_u8 key[16], const mc_u8 iv[MC_GCM_IV_SIZE], const mc_u8 *aad, mc_usize aad_len, const mc_u8 *ciphertext, mc_usize ct_len, const mc_u8 tag[MC_GCM_TAG_SIZE], mc_u8 *plaintext);

// --- mc_x25519.h ---
#define MC_X25519_KEY_SIZE 32
void mc_x25519_public(mc_u8 public_key[MC_X25519_KEY_SIZE], const mc_u8 private_key[MC_X25519_KEY_SIZE]);
int mc_x25519_shared(mc_u8 shared[MC_X25519_KEY_SIZE], const mc_u8 private_key[MC_X25519_KEY_SIZE], const mc_u8 peer_public[MC_X25519_KEY_SIZE]);

// --- mc_tls13_handshake.h ---
#define MC_TLS13_HANDSHAKE_CLIENT_HELLO 1
#define MC_TLS13_HANDSHAKE_SERVER_HELLO 2
#define MC_TLS13_EXT_SERVER_NAME 0x0000
#define MC_TLS13_EXT_SUPPORTED_GROUPS 0x000a
#define MC_TLS13_EXT_SIGNATURE_ALGORITHMS 0x000d
#define MC_TLS13_EXT_SUPPORTED_VERSIONS 0x002b
#define MC_TLS13_EXT_PSK_KEY_EXCHANGE_MODES 0x002d
#define MC_TLS13_EXT_KEY_SHARE 0x0033
#define MC_TLS13_EXT_SESSION_TICKET 0x0023
#define MC_TLS13_EXT_RENEGOTIATION_INFO 0xff01
#define MC_TLS13_EXT_RECORD_SIZE_LIMIT 0x001c
#define MC_TLS13_GROUP_X25519 0x001d
struct mc_tls13_server_hello {
	mc_u16 legacy_version;
	mc_u8 random[32];
	mc_u8 legacy_session_id_echo_len;
	mc_u16 cipher_suite;
	mc_u8 legacy_compression_method;
	mc_u16 selected_version;
	mc_u16 key_share_group;
	mc_u8 key_share[32];
	mc_u16 key_share_len;
};
int mc_tls13_build_client_hello(const char *sni, mc_usize sni_len, const mc_u8 random32[32], const mc_u8 *legacy_session_id, mc_usize legacy_session_id_len, const mc_u8 x25519_pub[32], mc_u8 *out, mc_usize out_cap, mc_usize *out_len);
int mc_tls13_build_client_hello_rfc8448_1rtt(const mc_u8 random32[32], const mc_u8 x25519_pub[32], mc_u8 *out, mc_usize out_cap, mc_usize *out_len);
int mc_tls13_parse_server_hello(const mc_u8 *msg, mc_usize msg_len, struct mc_tls13_server_hello *out);

// --- mc_tls13_transcript.h ---
struct mc_tls13_transcript {
	mc_sha256_ctx sha;
};
void mc_tls13_transcript_init(struct mc_tls13_transcript *t);
void mc_tls13_transcript_update(struct mc_tls13_transcript *t, const mc_u8 *data, mc_usize len);
void mc_tls13_transcript_final(const struct mc_tls13_transcript *t, mc_u8 out[MC_SHA256_DIGEST_SIZE]);

// --- mc_tls_record.h ---
#define MC_TLS_RECORD_HEADER_SIZE 5
#define MC_TLS_CONTENT_CHANGE_CIPHER_SPEC 20
#define MC_TLS_CONTENT_ALERT 21
#define MC_TLS_CONTENT_HANDSHAKE 22
#define MC_TLS_CONTENT_APPLICATION_DATA 23
int mc_tls_record_encrypt(const mc_u8 key[16], const mc_u8 iv[12], mc_u64 seq, mc_u8 inner_type, const mc_u8 *plaintext, mc_usize pt_len, mc_u8 *record_out, mc_usize record_cap, mc_usize *record_len_out);
int mc_tls_record_decrypt(const mc_u8 key[16], const mc_u8 iv[12], mc_u64 seq, const mc_u8 *record, mc_usize record_len, mc_u8 *inner_type_out, mc_u8 *plaintext_out, mc_usize plaintext_cap, mc_usize *pt_len_out);


// --- mc_tls13_client.h ---
struct mc_tls13_client {
	mc_i32 fd;
	mc_u32 timeout_ms;
	int debug;
	mc_u8 c_ap_key[16];
	mc_u8 c_ap_iv[12];
	mc_u8 s_ap_key[16];
	mc_u8 s_ap_iv[12];
	mc_u64 c_ap_seq;
	mc_u64 s_ap_seq;
	int handshake_done;
    int has_buffered_byte;
    mc_u8 buffered_byte;
};
void mc_tls13_client_init(struct mc_tls13_client *c, mc_i32 fd, mc_u32 timeout_ms);
int mc_tls13_client_handshake(struct mc_tls13_client *c, const char *sni, mc_usize sni_len);
mc_i64 mc_tls13_client_write_app(struct mc_tls13_client *c, const mc_u8 *buf, mc_usize len);
mc_i64 mc_tls13_client_read_app(struct mc_tls13_client *c, mc_u8 *buf, mc_usize cap);
