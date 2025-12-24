// Single-file build of "Wikipedia Terminal Facts" (wtf)
// x86-64 Linux only, static, no libc.
//
// Changes vs repo multi-file version for smaller binary:
// - No /etc/resolv.conf parsing: DNS resolver is hardcoded (Google IPv6 DNS).
// - DNS is UDP-only (no TCP fallback).
// - Consolidated minimal runtime (syscalls + tiny memcpy/memset/strlen/write_all).
// - Kept: ./wtf TERM and ./wtf -l xx TERM
// - Kept: opensearch fallback when summary returns 404.
// - Still does chunked decode (for robustness); can be removed later if you accept risk.

typedef unsigned long      mc_usize;
typedef unsigned long long mc_u64;
typedef long long          mc_i64;
typedef unsigned int       mc_u32;
typedef int                mc_i32;
typedef unsigned short     mc_u16;
typedef short              mc_i16;
typedef unsigned char      mc_u8;

#define MC_NULL ((void*)0)

// --- syscalls (x86-64 Linux) ---
#define MC_SYS_read           0
#define MC_SYS_write          1
#define MC_SYS_close          3
#define MC_SYS_poll           7
#define MC_SYS_socket         41
#define MC_SYS_connect        42
#define MC_SYS_sendto         44
#define MC_SYS_recvfrom       45
#define MC_SYS_fcntl          72
#define MC_SYS_getsockopt     55
#define MC_SYS_getrandom      318
#define MC_SYS_exit           60
#define MC_SYS_exit_group     231

static inline __attribute__((always_inline)) mc_i64 mc_syscall1(mc_i64 n, mc_i64 a1) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
	return ret;
}
static inline __attribute__((always_inline, unused)) mc_i64 mc_syscall2(mc_i64 n, mc_i64 a1, mc_i64 a2) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
	return ret;
}
static inline __attribute__((always_inline)) mc_i64 mc_syscall3(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3) {
	mc_i64 ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
	return ret;
}
static inline __attribute__((always_inline)) mc_i64 mc_syscall5(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5) {
	mc_i64 ret;
	register mc_i64 r10 __asm__("r10") = a4;
	register mc_i64 r8  __asm__("r8")  = a5;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
	return ret;
}
static inline __attribute__((always_inline)) mc_i64 mc_syscall6(mc_i64 n, mc_i64 a1, mc_i64 a2, mc_i64 a3, mc_i64 a4, mc_i64 a5, mc_i64 a6) {
	mc_i64 ret;
	register mc_i64 r10 __asm__("r10") = a4;
	register mc_i64 r8  __asm__("r8")  = a5;
	register mc_i64 r9  __asm__("r9")  = a6;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return ret;
}

static inline __attribute__((always_inline)) mc_i64 mc_sys_read(mc_i32 fd, void *buf, mc_usize len) {
	return mc_syscall3(MC_SYS_read, fd, (mc_i64)buf, (mc_i64)len);
}
static inline __attribute__((always_inline)) mc_i64 mc_sys_write(mc_i32 fd, const void *buf, mc_usize len) {
	return mc_syscall3(MC_SYS_write, fd, (mc_i64)buf, (mc_i64)len);
}
static inline __attribute__((always_inline)) mc_i64 mc_sys_close(mc_i32 fd) {
	return mc_syscall1(MC_SYS_close, fd);
}
static inline __attribute__((always_inline)) mc_i64 mc_sys_poll(void *fds, mc_u64 nfds, mc_i32 timeout_ms) {
	return mc_syscall3(MC_SYS_poll, (mc_i64)fds, (mc_i64)nfds, (mc_i64)timeout_ms);
}
static inline __attribute__((always_inline)) mc_i64 mc_sys_socket(mc_i32 domain, mc_i32 type, mc_i32 protocol) {
	return mc_syscall3(MC_SYS_socket, domain, type, protocol);
}
static inline __attribute__((always_inline)) mc_i64 mc_sys_connect(mc_i32 sockfd, const void *addr, mc_u32 addrlen) {
	return mc_syscall3(MC_SYS_connect, sockfd, (mc_i64)addr, addrlen);
}
static inline __attribute__((always_inline, unused)) mc_i64 mc_sys_sendto(mc_i32 sockfd, const void *buf, mc_usize len, mc_i32 flags, const void *dest_addr, mc_u32 addrlen) {
	return mc_syscall6(MC_SYS_sendto, sockfd, (mc_i64)buf, (mc_i64)len, flags, (mc_i64)dest_addr, addrlen);
}
static inline __attribute__((always_inline, unused)) mc_i64 mc_sys_recvfrom(mc_i32 sockfd, void *buf, mc_usize len, mc_i32 flags, void *src_addr, mc_u32 *addrlen_inout) {
	return mc_syscall6(MC_SYS_recvfrom, sockfd, (mc_i64)buf, (mc_i64)len, flags, (mc_i64)src_addr, (mc_i64)addrlen_inout);
}
static inline __attribute__((always_inline)) mc_i64 mc_sys_fcntl(mc_i32 fd, mc_i32 cmd, mc_i64 arg) {
	return mc_syscall3(MC_SYS_fcntl, fd, cmd, arg);
}
static inline __attribute__((always_inline)) mc_i64 mc_sys_getsockopt(mc_i32 sockfd, mc_i32 level, mc_i32 optname, void *optval, mc_u32 *optlen_inout) {
	return mc_syscall5(MC_SYS_getsockopt, sockfd, level, optname, (mc_i64)optval, (mc_i64)optlen_inout);
}
static inline __attribute__((always_inline)) mc_i64 mc_sys_getrandom(void *buf, mc_usize buflen, mc_u32 flags) {
	return mc_syscall3(MC_SYS_getrandom, (mc_i64)buf, (mc_i64)buflen, (mc_i64)flags);
}

__attribute__((noreturn)) static void mc_exit(mc_i32 code) {
	(void)mc_syscall1(MC_SYS_exit_group, code);
	__asm__ volatile("ud2");
	__builtin_unreachable();
}

// --- tiny libc bits ---
static inline __attribute__((always_inline)) mc_usize mc_strlen(const char *s) {
	const char *p = s;
	while (*p) p++;
	return (mc_usize)(p - s);
}
static inline __attribute__((always_inline)) void *mc_memcpy(void *dst, const void *src, mc_usize n) {
	void *ret = dst;
	if (n) {
		void *d = dst;
		const void *s = src;
		__asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(n) : : "memory");
	}
	return ret;
}
static inline __attribute__((always_inline)) void *mc_memset(void *dst, int c, mc_usize n) {
	void *ret = dst;
	if (n) {
		void *d = dst;
		mc_u8 uc = (mc_u8)c;
		__asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(uc) : "memory");
	}
	return ret;
}
static inline __attribute__((always_inline)) int mc_memcmp(const void *a, const void *b, mc_usize n) {
	const mc_u8 *pa = (const mc_u8*)a;
	const mc_u8 *pb = (const mc_u8*)b;
	for (mc_usize i = 0; i < n; i++) if (pa[i] != pb[i]) return (int)pa[i] - (int)pb[i];
	return 0;
}
static mc_i64 mc_write_all(mc_i32 fd, const void *buf, mc_usize len) {
	const mc_u8 *p = (const mc_u8*)buf;
	mc_usize off = 0;
	while (off < len) {
		mc_i64 r = mc_sys_write(fd, p + off, len - off);
		if (r < 0) return r;
		if (r == 0) return -1;
		off += (mc_usize)r;
	}
	return 0;
}
static mc_i64 mc_write_str(mc_i32 fd, const char *s) {
	return mc_write_all(fd, s, mc_strlen(s));
}
static inline __attribute__((always_inline, unused)) int mc_streq(const char *a, const char *b) {
	while (*a && *b) { if (*a != *b) return 0; a++; b++; }
	return *a == *b;
}

// --- net bits ---
#define MC_AF_INET6      10
#define MC_SOCK_STREAM   1
#define MC_SOCK_DGRAM    2
#define MC_SOCK_CLOEXEC  02000000
#define MC_IPPROTO_TCP   6
#define MC_IPPROTO_UDP   17
#define MC_SOL_SOCKET    1
#define MC_SO_ERROR      4
#define MC_F_GETFL       3
#define MC_F_SETFL       4
#define MC_O_NONBLOCK    00004000
#define MC_EINPROGRESS   115

struct mc_pollfd { mc_i32 fd; mc_i16 events; mc_i16 revents; };
#define MC_POLLIN  0x0001
#define MC_POLLOUT 0x0004

struct mc_in6_addr { mc_u8 s6_addr[16]; };
struct mc_sockaddr_in6 {
	mc_u16 sin6_family;
	mc_u16 sin6_port;
	mc_u32 sin6_flowinfo;
	struct mc_in6_addr sin6_addr;
	mc_u32 sin6_scope_id;
};

// Hardcoded Google DNS IPv6: 2001:4860:4860::8888
static const mc_u8 mc_dns_google_v6[16] = { 0x20,0x01,0x48,0x60,0x48,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x88 };

// --- TLS 1.3 minimal (from repo, inlined) ---
#define MC_SHA256_BLOCK_SIZE 64u
#define MC_SHA256_DIGEST_SIZE 32u
typedef struct {
	mc_u32 state[8];
	mc_u64 count_bytes;
	mc_u8 buffer[MC_SHA256_BLOCK_SIZE];
	mc_u32 buffer_len;
} mc_sha256_ctx;

static mc_u32 rotr32(mc_u32 x, mc_u32 n) { return (mc_u32)((x >> n) | (x << (32u - n))); }
static mc_u32 load_be32(const mc_u8 *p) { return ((mc_u32)p[0] << 24) | ((mc_u32)p[1] << 16) | ((mc_u32)p[2] << 8) | ((mc_u32)p[3] << 0); }
static mc_u32 load_le32(const mc_u8 *p) { return ((mc_u32)p[0] << 0) | ((mc_u32)p[1] << 8) | ((mc_u32)p[2] << 16) | ((mc_u32)p[3] << 24); }
static void store_be32(mc_u8 *p, mc_u32 v) { p[0]=(mc_u8)(v>>24); p[1]=(mc_u8)(v>>16); p[2]=(mc_u8)(v>>8); p[3]=(mc_u8)(v>>0); }
static void store_be64(mc_u8 *p, mc_u64 v) {
	p[0]=(mc_u8)(v>>56); p[1]=(mc_u8)(v>>48); p[2]=(mc_u8)(v>>40); p[3]=(mc_u8)(v>>32);
	p[4]=(mc_u8)(v>>24); p[5]=(mc_u8)(v>>16); p[6]=(mc_u8)(v>>8);  p[7]=(mc_u8)(v>>0);
}
static mc_u32 ch(mc_u32 x, mc_u32 y, mc_u32 z) { return (x & y) ^ (~x & z); }
static mc_u32 maj(mc_u32 x, mc_u32 y, mc_u32 z) { return (x & y) ^ (x & z) ^ (y & z); }
static mc_u32 bsig0(mc_u32 x) { return rotr32(x,2) ^ rotr32(x,13) ^ rotr32(x,22); }
static mc_u32 bsig1(mc_u32 x) { return rotr32(x,6) ^ rotr32(x,11) ^ rotr32(x,25); }
static mc_u32 ssig0(mc_u32 x) { return rotr32(x,7) ^ rotr32(x,18) ^ (x>>3); }
static mc_u32 ssig1(mc_u32 x) { return rotr32(x,17) ^ rotr32(x,19) ^ (x>>10); }

static const mc_u8 *sha256_k_bytes(void) {
	return (const mc_u8 *)
	"\x98\x2f\x8a\x42\x91\x44\x37\x71\xcf\xfb\xc0\xb5\xa5\xdb\xb5\xe9"
	"\x5b\xc2\x56\x39\xf1\x11\xf1\x59\xa4\x82\x3f\x92\xd5\x5e\x1c\xab"
	"\x98\xaa\x07\xd8\x01\x5b\x83\x12\xbe\x85\x31\x24\xc3\x7d\x0c\x55"
	"\x74\x5d\xbe\x72\xfe\xb1\xde\x80\xa7\x06\xdc\x9b\x74\xf1\x9b\xc1"
	"\xc1\x69\x9b\xe4\x86\x47\xbe\xef\xc6\x9d\xc1\x0f\xcc\xa1\x0c\x24"
	"\x6f\x2c\xe9\x2d\xaa\x84\x74\x4a\xdc\xa9\xb0\x5c\xda\x88\xf9\x76"
	"\x52\x51\x3e\x98\x6d\xc6\x31\xa8\xc8\x27\x03\xb0\xc7\x7f\x59\xbf"
	"\xf3\x0b\xe0\xc6\x47\x91\xa7\xd5\x51\x63\xca\x06\x67\x29\x29\x14"
	"\x85\x0a\xb7\x27\x38\x21\x1b\x2e\xfc\x6d\x2c\x4d\x13\x0d\x38\x53"
	"\x54\x73\x0a\x65\xbb\x0a\x6a\x76\x2e\xc9\xc2\x81\x85\x2c\x72\x92"
	"\xa1\xe8\xbf\xa2\x4b\x66\x1a\xa8\x70\x8b\x4b\xc2\xa3\x51\x6c\xc7"
	"\x19\xe8\x92\xd1\x24\x06\x99\xd6\x85\x35\x0e\xf4\x70\xa0\x6a\x10"
	"\x16\xc1\xa4\x19\x08\x6c\x37\x1e\x4c\x77\x48\x27\xb5\xbc\xb0\x34"
	"\xb3\x0c\x1c\x39\x4a\xaa\xd8\x4e\x4f\xca\x9c\x5b\xf3\x6f\x2e\x68"
	"\xee\x82\x8f\x74\x6f\x63\xa5\x78\x14\x78\xc8\x84\x08\x02\xc7\x8c"
	"\xfa\xff\xbe\x90\xeb\x6c\x50\xa4\xf7\xa3\xf9\xbe\xf2\x78\x71\xc6";
}
static void sha256_transform(mc_sha256_ctx *ctx, const mc_u8 block[64]) {
	mc_u32 w[64];
	for (mc_u32 i=0;i<16;i++) w[i]=load_be32(block+(mc_usize)(i*4u));
	for (mc_u32 i=16;i<64;i++) w[i]=ssig1(w[i-2])+w[i-7]+ssig0(w[i-15])+w[i-16];

	mc_u32 a=ctx->state[0],b=ctx->state[1],c=ctx->state[2],d=ctx->state[3];
	mc_u32 e=ctx->state[4],f=ctx->state[5],g=ctx->state[6],h=ctx->state[7];
	const mc_u8 *kb=sha256_k_bytes();

	for (mc_u32 i=0;i<64;i++) {
		mc_u32 t1=h+bsig1(e)+ch(e,f,g)+load_le32(kb+(mc_usize)(i*4u))+w[i];
		mc_u32 t2=bsig0(a)+maj(a,b,c);
		h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
	}
	ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
	ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}
static void mc_sha256_init(mc_sha256_ctx *ctx) {
	ctx->state[0]=0x6a09e667u; ctx->state[1]=0xbb67ae85u; ctx->state[2]=0x3c6ef372u; ctx->state[3]=0xa54ff53au;
	ctx->state[4]=0x510e527fu; ctx->state[5]=0x9b05688cu; ctx->state[6]=0x1f83d9abu; ctx->state[7]=0x5be0cd19u;
	ctx->count_bytes=0; ctx->buffer_len=0;
}
static void mc_sha256_update(mc_sha256_ctx *ctx, const void *data, mc_usize len) {
	const mc_u8 *p=(const mc_u8*)data;
	ctx->count_bytes += (mc_u64)len;
	if (ctx->buffer_len) {
		mc_u32 need=(mc_u32)(MC_SHA256_BLOCK_SIZE-ctx->buffer_len);
		mc_u32 take=(mc_u32)len; if (take>need) take=need;
		mc_memcpy(ctx->buffer+ctx->buffer_len,p,(mc_usize)take);
		ctx->buffer_len+=take; p+=take; len-=take;
		if (ctx->buffer_len==MC_SHA256_BLOCK_SIZE){ sha256_transform(ctx,ctx->buffer); ctx->buffer_len=0; }
	}
	while (len>=MC_SHA256_BLOCK_SIZE){ sha256_transform(ctx,p); p+=MC_SHA256_BLOCK_SIZE; len-=MC_SHA256_BLOCK_SIZE; }
	if (len){ mc_memcpy(ctx->buffer,p,len); ctx->buffer_len=(mc_u32)len; }
}
static void mc_sha256_final(mc_sha256_ctx *ctx, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	mc_u8 pad[MC_SHA256_BLOCK_SIZE+8];
	mc_u64 bit_len=ctx->count_bytes*8u;
	pad[0]=0x80u;
	mc_u32 pad_zeros = (ctx->buffer_len < 56u) ? (mc_u32)(56u-ctx->buffer_len-1u) : (mc_u32)(64u+56u-ctx->buffer_len-1u);
	mc_memset(pad+1,0,(mc_usize)pad_zeros);
	store_be64(pad+1+pad_zeros,bit_len);
	mc_sha256_update(ctx,pad,(mc_usize)(1u+pad_zeros+8u));
	for (mc_u32 i=0;i<8;i++) store_be32(out+(mc_usize)(i*4u),ctx->state[i]);
	mc_memset(ctx,0,sizeof(*ctx));
}
static void mc_sha256(const void *data, mc_usize len, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	mc_sha256_ctx ctx; mc_sha256_init(&ctx); mc_sha256_update(&ctx,data,len); mc_sha256_final(&ctx,out);
}

// HMAC/HKDF (from your pasted files)
typedef struct { mc_sha256_ctx inner; mc_u8 opad[MC_SHA256_BLOCK_SIZE]; } mc_hmac_sha256_ctx;

static void mc_hmac_sha256_init(mc_hmac_sha256_ctx *ctx, const mc_u8 *key, mc_usize key_len) {
	mc_u8 key_hash[MC_SHA256_DIGEST_SIZE];
	const mc_u8 *k = key;
	mc_usize klen = key_len;

	if (klen > MC_SHA256_BLOCK_SIZE) {
		mc_sha256(key, key_len, key_hash);
		k = key_hash;
		klen = MC_SHA256_DIGEST_SIZE;
	}

	mc_u8 ipad[MC_SHA256_BLOCK_SIZE];
	for (mc_u32 i = 0; i < MC_SHA256_BLOCK_SIZE; i++) {
		ipad[i] = 0x36u;
		ctx->opad[i] = 0x5cu;
	}
	for (mc_usize i = 0; i < klen; i++) {
		ipad[i] ^= k[i];
		ctx->opad[i] ^= k[i];
	}

	mc_sha256_init(&ctx->inner);
	mc_sha256_update(&ctx->inner, ipad, MC_SHA256_BLOCK_SIZE);

	mc_memset(key_hash, 0, sizeof(key_hash));
	mc_memset(ipad, 0, sizeof(ipad));
}
static void mc_hmac_sha256_update(mc_hmac_sha256_ctx *ctx, const void *data, mc_usize len) {
	mc_sha256_update(&ctx->inner, data, len);
}
static void mc_hmac_sha256_final(mc_hmac_sha256_ctx *ctx, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	mc_u8 inner_hash[MC_SHA256_DIGEST_SIZE];
	mc_sha256_final(&ctx->inner, inner_hash);

	mc_sha256_ctx outer;
	mc_sha256_init(&outer);
	mc_sha256_update(&outer, ctx->opad, MC_SHA256_BLOCK_SIZE);
	mc_sha256_update(&outer, inner_hash, MC_SHA256_DIGEST_SIZE);
	mc_sha256_final(&outer, out);

	mc_memset(inner_hash, 0, sizeof(inner_hash));
	mc_memset(&outer, 0, sizeof(outer));
}
static void mc_hmac_sha256(const mc_u8 *key, mc_usize key_len, const void *data, mc_usize data_len, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	mc_hmac_sha256_ctx ctx;
	mc_hmac_sha256_init(&ctx, key, key_len);
	mc_hmac_sha256_update(&ctx, data, data_len);
	mc_hmac_sha256_final(&ctx, out);
	mc_memset(&ctx, 0, sizeof(ctx));
}
static void mc_hkdf_extract(const mc_u8 *salt, mc_usize salt_len, const mc_u8 *ikm, mc_usize ikm_len, mc_u8 prk[MC_SHA256_DIGEST_SIZE]) {
	mc_u8 zeros[MC_SHA256_DIGEST_SIZE];
	if (!salt || salt_len == 0) {
		mc_memset(zeros, 0, sizeof(zeros));
		salt = zeros;
		salt_len = MC_SHA256_DIGEST_SIZE;
	}
	mc_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
	mc_memset(zeros, 0, sizeof(zeros));
}
static void mc_hkdf_expand(const mc_u8 prk[MC_SHA256_DIGEST_SIZE], const mc_u8 *info, mc_usize info_len, mc_u8 *okm, mc_usize okm_len) {
	if (!okm || okm_len == 0) return;
	if (!prk) { mc_memset(okm, 0, okm_len); return; }

	mc_usize n = (okm_len + (MC_SHA256_DIGEST_SIZE - 1u)) / MC_SHA256_DIGEST_SIZE;
	if (n > 255u) { mc_memset(okm, 0, okm_len); return; }

	mc_u8 t[MC_SHA256_DIGEST_SIZE];
	mc_usize tlen = 0;
	mc_usize out_off = 0;

	for (mc_u32 i = 1; i <= (mc_u32)n; i++) {
		mc_hmac_sha256_ctx h;
		mc_hmac_sha256_init(&h, prk, MC_SHA256_DIGEST_SIZE);
		if (tlen) mc_hmac_sha256_update(&h, t, tlen);
		if (info && info_len) mc_hmac_sha256_update(&h, info, info_len);
		mc_u8 c = (mc_u8)i;
		mc_hmac_sha256_update(&h, &c, 1);
		mc_hmac_sha256_final(&h, t);
		mc_memset(&h, 0, sizeof(h));

		tlen = MC_SHA256_DIGEST_SIZE;
		mc_usize take = okm_len - out_off;
		if (take > MC_SHA256_DIGEST_SIZE) take = MC_SHA256_DIGEST_SIZE;
		mc_memcpy(okm + out_off, t, take);
		out_off += take;
	}
	mc_memset(t, 0, sizeof(t));
}

// --- X25519 (from your pasted file) ---
#define MC_X25519_KEY_SIZE 32
typedef struct { mc_i64 v[16]; } fe;
static void fe_0(fe *o) { mc_memset(o, 0, sizeof(*o)); }
static void fe_1(fe *o) { fe_0(o); o->v[0] = 1; }
static void fe_copy(fe *o, const fe *a) { mc_memcpy(o, a, sizeof(*o)); }
static void fe_add(fe *o, const fe *a, const fe *b) { for (int i = 0; i < 16; i++) o->v[i] = a->v[i] + b->v[i]; }
static void fe_sub(fe *o, const fe *a, const fe *b) { for (int i = 0; i < 16; i++) o->v[i] = a->v[i] - b->v[i]; }
static void fe_cswap(fe *a, fe *b, mc_i64 swap) {
	mc_i64 mask = -swap;
	for (int i = 0; i < 16; i++) {
		mc_i64 t = mask & (a->v[i] ^ b->v[i]);
		a->v[i] ^= t; b->v[i] ^= t;
	}
}
static void fe_carry(fe *o) {
	for (int i = 0; i < 16; i++) {
		o->v[i] += ((mc_i64)1 << 16);
		mc_i64 c = o->v[i] >> 16;
		o->v[i] -= c << 16;
		if (i == 15) o->v[0] += (c - 1) * 38;
		else o->v[i + 1] += (c - 1);
	}
}
static void fe_mul(fe *o, const fe *a, const fe *b) {
	mc_i64 t[31];
	mc_memset(t, 0, sizeof(t));
	for (int i = 0; i < 16; i++) for (int j = 0; j < 16; j++) t[i + j] += a->v[i] * b->v[j];
	for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
	for (int i = 0; i < 16; i++) o->v[i] = t[i];
	fe_carry(o); fe_carry(o);
}
static void fe_sq(fe *o, const fe *a) { fe_mul(o, a, a); }
static void fe_frombytes(fe *o, const mc_u8 s[32]) {
	for (int i = 0; i < 16; i++) o->v[i] = (mc_i64)((mc_u32)s[2*i] | ((mc_u32)s[2*i + 1] << 8));
	o->v[15] &= 0x7fffu;
}
static void fe_select(fe *o, const fe *a, const fe *b, mc_i64 sel) {
	mc_i64 mask = -sel;
	for (int i = 0; i < 16; i++) {
		mc_i64 x = a->v[i], y = b->v[i];
		o->v[i] = x ^ (mask & (x ^ y));
	}
}
static void fe_tobytes(mc_u8 s[32], const fe *n) {
	fe t; fe m;
	fe_copy(&t, n);
	fe_carry(&t); fe_carry(&t); fe_carry(&t);

	static const mc_i64 p[16] = {
		0xffed,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,
		0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0x7fff,
	};

	m.v[0] = t.v[0] - p[0];
	for (int i = 1; i < 16; i++) {
		mc_i64 borrow = (m.v[i - 1] >> 16) & 1;
		m.v[i] = t.v[i] - p[i] - borrow;
	}

	mc_i64 neg = (m.v[15] >> 16) & 1;
	fe_select(&t, &t, &m, 1 - neg);

	for (int i = 0; i < 16; i++) {
		mc_u16 v = (mc_u16)t.v[i];
		s[2*i + 0] = (mc_u8)(v & 0xffu);
		s[2*i + 1] = (mc_u8)(v >> 8);
	}
}
static void fe_inv(fe *o, const fe *i) {
	fe c;
	fe_copy(&c, i);
	for (int a = 253; a >= 0; a--) {
		fe_sq(&c, &c);
		if (a != 2 && a != 4) fe_mul(&c, &c, i);
	}
	fe_copy(o, &c);
}
static void clamp_scalar(mc_u8 k[32]) { k[0] &= 248u; k[31] &= 127u; k[31] |= 64u; }
static void x25519_scalar_mult(mc_u8 out[32], const mc_u8 scalar_in[32], const mc_u8 u_in[32]) {
	mc_u8 e[32];
	mc_memcpy(e, scalar_in, 32);
	clamp_scalar(e);

	fe x1, x2, z2, x3, z3;
	fe_frombytes(&x1, u_in);
	fe_1(&x2); fe_0(&z2);
	fe_copy(&x3, &x1); fe_1(&z3);

	fe a, aa, b, bb, e_fe;
	fe c, d, da, cb;
	fe tmp0, tmp1;

	mc_i64 swap = 0;

	fe a24;
	fe_0(&a24);
	a24.v[0] = 0xdb41;
	a24.v[1] = 1;

	for (int pos = 254; pos >= 0; pos--) {
		mc_i64 bit = (mc_i64)((e[pos >> 3] >> (pos & 7)) & 1u);
		swap ^= bit;
		fe_cswap(&x2, &x3, swap);
		fe_cswap(&z2, &z3, swap);
		swap = bit;

		fe_add(&a, &x2, &z2);
		fe_sq(&aa, &a);
		fe_sub(&b, &x2, &z2);
		fe_sq(&bb, &b);
		fe_sub(&e_fe, &aa, &bb);

		fe_add(&c, &x3, &z3);
		fe_sub(&d, &x3, &z3);
		fe_mul(&da, &d, &a);
		fe_mul(&cb, &c, &b);

		fe_add(&tmp0, &da, &cb);
		fe_sq(&x3, &tmp0);
		fe_sub(&tmp1, &da, &cb);
		fe_sq(&tmp1, &tmp1);
		fe_mul(&z3, &tmp1, &x1);

		fe_mul(&x2, &aa, &bb);
		fe_mul(&tmp0, &e_fe, &a24);
		fe_add(&tmp0, &tmp0, &aa);
		fe_mul(&z2, &e_fe, &tmp0);
	}

	fe_cswap(&x2, &x3, swap);
	fe_cswap(&z2, &z3, swap);

	fe_inv(&z2, &z2);
	fe_mul(&x2, &x2, &z2);
	fe_tobytes(out, &x2);
}
static void mc_x25519_public(mc_u8 public_key[MC_X25519_KEY_SIZE], const mc_u8 private_key[MC_X25519_KEY_SIZE]) {
	mc_u8 base[32];
	mc_memset(base, 0, sizeof(base));
	base[0] = 9;
	x25519_scalar_mult(public_key, private_key, base);
}
static int mc_x25519_shared(mc_u8 shared[MC_X25519_KEY_SIZE], const mc_u8 private_key[MC_X25519_KEY_SIZE], const mc_u8 peer_public[MC_X25519_KEY_SIZE]) {
	x25519_scalar_mult(shared, private_key, peer_public);
	mc_u8 acc = 0;
	for (int i = 0; i < 32; i++) acc |= shared[i];
	return acc ? 0 : -1;
}

// AES-NI (kept; relies on -maes and compiler intrinsics)
#include <wmmintrin.h>
#define MC_AES128_KEY_SIZE 16u
#define MC_AES128_BLOCK_SIZE 16u
typedef struct { mc_u32 rk[44]; } mc_aes128_ctx;

static inline __attribute__((always_inline)) __m128i aes_128_key_exp(__m128i key, __m128i key_gen_res) {
	key_gen_res = _mm_shuffle_epi32(key_gen_res, _MM_SHUFFLE(3,3,3,3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, key_gen_res);
}
static void mc_aes128_init(mc_aes128_ctx *ctx, const mc_u8 key[MC_AES128_KEY_SIZE]) {
	__m128i k = _mm_loadu_si128((const __m128i*)key);
	_mm_storeu_si128((__m128i*)&ctx->rk[0], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x01)); _mm_storeu_si128((__m128i*)&ctx->rk[4], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x02)); _mm_storeu_si128((__m128i*)&ctx->rk[8], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x04)); _mm_storeu_si128((__m128i*)&ctx->rk[12], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x08)); _mm_storeu_si128((__m128i*)&ctx->rk[16], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x10)); _mm_storeu_si128((__m128i*)&ctx->rk[20], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x20)); _mm_storeu_si128((__m128i*)&ctx->rk[24], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x40)); _mm_storeu_si128((__m128i*)&ctx->rk[28], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x80)); _mm_storeu_si128((__m128i*)&ctx->rk[32], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x1B)); _mm_storeu_si128((__m128i*)&ctx->rk[36], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x36)); _mm_storeu_si128((__m128i*)&ctx->rk[40], k);
}
static void mc_aes128_encrypt_block(const mc_aes128_ctx *ctx, const mc_u8 in[MC_AES128_BLOCK_SIZE], mc_u8 out[MC_AES128_BLOCK_SIZE]) {
	__m128i m = _mm_loadu_si128((const __m128i*)in);
	m = _mm_xor_si128(m, _mm_loadu_si128((const __m128i*)&ctx->rk[0]));
	for (int i = 1; i < 10; i++) m = _mm_aesenc_si128(m, _mm_loadu_si128((const __m128i*)&ctx->rk[i*4]));
	m = _mm_aesenclast_si128(m, _mm_loadu_si128((const __m128i*)&ctx->rk[40]));
	_mm_storeu_si128((__m128i*)out, m);
}

// GCM (from repo)
#define MC_GCM_TAG_SIZE 16
#define MC_GCM_IV_SIZE  12
static void xor16(mc_u8 out[16], const mc_u8 a[16], const mc_u8 b[16]) { for (int i = 0; i < 16; i++) out[i] = (mc_u8)(a[i] ^ b[i]); }
static void inc32(mc_u8 counter[16]) {
	mc_u32 x = ((mc_u32)counter[12] << 24) | ((mc_u32)counter[13] << 16) | ((mc_u32)counter[14] << 8) | (mc_u32)counter[15];
	x++;
	counter[12]=(mc_u8)(x>>24); counter[13]=(mc_u8)(x>>16); counter[14]=(mc_u8)(x>>8); counter[15]=(mc_u8)(x>>0);
}
static void shift_right_one(mc_u8 v[16]) {
	mc_u8 carry = 0;
	for (int i=0;i<16;i++){
		mc_u8 b=v[i];
		mc_u8 new_carry=(mc_u8)(b&1u);
		v[i]=(mc_u8)((b>>1)|(carry?0x80u:0));
		carry=new_carry;
	}
}
static void ghash_mul(mc_u8 x[16], const mc_u8 h[16]) {
	mc_u8 z[16], v[16];
	mc_memset(z,0,16);
	mc_memcpy(v,h,16);
	for (int byte=0;byte<16;byte++){
		mc_u8 xb=x[byte];
		for (int bit=0;bit<8;bit++){
			if (xb & 0x80u) for (int i=0;i<16;i++) z[i]^=v[i];
			mc_u8 lsb=(mc_u8)(v[15]&1u);
			shift_right_one(v);
			if (lsb) v[0]^=0xe1u;
			xb=(mc_u8)(xb<<1);
		}
	}
	mc_memcpy(x,z,16);
}
static void ghash_update(mc_u8 y[16], const mc_u8 h[16], const mc_u8 *data, mc_usize len) {
	mc_u8 block[16];
	while (len>=16){
		for (int i=0;i<16;i++) y[i]^=data[i];
		ghash_mul(y,h);
		data+=16; len-=16;
	}
	if (len){
		mc_memset(block,0,16);
		mc_memcpy(block,data,len);
		for (int i=0;i<16;i++) y[i]^=block[i];
		ghash_mul(y,h);
	}
}
static void ghash_final_lengths(mc_u8 y[16], const mc_u8 h[16], mc_usize aad_len, mc_usize ct_len) {
	mc_u8 lens[16];
	mc_u64 a_bits=(mc_u64)aad_len*8u, c_bits=(mc_u64)ct_len*8u;
	store_be64(lens+0,a_bits);
	store_be64(lens+8,c_bits);
	for (int i=0;i<16;i++) y[i]^=lens[i];
	ghash_mul(y,h);
}
static void aes128_ctr_xor(const mc_aes128_ctx *aes, mc_u8 counter[16], const mc_u8 *in, mc_u8 *out, mc_usize len) {
	mc_u8 stream[16];
	while (len){
		mc_aes128_encrypt_block(aes,counter,stream);
		inc32(counter);
		mc_usize n=(len<16)?len:16;
		for (mc_usize i=0;i<n;i++) out[i]=(mc_u8)(in[i]^stream[i]);
		in+=n; out+=n; len-=n;
	}
}
static int ct_memeq(const mc_u8 *a, const mc_u8 *b, mc_usize n) { mc_u8 diff=0; for (mc_usize i=0;i<n;i++) diff|=(mc_u8)(a[i]^b[i]); return diff==0; }

static int mc_aes128_gcm_encrypt(const mc_u8 key[16], const mc_u8 iv[MC_GCM_IV_SIZE],
	const mc_u8 *aad, mc_usize aad_len, const mc_u8 *plaintext, mc_usize pt_len,
	mc_u8 *ciphertext, mc_u8 tag[MC_GCM_TAG_SIZE]) {
	mc_aes128_ctx aes; mc_aes128_init(&aes,key);

	mc_u8 h[16], zero[16];
	mc_memset(zero,0,16);
	mc_aes128_encrypt_block(&aes,zero,h);

	mc_u8 j0[16];
	mc_memcpy(j0,iv,MC_GCM_IV_SIZE);
	j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;

	mc_u8 ctr[16];
	mc_memcpy(ctr,j0,16);
	inc32(ctr);
	if (pt_len) aes128_ctr_xor(&aes,ctr,plaintext,ciphertext,pt_len);

	mc_u8 y[16];
	mc_memset(y,0,16);
	if (aad_len) ghash_update(y,h,aad,aad_len);
	if (pt_len) ghash_update(y,h,ciphertext,pt_len);
	ghash_final_lengths(y,h,aad_len,pt_len);

	mc_u8 s[16];
	mc_aes128_encrypt_block(&aes,j0,s);
	xor16(tag,s,y);
	return 0;
}
static int mc_aes128_gcm_decrypt(const mc_u8 key[16], const mc_u8 iv[MC_GCM_IV_SIZE],
	const mc_u8 *aad, mc_usize aad_len, const mc_u8 *ciphertext, mc_usize ct_len,
	const mc_u8 tag[MC_GCM_TAG_SIZE], mc_u8 *plaintext) {
	mc_aes128_ctx aes; mc_aes128_init(&aes,key);

	mc_u8 h[16], zero[16];
	mc_memset(zero,0,16);
	mc_aes128_encrypt_block(&aes,zero,h);

	mc_u8 j0[16];
	mc_memcpy(j0,iv,MC_GCM_IV_SIZE);
	j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;

	mc_u8 y[16];
	mc_memset(y,0,16);
	if (aad_len) ghash_update(y,h,aad,aad_len);
	if (ct_len) ghash_update(y,h,ciphertext,ct_len);
	ghash_final_lengths(y,h,aad_len,ct_len);

	mc_u8 s[16];
	mc_aes128_encrypt_block(&aes,j0,s);
	mc_u8 exp_tag[16];
	xor16(exp_tag,s,y);
	if (!ct_memeq(exp_tag,tag,16)) return -1;

	mc_u8 ctr[16];
	mc_memcpy(ctr,j0,16);
	inc32(ctr);
	if (ct_len) aes128_ctr_xor(&aes,ctr,ciphertext,plaintext,ct_len);
	return 0;
}

// transcript
struct mc_tls13_transcript { mc_sha256_ctx sha; };
static void mc_tls13_transcript_init(struct mc_tls13_transcript *t) { if (!t) return; mc_sha256_init(&t->sha); }
static void mc_tls13_transcript_update(struct mc_tls13_transcript *t, const mc_u8 *data, mc_usize len) { if (!t) return; if (!data && len) return; mc_sha256_update(&t->sha, data, len); }
static void mc_tls13_transcript_final(const struct mc_tls13_transcript *t, mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	if (!out) return;
	if (!t) { mc_memset(out,0,MC_SHA256_DIGEST_SIZE); return; }
	mc_sha256_ctx tmp = t->sha;
	mc_sha256_final(&tmp, out);
	mc_memset(&tmp, 0, sizeof(tmp));
}

// TLS HKDF label helpers (from repo mc_tls13.c, slightly compact)
static inline __attribute__((always_inline)) void store_be16(mc_u8 *p, mc_u16 v){ p[0]=(mc_u8)(v>>8); p[1]=(mc_u8)(v>>0); }
static mc_usize cstr_len(const char *s){ mc_usize n=0; if(!s) return 0; while(s[n]) n++; return n; }

static int mc_tls13_hkdf_expand_label(const mc_u8 secret[MC_SHA256_DIGEST_SIZE], const char *label,
	const mc_u8 *context, mc_usize context_len, mc_u8 *out, mc_usize out_len) {
	if (!out || out_len==0) return -1;
	if (!secret) { mc_memset(out,0,out_len); return -1; }

	const char *prefix="tls13 ";
	mc_usize prefix_len=6u;
	mc_usize label_len=cstr_len(label);
	mc_usize full_label_len=prefix_len+label_len;
	if (full_label_len>255u || context_len>255u || out_len>0xffffu) return -1;

	mc_u8 info[2u+1u+255u+1u+255u];
	mc_usize off=0;
	store_be16(info+off,(mc_u16)out_len); off+=2;
	info[off++]=(mc_u8)full_label_len;
	mc_memcpy(info+off,prefix,prefix_len); off+=prefix_len;
	if (label_len){ mc_memcpy(info+off,label,label_len); off+=label_len; }
	info[off++]=(mc_u8)context_len;
	if (context_len){
		if (!context) return -1;
		mc_memcpy(info+off,context,context_len); off+=context_len;
	}
	mc_hkdf_expand(secret,info,off,out,out_len);
	mc_memset(info,0,sizeof(info));
	return 0;
}
static int mc_tls13_derive_secret(const mc_u8 secret[MC_SHA256_DIGEST_SIZE], const char *label,
	const mc_u8 transcript_hash[MC_SHA256_DIGEST_SIZE], mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	if (!out) return -1;
	if (!transcript_hash){ mc_memset(out,0,MC_SHA256_DIGEST_SIZE); return -1; }
	return mc_tls13_hkdf_expand_label(secret,label,transcript_hash,MC_SHA256_DIGEST_SIZE,out,MC_SHA256_DIGEST_SIZE);
}
static int mc_tls13_finished_key(const mc_u8 base_key[MC_SHA256_DIGEST_SIZE], mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	return mc_tls13_hkdf_expand_label(base_key,"finished",MC_NULL,0,out,MC_SHA256_DIGEST_SIZE);
}
static void mc_tls13_finished_verify_data(const mc_u8 finished_key[MC_SHA256_DIGEST_SIZE], const mc_u8 transcript_hash[MC_SHA256_DIGEST_SIZE],
	mc_u8 out[MC_SHA256_DIGEST_SIZE]) {
	if (!out) return;
	if (!finished_key || !transcript_hash){ mc_memset(out,0,MC_SHA256_DIGEST_SIZE); return; }
	mc_hmac_sha256(finished_key,MC_SHA256_DIGEST_SIZE,transcript_hash,MC_SHA256_DIGEST_SIZE,out);
}

// TLS handshake and record layer (from repo, minimal)
#define MC_TLS13_HANDSHAKE_SERVER_HELLO 2
#define MC_TLS13_HANDSHAKE_CLIENT_HELLO 1
#define MC_TLS13_EXT_SERVER_NAME 0x0000
#define MC_TLS13_EXT_SUPPORTED_GROUPS 0x000a
#define MC_TLS13_EXT_SIGNATURE_ALGORITHMS 0x000d
#define MC_TLS13_EXT_SUPPORTED_VERSIONS 0x002b
#define MC_TLS13_EXT_PSK_KEY_EXCHANGE_MODES 0x002d
#define MC_TLS13_EXT_KEY_SHARE 0x0033
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

struct wbuf{ mc_u8 *p; mc_usize cap,len; };
static int wb_init(struct wbuf*b, mc_u8*p, mc_usize cap){ if(!b||!p||cap==0) return -1; b->p=p; b->cap=cap; b->len=0; return 0; }
static int wb_put_u8(struct wbuf*b, mc_u8 v){ if(!b||b->len+1>b->cap) return -1; b->p[b->len++]=v; return 0; }
static int wb_put_u16(struct wbuf*b, mc_u16 v){ if(!b||b->len+2>b->cap) return -1; b->p[b->len++]=(mc_u8)(v>>8); b->p[b->len++]=(mc_u8)(v>>0); return 0; }
static int wb_put_u24(struct wbuf*b, mc_u32 v){ if(!b||b->len+3>b->cap) return -1; b->p[b->len++]=(mc_u8)(v>>16); b->p[b->len++]=(mc_u8)(v>>8); b->p[b->len++]=(mc_u8)(v>>0); return 0; }
static int wb_put_bytes(struct wbuf*b, const mc_u8*p, mc_usize n){ if(!b||(!p&&n)||b->len+n>b->cap) return -1; if(n) mc_memcpy(b->p+b->len,p,n); b->len+=n; return 0; }
static void wb_patch_u16_at(struct wbuf*b, mc_usize off, mc_u16 v){ if(!b||off+2>b->cap) return; b->p[off]=(mc_u8)(v>>8); b->p[off+1]=(mc_u8)(v>>0); }
static void wb_patch_u24_at(struct wbuf*b, mc_usize off, mc_u32 v){ if(!b||off+3>b->cap) return; b->p[off]=(mc_u8)(v>>16); b->p[off+1]=(mc_u8)(v>>8); b->p[off+2]=(mc_u8)(v>>0); }

static const mc_u8 *rfc8448_sig_algs_ptr(void){
	return (const mc_u8 *)
	"\x04\x03\x05\x03\x06\x03\x02\x03\x08\x04\x08\x05\x08\x06\x04\x01"
	"\x05\x01\x06\x01\x02\x01\x04\x02\x05\x02\x06\x02\x02\x02";
}
#define RFC8448_SIG_ALGS_LEN 30u

static int mc_tls13_build_client_hello(const char *sni, mc_usize sni_len, const mc_u8 random32[32], const mc_u8 *legacy_session_id, mc_usize legacy_session_id_len,
	const mc_u8 x25519_pub[32], mc_u8 *out, mc_usize out_cap, mc_usize *out_len) {
	if (!out||!out_len||!sni||sni_len==0||!random32||!x25519_pub) return -1;
	if (!legacy_session_id && legacy_session_id_len) return -1;
	if (legacy_session_id_len>32u||sni_len>0xffffu) return -1;

	struct wbuf b; if (wb_init(&b,out,out_cap)!=0) return -1;

	if (wb_put_u8(&b,MC_TLS13_HANDSHAKE_CLIENT_HELLO)!=0) return -1;
	mc_usize hs_len_off=b.len; if (wb_put_u24(&b,0)!=0) return -1;

	if (wb_put_u16(&b,0x0303)!=0) return -1;
	if (wb_put_bytes(&b,random32,32)!=0) return -1;
	if (wb_put_u8(&b,(mc_u8)legacy_session_id_len)!=0) return -1;
	if (wb_put_bytes(&b,legacy_session_id,legacy_session_id_len)!=0) return -1;

	if (wb_put_u16(&b,2)!=0) return -1;
	if (wb_put_u16(&b,0x1301)!=0) return -1;

	if (wb_put_u8(&b,1)!=0) return -1;
	if (wb_put_u8(&b,0)!=0) return -1;

	mc_usize exts_len_off=b.len; if (wb_put_u16(&b,0)!=0) return -1;
	mc_usize exts_start=b.len;

	// server_name
	if (wb_put_u16(&b,MC_TLS13_EXT_SERVER_NAME)!=0) return -1;
	mc_usize sn_len_off=b.len; if (wb_put_u16(&b,0)!=0) return -1;
	mc_usize sn_start=b.len;
	if (wb_put_u16(&b,0)!=0) return -1; // list len patched later
	mc_usize snlist_start=b.len;
	if (wb_put_u8(&b,0)!=0) return -1;
	if (wb_put_u16(&b,(mc_u16)sni_len)!=0) return -1;
	if (wb_put_bytes(&b,(const mc_u8*)sni,sni_len)!=0) return -1;
	wb_patch_u16_at(&b,sn_start,(mc_u16)(b.len-snlist_start));
	wb_patch_u16_at(&b,sn_len_off,(mc_u16)(b.len-sn_start));

	// supported_groups: x25519
	if (wb_put_u16(&b,MC_TLS13_EXT_SUPPORTED_GROUPS)!=0) return -1;
	if (wb_put_u16(&b,4)!=0) return -1;
	if (wb_put_u16(&b,2)!=0) return -1;
	if (wb_put_u16(&b,MC_TLS13_GROUP_X25519)!=0) return -1;

	// key_share
	if (wb_put_u16(&b,MC_TLS13_EXT_KEY_SHARE)!=0) return -1;
	if (wb_put_u16(&b,0x0026)!=0) return -1;
	if (wb_put_u16(&b,0x0024)!=0) return -1;
	if (wb_put_u16(&b,MC_TLS13_GROUP_X25519)!=0) return -1;
	if (wb_put_u16(&b,0x0020)!=0) return -1;
	if (wb_put_bytes(&b,x25519_pub,32)!=0) return -1;

	// supported_versions
	if (wb_put_u16(&b,MC_TLS13_EXT_SUPPORTED_VERSIONS)!=0) return -1;
	if (wb_put_u16(&b,3)!=0) return -1;
	if (wb_put_u8(&b,2)!=0) return -1;
	if (wb_put_u16(&b,0x0304)!=0) return -1;

	// signature_algorithms
	if (wb_put_u16(&b,MC_TLS13_EXT_SIGNATURE_ALGORITHMS)!=0) return -1;
	if (wb_put_u16(&b,0x0020)!=0) return -1;
	if (wb_put_u16(&b,0x001e)!=0) return -1;
	if (wb_put_bytes(&b,rfc8448_sig_algs_ptr(),RFC8448_SIG_ALGS_LEN)!=0) return -1;

	// psk_key_exchange_modes
	if (wb_put_u16(&b,MC_TLS13_EXT_PSK_KEY_EXCHANGE_MODES)!=0) return -1;
	if (wb_put_u16(&b,2)!=0) return -1;
	if (wb_put_u8(&b,1)!=0) return -1;
	if (wb_put_u8(&b,1)!=0) return -1;

	mc_usize exts_len=b.len-exts_start;
	wb_patch_u16_at(&b,exts_len_off,(mc_u16)exts_len);

	mc_usize hs_len=b.len-(hs_len_off+3u);
	wb_patch_u24_at(&b,hs_len_off,(mc_u32)hs_len);

	*out_len=b.len;
	return 0;
}

struct rbuf { const mc_u8 *p; mc_usize len, off; };
static int rb_init(struct rbuf*r, const mc_u8*p, mc_usize len){ if(!r||(!p&&len)) return -1; r->p=p; r->len=len; r->off=0; return 0; }
static int rb_need(struct rbuf*r, mc_usize n){ return (r && r->off+n<=r->len) ? 0 : -1; }
static int rb_get_u8(struct rbuf*r, mc_u8*out){ if(!out||rb_need(r,1)) return -1; *out=r->p[r->off++]; return 0; }
static int rb_get_u16(struct rbuf*r, mc_u16*out){
	if(!out||rb_need(r,2)) return -1;
	mc_u16 v=(mc_u16)((mc_u16)r->p[r->off]<<8); v|=(mc_u16)r->p[r->off+1u]; r->off+=2; *out=v; return 0;
}
static int rb_get_u24(struct rbuf*r, mc_u32*out){
	if(!out||rb_need(r,3)) return -1;
	mc_u32 v=0; v|=((mc_u32)r->p[r->off+0u]<<16); v|=((mc_u32)r->p[r->off+1u]<<8); v|=((mc_u32)r->p[r->off+2u]<<0);
	r->off+=3; *out=v; return 0;
}
static int rb_get_bytes(struct rbuf*r, mc_u8*out, mc_usize n){ if((!out&&n)||rb_need(r,n)) return -1; if(n) mc_memcpy(out,r->p+r->off,n); r->off+=n; return 0; }
static int rb_skip(struct rbuf*r, mc_usize n){ if(rb_need(r,n)) return -1; r->off+=n; return 0; }

static int mc_tls13_parse_server_hello(const mc_u8 *msg, mc_usize msg_len, struct mc_tls13_server_hello *out) {
	if (!msg || !out) return -1;
	mc_memset(out,0,sizeof(*out));
	struct rbuf r; if (rb_init(&r,msg,msg_len)!=0) return -1;

	mc_u8 hs_type=0; mc_u32 hs_len=0;
	if (rb_get_u8(&r,&hs_type)!=0) return -1;
	if (rb_get_u24(&r,&hs_len)!=0) return -1;
	if (hs_type!=MC_TLS13_HANDSHAKE_SERVER_HELLO) return -1;
	if (r.off + (mc_usize)hs_len != r.len) return -1;

	if (rb_get_u16(&r,&out->legacy_version)!=0) return -1;
	if (rb_get_bytes(&r,out->random,32)!=0) return -1;
	if (rb_get_u8(&r,&out->legacy_session_id_echo_len)!=0) return -1;
	if (rb_skip(&r,(mc_usize)out->legacy_session_id_echo_len)!=0) return -1;
	if (rb_get_u16(&r,&out->cipher_suite)!=0) return -1;
	if (rb_get_u8(&r,&out->legacy_compression_method)!=0) return -1;

	mc_u16 exts_len=0; if (rb_get_u16(&r,&exts_len)!=0) return -1;
	if (rb_need(&r,exts_len)!=0) return -1;
	mc_usize exts_end=r.off+(mc_usize)exts_len;
	while (r.off<exts_end){
		mc_u16 ext_type=0, ext_len2=0;
		if (rb_get_u16(&r,&ext_type)!=0) return -1;
		if (rb_get_u16(&r,&ext_len2)!=0) return -1;
		if (rb_need(&r,ext_len2)!=0) return -1;
		mc_usize ext_start=r.off;
		if (ext_type==MC_TLS13_EXT_SUPPORTED_VERSIONS){
			mc_u16 v=0; if (ext_len2!=2) return -1;
			if (rb_get_u16(&r,&v)!=0) return -1;
			out->selected_version=v;
		}else if (ext_type==MC_TLS13_EXT_KEY_SHARE){
			mc_u16 group=0,klen=0;
			if (rb_get_u16(&r,&group)!=0) return -1;
			if (rb_get_u16(&r,&klen)!=0) return -1;
			if (klen>32) return -1;
			if (rb_get_bytes(&r,out->key_share,klen)!=0) return -1;
			out->key_share_group=group;
			out->key_share_len=klen;
		}else{
			if (rb_skip(&r,ext_len2)!=0) return -1;
		}
		if (r.off != ext_start + (mc_usize)ext_len2) return -1;
	}
	return (r.off==exts_end)?0:-1;
}

// TLS record
#define MC_TLS_RECORD_HEADER_SIZE 5
#define MC_TLS_CONTENT_CHANGE_CIPHER_SPEC 20
#define MC_TLS_CONTENT_ALERT 21
#define MC_TLS_CONTENT_HANDSHAKE 22
#define MC_TLS_CONTENT_APPLICATION_DATA 23

static mc_u16 load_be16(const mc_u8 *p){ return (mc_u16)(((mc_u16)p[0]<<8)|(mc_u16)p[1]); }
static void make_nonce(mc_u8 nonce[12], const mc_u8 iv[12], mc_u64 seq){
	mc_memcpy(nonce,iv,12);
	for (int i=0;i<8;i++) nonce[11-i] ^= (mc_u8)(seq>>(8*i));
}

static int mc_tls_record_encrypt(const mc_u8 key[16], const mc_u8 iv[12], mc_u64 seq, mc_u8 inner_type,
	const mc_u8 *plaintext, mc_usize pt_len, mc_u8 *record_out, mc_usize record_cap, mc_usize *record_len_out) {
	if (!record_out || !record_len_out) return -1;
	if (!plaintext && pt_len) return -1;

	mc_usize inner_len = pt_len + 1u;
	mc_usize ct_len = inner_len;
	mc_usize rec_len = MC_TLS_RECORD_HEADER_SIZE + ct_len + MC_GCM_TAG_SIZE;
	if (rec_len > record_cap || ct_len > 0xffffu) return -1;

	mc_u8 *hdr = record_out;
	hdr[0] = (mc_u8)MC_TLS_CONTENT_APPLICATION_DATA;
	hdr[1] = 0x03; hdr[2] = 0x03;
	store_be16(hdr+3,(mc_u16)(ct_len+MC_GCM_TAG_SIZE));

	mc_u8 nonce[12];
	make_nonce(nonce,iv,seq);

	mc_u8 *ct = record_out + MC_TLS_RECORD_HEADER_SIZE;
	if (pt_len) mc_memcpy(ct,plaintext,pt_len);
	ct[pt_len]=inner_type;

	mc_u8 tag[16];
	if (mc_aes128_gcm_encrypt(key,nonce,hdr,MC_TLS_RECORD_HEADER_SIZE,ct,inner_len,ct,tag)!=0) return -1;
	mc_memcpy(ct+ct_len,tag,16);

	*record_len_out = rec_len;
	return 0;
}
static int mc_tls_record_decrypt(const mc_u8 key[16], const mc_u8 iv[12], mc_u64 seq,
	const mc_u8 *record, mc_usize record_len, mc_u8 *inner_type_out, mc_u8 *plaintext_out, mc_usize plaintext_cap, mc_usize *pt_len_out) {
	if (!record || record_len < MC_TLS_RECORD_HEADER_SIZE + MC_GCM_TAG_SIZE) return -1;
	if (!inner_type_out || !plaintext_out || !pt_len_out) return -1;

	const mc_u8 *hdr = record;
	if (hdr[0] != (mc_u8)MC_TLS_CONTENT_APPLICATION_DATA) return -1;
	if (hdr[1] != 0x03 || hdr[2] != 0x03) return -1;

	mc_u16 len16 = load_be16(hdr+3);
	mc_usize enc_len = (mc_usize)len16;
	if (MC_TLS_RECORD_HEADER_SIZE + enc_len != record_len) return -1;
	if (enc_len < MC_GCM_TAG_SIZE) return -1;

	mc_usize ct_len = enc_len - MC_GCM_TAG_SIZE;
	const mc_u8 *ct = record + MC_TLS_RECORD_HEADER_SIZE;
	const mc_u8 *tag = ct + ct_len;
	if (ct_len > plaintext_cap) return -1;

	mc_u8 nonce[12];
	make_nonce(nonce,iv,seq);

	if (mc_aes128_gcm_decrypt(key,nonce,hdr,MC_TLS_RECORD_HEADER_SIZE,ct,ct_len,tag,plaintext_out)!=0) return -1;

	mc_usize i = ct_len;
	while (i>0 && plaintext_out[i-1]==0) i--;
	if (i==0) return -1;
	mc_u8 inner_type = plaintext_out[i-1];
	mc_usize content_len = i-1;

	*inner_type_out = inner_type;
	*pt_len_out = content_len;
	return 0;
}

// TLS client (from repo, with include spam removed)
#define MC_TLS13_HS_FINISHED 20

struct mc_tls13_client {
	mc_i32 fd;
	mc_u32 timeout_ms;
	mc_u8 c_ap_key[16];
	mc_u8 c_ap_iv[12];
	mc_u8 s_ap_key[16];
	mc_u8 s_ap_iv[12];
	mc_u64 c_ap_seq;
	mc_u64 s_ap_seq;
	int handshake_done;
};

static const mc_u8 *sha256_empty_hs_ptr(void) {
	return (const mc_u8 *)
	"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
	"\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
}
static int poll_one(mc_i32 fd, mc_i16 events, mc_u32 timeout_ms) {
	struct mc_pollfd pfd;
	pfd.fd=fd; pfd.events=events; pfd.revents=0;
	mc_i64 r = mc_sys_poll(&pfd,1,(mc_i32)timeout_ms);
	if (r<=0) return 0;
	return (pfd.revents & events) != 0;
}
static int read_exact_timeout(mc_i32 fd, void *buf, mc_usize len, mc_u32 timeout_ms) {
	mc_u8 *p=(mc_u8*)buf;
	mc_usize got=0;
	while (got<len){
		if (!poll_one(fd,MC_POLLIN,timeout_ms)) return 0;
		mc_i64 r=mc_sys_read(fd,p+got,len-got);
		if (r<=0) return 0;
		got += (mc_usize)r;
	}
	return 1;
}
static int write_all_timeout(mc_i32 fd, const void *buf, mc_usize len, mc_u32 timeout_ms) {
	const mc_u8 *p=(const mc_u8*)buf;
	mc_usize off=0;
	while (off<len){
		if (!poll_one(fd,MC_POLLOUT,timeout_ms)) return 0;
		mc_i64 w=mc_sys_write(fd,p+off,len-off);
		if (w<=0) return 0;
		off += (mc_usize)w;
	}
	return 1;
}
static int record_read_timeout(mc_i32 fd, mc_u32 timeout_ms, mc_u8 hdr[5], mc_u8 *payload, mc_usize payload_cap, mc_usize *out_len) {
	if (!hdr||!payload||!out_len) return 0;
	if (!read_exact_timeout(fd,hdr,5,timeout_ms)) return 0;
	mc_u16 rlen=(mc_u16)(((mc_u16)hdr[3]<<8)|(mc_u16)hdr[4]);
	if ((mc_usize)rlen>payload_cap) return 0;
	if (!read_exact_timeout(fd,payload,(mc_usize)rlen,timeout_ms)) return 0;
	*out_len=(mc_usize)rlen;
	return 1;
}
static int hs_append(mc_u8 *buf, mc_usize cap, mc_usize *io_len, const mc_u8 *p, mc_usize n) {
	if (!buf||!io_len) return -1;
	if (!p && n) return -1;
	if (*io_len + n > cap) return -1;
	if (n) mc_memcpy(buf + *io_len, p, n);
	*io_len += n;
	return 0;
}
static int hs_consume_one(mc_u8 *buf, mc_usize *io_len, mc_u8 *out_type, mc_u32 *out_body_len, mc_u8 *out_msg, mc_usize out_cap, mc_usize *out_msg_len) {
	if (!buf||!io_len||!out_type||!out_body_len||!out_msg||!out_msg_len) return -1;
	if (*io_len < 4u) return 1;
	mc_u8 ht=buf[0];
	mc_u32 hl=((mc_u32)buf[1]<<16)|((mc_u32)buf[2]<<8)|(mc_u32)buf[3];
	mc_usize total=4u+(mc_usize)hl;
	if (total>*io_len) return 1;
	if (total>out_cap) return -1;
	mc_memcpy(out_msg,buf,total);
	*out_type=ht; *out_body_len=hl; *out_msg_len=total;
	mc_usize rem=*io_len-total;
	if (rem) mc_memcpy(buf,buf+total,rem);
	*io_len=rem;
	return 0;
}
static int getrandom_best_effort(void *buf, mc_usize len) {
	mc_u8 *p=(mc_u8*)buf;
	mc_usize off=0;
	while (off<len){
		mc_i64 r=mc_sys_getrandom(p+off,len-off,0);
		if (r<=0) break;
		off += (mc_usize)r;
	}
	return off==len;
}
static void mc_tls13_client_init(struct mc_tls13_client *c, mc_i32 fd, mc_u32 timeout_ms) {
	if (!c) return;
	mc_memset(c,0,sizeof(*c));
	c->fd=fd;
	c->timeout_ms=timeout_ms;
}
static int mc_tls13_client_handshake(struct mc_tls13_client *c, const char *sni, mc_usize sni_len) {
	if (!c || c->fd < 0) return -1;
	if (sni && (sni_len==0 || sni_len>255u)) return -1;

	mc_u8 ch_random[32], ch_sid[32], x25519_priv[32], x25519_pub[32];
	(void)getrandom_best_effort(ch_random,sizeof(ch_random));
	(void)getrandom_best_effort(ch_sid,sizeof(ch_sid));
	(void)getrandom_best_effort(x25519_priv,sizeof(x25519_priv));
	mc_x25519_public(x25519_pub,x25519_priv);

	mc_u8 ch[2048];
	mc_usize ch_len=0;
	if (mc_tls13_build_client_hello(sni?sni:"", sni?sni_len:0, ch_random, ch_sid, sizeof(ch_sid), x25519_pub, ch, sizeof(ch), &ch_len) != 0) return -1;

	mc_u8 rec[5+2048];
	if (ch_len>2048) return -1;
	rec[0]=22; rec[1]=0x03; rec[2]=0x01;
	rec[3]=(mc_u8)((ch_len>>8)&0xFFu);
	rec[4]=(mc_u8)(ch_len&0xFFu);
	mc_memcpy(rec+5,ch,ch_len);
	if (!write_all_timeout(c->fd,rec,5+ch_len,c->timeout_ms)) return -1;

	// read until ServerHello
	mc_u8 rhdr[5], payload[65536], sh_msg[2048];
	mc_usize sh_len=0; int got_sh=0;
	for (int iter=0; iter<32; iter++){
		if (!read_exact_timeout(c->fd,rhdr,5,c->timeout_ms)) break;
		mc_u8 rtype=rhdr[0];
		mc_usize rlen=(mc_usize)((mc_u16)(((mc_u16)rhdr[3]<<8)|(mc_u16)rhdr[4]));
		if (rlen>sizeof(payload)) break;
		if (!read_exact_timeout(c->fd,payload,rlen,c->timeout_ms)) break;
		if (rtype!=22) continue;
		mc_usize off=0;
		while (off+4 <= rlen){
			mc_u8 ht=payload[off+0];
			mc_u32 hl=((mc_u32)payload[off+1]<<16)|((mc_u32)payload[off+2]<<8)|(mc_u32)payload[off+3];
			mc_usize htot=4u+(mc_usize)hl;
			if (off+htot>rlen) break;
			if (ht==MC_TLS13_HANDSHAKE_SERVER_HELLO){
				if (htot>sizeof(sh_msg)) break;
				mc_memcpy(sh_msg,payload+off,htot);
				sh_len=htot; got_sh=1; break;
			}
			off += htot;
		}
		if (got_sh) break;
	}
	if (!got_sh) return -1;

	struct mc_tls13_server_hello sh;
	if (mc_tls13_parse_server_hello(sh_msg,sh_len,&sh)!=0) return -1;

	struct mc_tls13_transcript t;
	mc_tls13_transcript_init(&t);
	mc_tls13_transcript_update(&t, ch, ch_len);
	mc_tls13_transcript_update(&t, sh_msg, sh_len);
	mc_u8 chsh_hash[32];
	mc_tls13_transcript_final(&t, chsh_hash);

	if (sh.key_share_group != MC_TLS13_GROUP_X25519 || sh.key_share_len != 32) return -1;
	if (sh.selected_version != 0x0304) return -1;

	mc_u8 ecdhe[32];
	if (mc_x25519_shared(ecdhe, x25519_priv, sh.key_share) != 0) return -1;

	mc_u8 zeros32[32]; mc_memset(zeros32,0,32);
	mc_u8 early[32];
	mc_hkdf_extract(zeros32,32,zeros32,32,early);

	mc_u8 derived[32];
	if (mc_tls13_derive_secret(early, "derived", sha256_empty_hs_ptr(), derived) != 0) return -1;

	mc_u8 handshake_secret[32];
	mc_hkdf_extract(derived,32,ecdhe,32,handshake_secret);

	mc_u8 c_hs[32], s_hs[32];
	if (mc_tls13_derive_secret(handshake_secret,"c hs traffic",chsh_hash,c_hs)!=0) return -1;
	if (mc_tls13_derive_secret(handshake_secret,"s hs traffic",chsh_hash,s_hs)!=0) return -1;

	mc_u8 c_key[16], c_iv[12], s_key[16], s_iv[12];
	if (mc_tls13_hkdf_expand_label(c_hs,"key",MC_NULL,0,c_key,16)!=0) return -1;
	if (mc_tls13_hkdf_expand_label(c_hs,"iv",MC_NULL,0,c_iv,12)!=0) return -1;
	if (mc_tls13_hkdf_expand_label(s_hs,"key",MC_NULL,0,s_key,16)!=0) return -1;
	if (mc_tls13_hkdf_expand_label(s_hs,"iv",MC_NULL,0,s_iv,12)!=0) return -1;

	mc_u64 s_hs_seq=0, c_hs_seq=0;
	int verified_server_finished=0;

	mc_u8 hs_buf[131072];
	mc_usize hs_buf_len=0;

	for (int iter=0; iter<256; iter++){
		mc_usize rlen=0;
		if (!record_read_timeout(c->fd,c->timeout_ms,rhdr,payload,sizeof(payload),&rlen)) break;
		mc_u8 rtype=rhdr[0];
		if (rtype==MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) continue;
		if (rtype==MC_TLS_CONTENT_ALERT) break;
		if (rtype!=MC_TLS_CONTENT_APPLICATION_DATA) continue;

		mc_u8 record[5+65536];
		mc_usize record_len=5u+rlen;
		mc_memcpy(record,rhdr,5);
		mc_memcpy(record+5,payload,rlen);

		mc_u8 inner_type=0;
		mc_u8 pt[65536];
		mc_usize pt_len=0;
		if (mc_tls_record_decrypt(s_key,s_iv,s_hs_seq,record,record_len,&inner_type,pt,sizeof(pt),&pt_len)!=0) break;
		s_hs_seq++;
		if (inner_type!=MC_TLS_CONTENT_HANDSHAKE) continue;
		if (hs_append(hs_buf,sizeof(hs_buf),&hs_buf_len,pt,pt_len)!=0) break;

		for (;;) {
			mc_u8 msg_type=0; mc_u32 msg_body_len=0;
			mc_u8 msg[65536]; mc_usize msg_len=0;
			int cr=hs_consume_one(hs_buf,&hs_buf_len,&msg_type,&msg_body_len,msg,sizeof(msg),&msg_len);
			if (cr==1) break;
			if (cr!=0) { iter=9999; break; }

			if (msg_type==MC_TLS13_HS_FINISHED){
				mc_u8 th_pre[32];
				mc_tls13_transcript_final(&t, th_pre);
				mc_u8 s_finished_key[32];
				if (mc_tls13_finished_key(s_hs,s_finished_key)!=0) { iter=9999; break; }
				mc_u8 expected_verify[32];
				mc_tls13_finished_verify_data(s_finished_key,th_pre,expected_verify);
				mc_memset(s_finished_key,0,32);
				if (msg_body_len!=32 || msg_len!=36) { iter=9999; break; }
				if (mc_memcmp(expected_verify,msg+4,32)!=0) { iter=9999; break; }
				verified_server_finished=1;
			}

			mc_tls13_transcript_update(&t,msg,msg_len);
			if (msg_type==MC_TLS13_HS_FINISHED) break;
		}
		if (verified_server_finished) break;
	}
	if (!verified_server_finished) return -1;

	mc_u8 th_post_server_finished[32];
	mc_tls13_transcript_final(&t, th_post_server_finished);

	mc_u8 c_finished_key[32];
	if (mc_tls13_finished_key(c_hs,c_finished_key)!=0) return -1;
	mc_u8 c_verify[32];
	mc_tls13_finished_verify_data(c_finished_key,th_post_server_finished,c_verify);
	mc_memset(c_finished_key,0,32);

	mc_u8 cfin[4+32];
	cfin[0]=(mc_u8)MC_TLS13_HS_FINISHED; cfin[1]=0; cfin[2]=0; cfin[3]=32;
	mc_memcpy(cfin+4,c_verify,32);

	mc_u8 cfin_record[5+1024];
	mc_usize cfin_record_len=0;
	if (mc_tls_record_encrypt(c_key,c_iv,c_hs_seq,MC_TLS_CONTENT_HANDSHAKE,cfin,sizeof(cfin),cfin_record,sizeof(cfin_record),&cfin_record_len)!=0) return -1;
	c_hs_seq++;
	if (!write_all_timeout(c->fd,cfin_record,cfin_record_len,c->timeout_ms)) return -1;
	mc_tls13_transcript_update(&t,cfin,sizeof(cfin));

	mc_u8 derived2[32];
	if (mc_tls13_derive_secret(handshake_secret,"derived",sha256_empty_hs_ptr(),derived2)!=0) return -1;

	mc_u8 master_secret[32], zeros32b[32];
	mc_memset(zeros32b,0,32);
	mc_hkdf_extract(derived2,32,zeros32b,32,master_secret);

	mc_u8 c_ap[32], s_ap[32];
	if (mc_tls13_derive_secret(master_secret,"c ap traffic",th_post_server_finished,c_ap)!=0) return -1;
	if (mc_tls13_derive_secret(master_secret,"s ap traffic",th_post_server_finished,s_ap)!=0) return -1;
	mc_memset(master_secret,0,32);

	mc_u8 c_ap_key[16], c_ap_iv[12], s_ap_key[16], s_ap_iv[12];
	if (mc_tls13_hkdf_expand_label(c_ap,"key",MC_NULL,0,c_ap_key,16)!=0) return -1;
	if (mc_tls13_hkdf_expand_label(c_ap,"iv",MC_NULL,0,c_ap_iv,12)!=0) return -1;
	if (mc_tls13_hkdf_expand_label(s_ap,"key",MC_NULL,0,s_ap_key,16)!=0) return -1;
	if (mc_tls13_hkdf_expand_label(s_ap,"iv",MC_NULL,0,s_ap_iv,12)!=0) return -1;

	c->c_ap_seq=0; c->s_ap_seq=0;
	mc_memcpy(c->c_ap_key,c_ap_key,16); mc_memcpy(c->c_ap_iv,c_ap_iv,12);
	mc_memcpy(c->s_ap_key,s_ap_key,16); mc_memcpy(c->s_ap_iv,s_ap_iv,12);
	c->handshake_done=1;

	// wipe some
	mc_memset(x25519_priv,0,32);
	mc_memset(ecdhe,0,32);
	mc_memset(handshake_secret,0,32);
	mc_memset(c_hs,0,32); mc_memset(s_hs,0,32);
	mc_memset(c_key,0,16); mc_memset(c_iv,0,12);
	mc_memset(s_key,0,16); mc_memset(s_iv,0,12);

	return 0;
}
static mc_i64 mc_tls13_client_write_app(struct mc_tls13_client *c, const mc_u8 *buf, mc_usize len) {
	if (!c || !c->handshake_done) return -1;
	if (!buf && len) return -1;
	mc_usize off=0;
	while (off<len){
		mc_usize chunk=len-off; if (chunk>16384u) chunk=16384u;
		mc_u8 rec[5+16384+64];
		mc_usize rec_len=0;
		if (mc_tls_record_encrypt(c->c_ap_key,c->c_ap_iv,c->c_ap_seq,MC_TLS_CONTENT_APPLICATION_DATA,buf+off,chunk,rec,sizeof(rec),&rec_len)!=0) return -1;
		c->c_ap_seq++;
		if (!write_all_timeout(c->fd,rec,rec_len,c->timeout_ms)) return -1;
		off += chunk;
	}
	return (mc_i64)len;
}
static mc_i64 mc_tls13_client_read_app(struct mc_tls13_client *c, mc_u8 *buf, mc_usize cap) {
	if (!c || !c->handshake_done || !buf || cap==0) return -1;
	for (;;) {
		mc_u8 rhdr[5], payload[65536];
		mc_usize rlen=0;
		if (!record_read_timeout(c->fd,c->timeout_ms,rhdr,payload,sizeof(payload),&rlen)) return -1;
		mc_u8 rtype=rhdr[0];
		if (rtype==MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) continue;
		if (rtype==MC_TLS_CONTENT_ALERT) return 0;
		if (rtype!=MC_TLS_CONTENT_APPLICATION_DATA) continue;

		mc_u8 record[5+65536];
		mc_usize record_len=5u+rlen;
		mc_memcpy(record,rhdr,5);
		mc_memcpy(record+5,payload,rlen);

		mc_u8 inner_type=0;
		mc_u8 pt[65536];
		mc_usize pt_len=0;
		if (mc_tls_record_decrypt(c->s_ap_key,c->s_ap_iv,c->s_ap_seq,record,record_len,&inner_type,pt,sizeof(pt),&pt_len)!=0) return -1;
		c->s_ap_seq++;

		if (inner_type==MC_TLS_CONTENT_APPLICATION_DATA){
			if (pt_len>cap) pt_len=cap;
			mc_memcpy(buf,pt,pt_len);
			return (mc_i64)pt_len;
		}
		if (inner_type==MC_TLS_CONTENT_ALERT){
			if (pt_len>=2 && pt[1]==0) return 0;
			return -1;
		}
	}
}

// --- wtf app code (DNS/HTTP/JSON) ---
static mc_u16 mc_bswap16(mc_u16 x){ return (mc_u16)((x<<8)|(x>>8)); }
static mc_u16 mc_htons(mc_u16 x){ return mc_bswap16(x); }

static int mc_hexval(mc_u8 c){
	if (c>='0'&&c<='9') return (int)(c-'0');
	if (c>='a'&&c<='f') return 10+(int)(c-'a');
	if (c>='A'&&c<='F') return 10+(int)(c-'A');
	return -1;
}

static mc_u16 dns_pick_id(void){
	mc_u16 id=0;
	mc_i64 r=mc_sys_getrandom(&id,sizeof(id),0);
	if (r==(mc_i64)sizeof(id) && id!=0) return id;
	// fallback: some nonzero constant
	return 1;
}

static int dns_encode_qname(mc_u8 *dst, mc_usize cap, const char *name, mc_usize *io_off){
	mc_usize off=*io_off;
	const char *p=name;
	while (*p){
		const char *label=p;
		mc_usize len=0;
		while (*p && *p!='.'){ len++; p++; if (len>63) return 0; }
		if (off+1+len>=cap) return 0;
		dst[off++]=(mc_u8)len;
		for (mc_usize i=0;i<len;i++) dst[off++]=(mc_u8)label[i];
		if (*p=='.') p++;
	}
	if (off+1>cap) return 0;
	dst[off++]=0;
	*io_off=off;
	return 1;
}

static int dns_name_skip(const mc_u8 *msg, mc_usize msglen, mc_usize off, mc_usize *out_off){
	mc_usize o=off;
	for(;;){
		if (o>=msglen) return 0;
		mc_u8 len=msg[o++];
		if (len==0){ *out_off=o; return 1; }
		if ((len&0xC0u)==0xC0u){ if (o>=msglen) return 0; o++; *out_off=o; return 1; }
		if (len>63) return 0;
		if (o+len>msglen) return 0;
		o+=len;
	}
}

// UDP-only AAAA resolver (no TCP fallback)
static int dns6_resolve_first_aaaa(const mc_u8 server_ip[16], const char *name, mc_u32 timeout_ms, mc_u8 out_ip[16]){
	struct mc_sockaddr_in6 sa;
	mc_memset(&sa,0,sizeof(sa));
	sa.sin6_family=(mc_u16)MC_AF_INET6;
	sa.sin6_port=mc_htons(53);
	for (int i=0;i<16;i++) sa.sin6_addr.s6_addr[i]=server_ip[i];

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_DGRAM | MC_SOCK_CLOEXEC, MC_IPPROTO_UDP);
	if (fd < 0) return 0;

	// connect UDP socket so we can use write/read
	if (mc_sys_connect((mc_i32)fd, &sa, (mc_u32)sizeof(sa)) < 0) { (void)mc_sys_close((mc_i32)fd); return 0; }

	mc_u8 q[512];
	mc_usize qn=12;
	mc_u16 id=dns_pick_id();
	q[0]=(mc_u8)(id>>8); q[1]=(mc_u8)(id&0xFFu);
	q[2]=0x01; q[3]=0x00;
	q[4]=0; q[5]=1; q[6]=0; q[7]=0; q[8]=0; q[9]=0; q[10]=0; q[11]=0;

	if (!dns_encode_qname(q,sizeof(q),name,&qn)) { (void)mc_sys_close((mc_i32)fd); return 0; }
	if (qn+4>sizeof(q)) { (void)mc_sys_close((mc_i32)fd); return 0; }
	q[qn++]=0x00; q[qn++]=0x1c; // AAAA
	q[qn++]=0x00; q[qn++]=0x01; // IN

	if (mc_write_all((mc_i32)fd,q,qn) < 0) { (void)mc_sys_close((mc_i32)fd); return 0; }

	struct mc_pollfd pfd;
	pfd.fd=(mc_i32)fd; pfd.events=MC_POLLIN; pfd.revents=0;
	if (mc_sys_poll(&pfd,1,(mc_i32)timeout_ms) <= 0 || (pfd.revents & MC_POLLIN)==0) { (void)mc_sys_close((mc_i32)fd); return 0; }

	mc_u8 resp[1024];
	mc_i64 rr = mc_sys_read((mc_i32)fd, resp, sizeof(resp));
	(void)mc_sys_close((mc_i32)fd);
	if (rr <= 0) return 0;
	mc_usize rn = (mc_usize)rr;

	if (rn < 12) return 0;
	if (resp[0] != (mc_u8)(id>>8) || resp[1] != (mc_u8)(id&0xFFu)) return 0;
	mc_u16 flags = (mc_u16)(((mc_u16)resp[2]<<8)|(mc_u16)resp[3]);
	if ((flags & 0x8000u) == 0) return 0;
	mc_u16 qd = (mc_u16)(((mc_u16)resp[4]<<8)|(mc_u16)resp[5]);
	mc_u16 an = (mc_u16)(((mc_u16)resp[6]<<8)|(mc_u16)resp[7]);
	if (qd != 1 || an == 0) return 0;

	mc_usize off=12, noff=0;
	if (!dns_name_skip(resp,rn,off,&noff)) return 0;
	off=noff;
	if (off+4>rn) return 0;
	off += 4;

	for (mc_u16 i=0;i<an;i++){
		if (!dns_name_skip(resp,rn,off,&noff)) return 0;
		off=noff;
		if (off+10>rn) return 0;
		mc_u16 atype=(mc_u16)(((mc_u16)resp[off]<<8)|(mc_u16)resp[off+1]);
		mc_u16 aclass=(mc_u16)(((mc_u16)resp[off+2]<<8)|(mc_u16)resp[off+3]);
		mc_u16 rdlen=(mc_u16)(((mc_u16)resp[off+8]<<8)|(mc_u16)resp[off+9]);
		off += 10;
		if (off+rdlen>rn) return 0;
		if (atype==0x001cu && aclass==0x0001u && rdlen==16){
			mc_memcpy(out_ip, resp+off, 16);
			return 1;
		}
		off += rdlen;
	}
	return 0;
}

static int set_nonblock(mc_i32 fd, int enabled) {
	mc_i64 fl = mc_sys_fcntl(fd, MC_F_GETFL, 0);
	if (fl < 0) return 0;
	if (enabled) fl |= MC_O_NONBLOCK;
	else fl &= ~((mc_i64)MC_O_NONBLOCK);
	return mc_sys_fcntl(fd, MC_F_SETFL, fl) >= 0;
}
static int connect_with_timeout(mc_i32 fd, const void *sa, mc_u32 salen, mc_u32 timeout_ms) {
	if (timeout_ms == 0) return mc_sys_connect(fd, sa, salen) >= 0;
	if (!set_nonblock(fd,1)) return 0;
	mc_i64 r = mc_sys_connect(fd, sa, salen);
	if (r >= 0) { (void)set_nonblock(fd,0); return 1; }
	if (r != (mc_i64)-MC_EINPROGRESS) { (void)set_nonblock(fd,0); return 0; }
	struct mc_pollfd pfd; pfd.fd=fd; pfd.events=MC_POLLOUT; pfd.revents=0;
	mc_i64 pr = mc_sys_poll(&pfd,1,(mc_i32)timeout_ms);
	if (pr <= 0 || (pfd.revents & MC_POLLOUT)==0) { (void)set_nonblock(fd,0); return 0; }
	mc_i32 err=0; mc_u32 errlen=(mc_u32)sizeof(err);
	r = mc_sys_getsockopt(fd, MC_SOL_SOCKET, MC_SO_ERROR, &err, &errlen);
	(void)set_nonblock(fd,0);
	if (r < 0 || err != 0) return 0;
	return 1;
}

static int url_encode(const char *in, char *out, mc_usize cap) {
	static const char hex[] = "0123456789ABCDEF";
	mc_usize j=0;
	for (mc_usize i=0; in && in[i]; i++){
		mc_u8 c=(mc_u8)in[i];
		int safe=0;
		if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')) safe=1;
		if (c=='-'||c=='_'||c=='.'||c=='~') safe=1;
		if (safe){
			if (j+1>=cap) return 0;
			out[j++]=(char)c;
		}else{
			if (j+3>=cap) return 0;
			out[j++]='%';
			out[j++]=hex[(c>>4)&0xFu];
			out[j++]=hex[c&0xFu];
		}
	}
	if (!cap) return 0;
	out[j]=0;
	return 1;
}

static const char *json_skip_ws(const char *p){ while (p && (*p==' '||*p=='\t'||*p=='\r'||*p=='\n')) p++; return p; }
static int json_parse_string(const char *p, char *out, mc_usize cap, const char **out_next){
	if (!p || *p!='"') return 0;
	p++;
	mc_usize j=0;
	while (*p){
		char c=*p++;
		if (c=='"'){
			if (cap) out[j < cap ? j : (cap-1)] = 0;
			if (out_next) *out_next = p;
			return (j < cap);
		}
		if (c=='\\'){
			char e=*p;
			if (!e) return 0;
			p++;
			if (e=='n') c='\n';
			else if (e=='t') c='\t';
			else if (e=='r') c='\r';
			else if (e=='b') c='\b';
			else if (e=='f') c='\f';
			else if (e=='"') c='"';
			else if (e=='\\') c='\\';
			else if (e=='/') c='/';
			else if (e=='u'){
				for (int k=0;k<4;k++){ if (!*p) return 0; p++; }
				c='?';
			}else c=e;
		}
		if (j+1>=cap) return 0;
		out[j++]=c;
	}
	return 0;
}
static int json_extract_string_value(const char *json, const char *key, char *out, mc_usize cap) {
	if (!json || !key || !out || cap==0) return 0;
	const char *p=json;
	while (*p){
		if (*p!='"'){ p++; continue; }
		p++;
		const char *q=p; const char *k=key;
		while (*k && *q && *q==*k){ q++; k++; }
		if (*k==0 && *q=='"'){
			p=q+1;
			p=json_skip_ws(p);
			if (*p!=':') continue;
			p++; p=json_skip_ws(p);
			if (*p!='"') return 0;
			return json_parse_string(p,out,cap,MC_NULL);
		}
		while (*p && *p!='"'){ if (*p=='\\' && p[1]) p+=2; else p++; }
		if (*p=='"') p++;
	}
	return 0;
}
static int json_opensearch_first_title(const char *json, char *out, mc_usize cap){
	const char *p=json_skip_ws(json);
	if (!p || *p!='[') return 0;
	p++; p=json_skip_ws(p);
	if (*p!='"') return 0;
	char tmp[256];
	if (!json_parse_string(p,tmp,sizeof(tmp),&p)) return 0;
	p=json_skip_ws(p);
	if (*p!=',') return 0;
	p++; p=json_skip_ws(p);
	if (*p!='[') return 0;
	p++; p=json_skip_ws(p);
	if (*p==']') return 0;
	if (*p!='"') return 0;
	return json_parse_string(p,out,cap,MC_NULL);
}

static int http_parse_status(const char *hdr, mc_usize hdr_len, int *out_status){
	if (!hdr || hdr_len<12 || !out_status) return 0;
	int s=0; mc_usize i=0;
	while (i<hdr_len && hdr[i]!=' ') i++;
	while (i<hdr_len && hdr[i]==' ') i++;
	for (int k=0;k<3;k++){
		if (i>=hdr_len) return 0;
		char c=hdr[i++];
		if (c<'0'||c>'9') return 0;
		s=s*10+(c-'0');
	}
	*out_status=s;
	return 1;
}
static int header_has_token_ci(const char *hdr, mc_usize hdr_len, const char *needle){
	mc_usize nlen=mc_strlen(needle);
	if (nlen==0 || hdr_len<nlen) return 0;
	for (mc_usize i=0;i+nlen<=hdr_len;i++){
		int ok=1;
		for (mc_usize j=0;j<nlen;j++){
			char a=hdr[i+j], b=needle[j];
			if (a>='A'&&a<='Z') a=(char)(a-'A'+'a');
			if (b>='A'&&b<='Z') b=(char)(b-'A'+'a');
			if (a!=b){ ok=0; break; }
		}
		if (ok) return 1;
	}
	return 0;
}
static int http_chunked_decode(const char *in, mc_usize in_len, char *out, mc_usize out_cap, mc_usize *out_len){
	mc_usize o=0,i=0;
	while (i<in_len){
		mc_u64 sz=0; int any=0;
		while (i<in_len){
			char c=in[i];
			if (c=='\r'||c=='\n'||c==';') break;
			int hv=mc_hexval((mc_u8)c);
			if (hv<0) return 0;
			sz=(sz<<4)|(mc_u64)hv;
			any=1; i++;
		}
		if (!any) return 0;
		while (i<in_len && in[i] != '\n') i++;
		if (i>=in_len) return 0;
		i++;
		if (sz==0){
			if (out_len) *out_len=o;
			if (o<out_cap) out[o]=0;
			return 1;
		}
		if (sz>(mc_u64)(in_len-i)) return 0;
		if (o+(mc_usize)sz+1>out_cap) return 0;
		mc_memcpy(out+o,in+i,(mc_usize)sz);
		o+=(mc_usize)sz;
		i+=(mc_usize)sz;
		if (i+1>=in_len) return 0;
		if (in[i]=='\r') i++;
		if (i>=in_len || in[i]!='\n') return 0;
		i++;
	}
	return 0;
}

static int cstr_cat2(char *dst, mc_usize cap, const char *a, const char *b){
	if (!dst||cap==0) return 0;
	if (!a) a="";
	if (!b) b="";
	mc_usize al=mc_strlen(a), bl=mc_strlen(b);
	if (al+bl+1>cap) return 0;
	mc_memcpy(dst,a,al);
	mc_memcpy(dst+al,b,bl);
	dst[al+bl]=0;
	return 1;
}
static int cstr_cat3(char *dst, mc_usize cap, const char *a, const char *b, const char *c){
	if (!dst||cap==0) return 0;
	if (!a) a="";
	if (!b) b="";
	if (!c) c="";
	mc_usize al=mc_strlen(a), bl=mc_strlen(b), cl=mc_strlen(c);
	if (al+bl+cl+1>cap) return 0;
	mc_memcpy(dst,a,al);
	mc_memcpy(dst+al,b,bl);
	mc_memcpy(dst+al+bl,c,cl);
	dst[al+bl+cl]=0;
	return 1;
}
static inline __attribute__((always_inline)) void join_query(int argc, char **argv, int start, char *out, mc_usize cap){
	mc_usize n=0;
	for (int i=start;i<argc && argv[i];i++){
		if (i>start && n+1<cap) out[n++]='_';
		for (const char *p=argv[i]; *p && n+1<cap; p++) out[n++]=(*p==' ')?'_':*p;
	}
	if (cap) out[n<cap?n:(cap-1)]=0;
}

static int https_get_raw(const char *argv0, const char *host, const char *path, char *out, mc_usize out_cap, mc_usize *out_len){
	(void)argv0;
	if (!host||!path||!out||!out_len) return 0;
	*out_len=0;
	mc_usize host_len=mc_strlen(host);
	mc_usize path_len=mc_strlen(path);
	if (host_len==0||host_len>255u) return 0;
	if (path_len==0||path[0]!='/'||path_len>2048u) return 0;

	mc_u8 dns_server[16]; mc_memcpy(dns_server, mc_dns_google_v6, 16);

	mc_u8 dst_ip[16];
	if (!dns6_resolve_first_aaaa(dns_server, host, 5000, dst_ip)) return 0;

	struct mc_sockaddr_in6 dst;
	mc_memset(&dst,0,sizeof(dst));
	dst.sin6_family=(mc_u16)MC_AF_INET6;
	dst.sin6_port=mc_htons(443);
	for (int k=0;k<16;k++) dst.sin6_addr.s6_addr[k]=dst_ip[k];

	mc_i64 fd=mc_sys_socket(MC_AF_INET6, MC_SOCK_STREAM|MC_SOCK_CLOEXEC, MC_IPPROTO_TCP);
	if (fd<0) return 0;
	if (!connect_with_timeout((mc_i32)fd,&dst,(mc_u32)sizeof(dst),5000)){
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	struct mc_tls13_client c;
	mc_tls13_client_init(&c,(mc_i32)fd,5000);
	if (mc_tls13_client_handshake(&c,host,host_len)!=0){
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	char req[4096];
	mc_usize req_len=0;
	{
		static const char p0[]="GET ";
		static const char p1[]=" HTTP/1.1\r\nHost:";
		static const char p2[]="\r\nUser-Agent:https://github.com/mathiasschindler/wikipedia-terminal-facts\r\nConnection:close\r\n\r\n";
		mc_usize l0=sizeof(p0)-1u, l1=sizeof(p1)-1u, l2=sizeof(p2)-1u;
		mc_usize need=l0+path_len+l1+host_len+l2;
		if (need>sizeof(req)){ (void)mc_sys_close((mc_i32)fd); return 0; }
		mc_memcpy(req+req_len,p0,l0); req_len+=l0;
		mc_memcpy(req+req_len,path,path_len); req_len+=path_len;
		mc_memcpy(req+req_len,p1,l1); req_len+=l1;
		mc_memcpy(req+req_len,host,host_len); req_len+=host_len;
		mc_memcpy(req+req_len,p2,l2); req_len+=l2;
	}

	if (mc_tls13_client_write_app(&c,(const mc_u8*)req,req_len)<0){
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	for(;;){
		mc_u8 buf[8192];
		mc_i64 rn=mc_tls13_client_read_app(&c,buf,sizeof(buf));
		if (rn>0){
			mc_usize n=(mc_usize)rn;
			if (*out_len+n>out_cap){ (void)mc_sys_close((mc_i32)fd); return 0; }
			mc_memcpy(out+*out_len,buf,n);
			*out_len += n;
			continue;
		}
		if (rn==0) break;
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	(void)mc_sys_close((mc_i32)fd);
	if (*out_len<out_cap) out[*out_len]=0;
	return 1;
}

static int https_get_json_body(const char *argv0, const char *host, const char *path,
	char *json_out, mc_usize json_cap, int *status_out) {
	static char resp[262144];
	mc_usize rn=0;
	if (!https_get_raw(argv0,host,path,resp,sizeof(resp)-1u,&rn)) return 0;

	mc_usize hdr_end=0;
	for (mc_usize i=0;i+3<rn;i++){
		if (resp[i]=='\r'&&resp[i+1]=='\n'&&resp[i+2]=='\r'&&resp[i+3]=='\n'){ hdr_end=i+4; break; }
	}
	if (!hdr_end) return 0;

	int status=0;
	if (!http_parse_status(resp,hdr_end,&status)) return 0;
	if (status_out) *status_out=status;

	const char *body=resp+hdr_end;
	mc_usize body_len=rn-hdr_end;

	if (header_has_token_ci(resp,hdr_end,"transfer-encoding: chunked")){
		mc_usize json_len=0;
		if (!http_chunked_decode(body,body_len,json_out,json_cap,&json_len)) return 0;
		return 1;
	}
	if (body_len+1>json_cap) return 0;
	mc_memcpy(json_out,body,body_len);
	json_out[body_len]=0;
	return 1;
}

static int wiki_get_summary(const char *argv0, const char *lang, const char *title, char *out, mc_usize cap){
	(void)argv0;
	char host[64];
	if (!cstr_cat2(host,sizeof(host),lang,".wikipedia.org")) return -1;
	char enc_title[256];
	if (!url_encode(title,enc_title,sizeof(enc_title))) return -1;
	char path[512];
	if (!cstr_cat2(path,sizeof(path),"/api/rest_v1/page/summary/",enc_title)) return -1;

	char body2[262144];
	int status=0;
	if (!https_get_json_body(argv0,host,path,body2,sizeof(body2),&status)) return -1;
	if (status==404) return 0;
	if (status!=200) return -1;
	if (!json_extract_string_value(body2,"extract",out,cap)) return -1;
	return 1;
}
static int wiki_search(const char *argv0, const char *lang, const char *query, char *out_title, mc_usize cap){
	(void)argv0;
	char host[64];
	if (!cstr_cat2(host,sizeof(host),lang,".wikipedia.org")) return 0;
	char enc_q[256];
	if (!url_encode(query,enc_q,sizeof(enc_q))) return 0;
	char path[768];
	if (!cstr_cat3(path,sizeof(path),"/w/api.php?action=opensearch&search=",enc_q,"&limit=1&format=json")) return 0;

	char body2[262144];
	int status=0;
	if (!https_get_json_body(argv0,host,path,body2,sizeof(body2),&status)) return 0;
	if (status!=200) return 0;
	return json_opensearch_first_title(body2,out_title,cap);
}

// --- entrypoint (minimal _start like your mc_start.c) ---
int main(int argc, char **argv);

__attribute__((noreturn, used, noinline)) static void mc_start_c(long *sp) {
	int argc = (int)sp[0];
	char **argv = (char **)(sp + 1);
	mc_exit((mc_i32)main(argc, argv));
}
__attribute__((naked, noreturn)) void _start(void) {
	__asm__ volatile(
		"mov %rsp, %rdi\n"
		"andq $-16, %rsp\n"
		"call mc_start_c\n"
	);
}

int main(int argc, char **argv) {
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "wtf";
	const char *lang = "en";
	int i = 1;
	if (i < argc && argv[i] && argv[i][0]=='-' && argv[i][1]=='l' && argv[i][2]==0) {
		if (i + 1 < argc) { lang = argv[i + 1]; i += 2; }
		else return 1;
	}
	if (i >= argc) return 1;

	char query[256];
	join_query(argc, argv, i, query, sizeof(query));
	if (query[0] == 0) return 1;

	char extract[32768];
	int rc = wiki_get_summary(argv0, lang, query, extract, sizeof(extract));
	if (rc == 0) {
		char found[256];
		if (wiki_search(argv0, lang, query, found, sizeof(found))) {
			rc = wiki_get_summary(argv0, lang, found, extract, sizeof(extract));
		}
	}
	if (rc <= 0) return 1;

	(void)mc_write_str(1, extract);
	if (extract[0] && extract[mc_strlen(extract) - 1] != '\n') (void)mc_write_str(1, "\n");
	return 0;
}