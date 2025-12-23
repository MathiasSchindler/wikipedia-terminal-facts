#include "mc_min.h"
#include "mc_min.h"
#include "mc_min.h"

// wtf — Wikipedia Terminal Facts
// Minimal Wikipedia client using monacc's TLS 1.3 implementation.

static mc_u16 mc_bswap16(mc_u16 x) {
	return (mc_u16)((mc_u16)(x << 8) | (mc_u16)(x >> 8));
}

static mc_u16 mc_htons(mc_u16 x) {
	return mc_bswap16(x);
}

static int mc_hexval(mc_u8 c) {
	if (c >= (mc_u8)'0' && c <= (mc_u8)'9') return (int)(c - (mc_u8)'0');
	if (c >= (mc_u8)'a' && c <= (mc_u8)'f') return 10 + (int)(c - (mc_u8)'a');
	if (c >= (mc_u8)'A' && c <= (mc_u8)'F') return 10 + (int)(c - (mc_u8)'A');
	return -1;
}

// Strict IPv6 literal parser.
// Supports :: compression. No IPv4-embedded form. No zone index (%eth0).
static int parse_ipv6_literal(const char *s, mc_u8 out[16]) {
	if (!s || !*s) return 0;
	for (const char *p = s; *p; p++) {
		if (*p == '%') return 0;
	}

	mc_u16 words[8];
	for (int i = 0; i < 8; i++) words[i] = 0;
	int nwords = 0;
	int compress_at = -1;

	const char *p = s;
	if (*p == ':') {
		p++;
		if (*p != ':') return 0;
		compress_at = 0;
		p++;
	}

	while (*p) {
		if (nwords >= 8) return 0;

		mc_u32 v = 0;
		int nd = 0;
		while (*p) {
			int hv = mc_hexval((mc_u8)*p);
			if (hv < 0) break;
			v = (v << 4) | (mc_u32)hv;
			nd++;
			if (nd > 4) return 0;
			p++;
		}
		if (nd == 0) return 0;
		words[nwords++] = (mc_u16)v;

		if (*p == 0) break;
		if (*p != ':') return 0;
		p++;
		if (*p == 0) return 0;
		if (*p == ':') {
			if (compress_at >= 0) return 0;
			compress_at = nwords;
			p++;
			if (*p == 0) break;
		}
	}

	if (compress_at >= 0) {
		int zeros = 8 - nwords;
		if (zeros < 0) return 0;
		for (int i = nwords - 1; i >= compress_at; i--) {
			words[i + zeros] = words[i];
		}
		for (int i = 0; i < zeros; i++) {
			words[compress_at + i] = 0;
		}
		nwords = 8;
	}

	if (nwords != 8) return 0;

	for (int i = 0; i < 8; i++) {
		out[i * 2 + 0] = (mc_u8)((words[i] >> 8) & 0xFFu);
		out[i * 2 + 1] = (mc_u8)(words[i] & 0xFFu);
	}
	return 1;
}

static int resolv_conf_pick_v6(mc_u8 out_server[16]) {
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, "/etc/resolv.conf", MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) return 0;

	char buf[4096];
	mc_i64 n = mc_sys_read((mc_i32)fd, buf, sizeof(buf) - 1);
	(void)mc_sys_close((mc_i32)fd);
	if (n <= 0) return 0;
	buf[(mc_usize)n] = 0;

	const char *p = buf;
	while (*p) {
		const char *line = p;
		while (*p && *p != '\n') p++;
		const char *end = p;
		if (*p == '\n') p++;

		while (line < end && (*line == ' ' || *line == '\t')) line++;
		if (line >= end || *line == '#') continue;

		const char *kw = "nameserver";
		mc_usize kwlen = 10;
		if ((mc_usize)(end - line) < kwlen) continue;
		int ok = 1;
		for (mc_usize i = 0; i < kwlen; i++) {
			if (line[i] != kw[i]) {
				ok = 0;
				break;
			}
		}
		if (!ok) continue;
		const char *q = line + kwlen;
		if (q >= end || !(*q == ' ' || *q == '\t')) continue;
		while (q < end && (*q == ' ' || *q == '\t')) q++;
		if (q >= end) continue;

		const char *tok = q;
		while (q < end && !(*q == ' ' || *q == '\t' || *q == '#')) q++;
		mc_usize tlen = (mc_usize)(q - tok);
		if (tlen == 0 || tlen >= 128) continue;
		char tmp[128];
		for (mc_usize i = 0; i < tlen; i++) tmp[i] = tok[i];
		tmp[tlen] = 0;
		if (parse_ipv6_literal(tmp, out_server)) {
			return 1;
		}
	}

	return 0;
}

static mc_u16 dns_pick_id(void) {
	mc_u16 id = 0;
	mc_i64 r = mc_sys_getrandom(&id, sizeof(id), 0);
	if (r == (mc_i64)sizeof(id) && id != 0) return id;

	struct mc_timespec ts;
	(void)mc_sys_clock_gettime(MC_CLOCK_MONOTONIC, &ts);
	mc_u64 mix = (mc_u64)ts.tv_nsec ^ ((mc_u64)ts.tv_sec << 32) ^ (mc_u64)(mc_usize)(void *)&id;
	id = (mc_u16)(mix & 0xFFFFu);
	if (id == 0) id = 1;
	return id;
}

static int dns_encode_qname(mc_u8 *dst, mc_usize cap, const char *name, mc_usize *io_off) {
	mc_usize off = *io_off;
	const char *p = name;
	while (*p) {
		const char *label = p;
		mc_usize len = 0;
		while (*p && *p != '.') {
			len++;
			p++;
			if (len > 63) return 0;
		}
		if (off + 1 + len >= cap) return 0;
		dst[off++] = (mc_u8)len;
		for (mc_usize i = 0; i < len; i++) dst[off++] = (mc_u8)label[i];
		if (*p == '.') p++;
	}
	if (off + 1 > cap) return 0;
	dst[off++] = 0;
	*io_off = off;
	return 1;
}

static int dns_name_skip(const mc_u8 *msg, mc_usize msglen, mc_usize off, mc_usize *out_off) {
	mc_usize o = off;
	for (;;) {
		if (o >= msglen) return 0;
		mc_u8 len = msg[o++];
		if (len == 0) {
			*out_off = o;
			return 1;
		}
		if ((len & 0xC0u) == 0xC0u) {
			if (o >= msglen) return 0;
			o++;
			*out_off = o;
			return 1;
		}
		if (len > 63) return 0;
		if (o + len > msglen) return 0;
		o += len;
	}
}

static int dns6_resolve_first_aaaa(const char *argv0, const mc_u8 server_ip[16], mc_u16 server_port, const char *name, mc_u32 timeout_ms,
	mc_u8 out_ip[16]) {
	struct mc_sockaddr_in6 sa;
	mc_memset(&sa, 0, sizeof(sa));
	sa.sin6_family = (mc_u16)MC_AF_INET6;
	sa.sin6_port = mc_htons(server_port);
	for (int i = 0; i < 16; i++) sa.sin6_addr.s6_addr[i] = server_ip[i];

	for (int attempt = 0; attempt < 2; attempt++) {
		int use_tcp = (attempt == 1);
		mc_i32 stype = use_tcp ? MC_SOCK_STREAM : MC_SOCK_DGRAM;
		mc_i32 proto = use_tcp ? MC_IPPROTO_TCP : MC_IPPROTO_UDP;

		mc_i64 fd = mc_sys_socket(MC_AF_INET6, stype | MC_SOCK_CLOEXEC, proto);
		if (fd < 0) mc_die_errno(argv0, "socket", fd);

		mc_i64 r = mc_sys_connect((mc_i32)fd, &sa, (mc_u32)sizeof(sa));
		if (r < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}

		mc_u8 q[512];
		mc_usize qn = 12;
		mc_u16 id = dns_pick_id();
		q[0] = (mc_u8)(id >> 8);
		q[1] = (mc_u8)(id & 0xFFu);
		q[2] = 0x01;
		q[3] = 0x00;
		q[4] = 0;
		q[5] = 1;
		q[6] = 0;
		q[7] = 0;
		q[8] = 0;
		q[9] = 0;
		q[10] = 0;
		q[11] = 0;

		if (!dns_encode_qname(q, sizeof(q), name, &qn)) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		if (qn + 4 > sizeof(q)) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		q[qn++] = 0x00;
		q[qn++] = 0x1c;
		q[qn++] = 0x00;
		q[qn++] = 0x01;

		mc_u8 tcpbuf[2 + sizeof(q)];
		const void *sendbuf = q;
		mc_usize sendlen = qn;
		if (use_tcp) {
			tcpbuf[0] = (mc_u8)((qn >> 8) & 0xFFu);
			tcpbuf[1] = (mc_u8)(qn & 0xFFu);
			for (mc_usize i = 0; i < qn; i++) tcpbuf[2 + i] = q[i];
			sendbuf = tcpbuf;
			sendlen = 2 + qn;
		}

		r = mc_write_all((mc_i32)fd, sendbuf, sendlen);
		if (r < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}

		mc_u8 resp[1024];
		mc_usize rn = 0;
		if (use_tcp) {
			struct mc_pollfd pfd;
			pfd.fd = (mc_i32)fd;
			pfd.events = MC_POLLIN;
			pfd.revents = 0;
			mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
			if (pr <= 0 || (pfd.revents & MC_POLLIN) == 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}

			mc_u8 len2[2];
			mc_i64 rr = mc_sys_read((mc_i32)fd, len2, 2);
			if (rr != 2) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}
			mc_u16 mlen = (mc_u16)(((mc_u16)len2[0] << 8) | (mc_u16)len2[1]);
			if (mlen > sizeof(resp)) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}
			rr = mc_sys_read((mc_i32)fd, resp, mlen);
			(void)mc_sys_close((mc_i32)fd);
			if (rr != (mc_i64)mlen) return 0;
			rn = (mc_usize)rr;
		} else {
			struct mc_pollfd pfd;
			pfd.fd = (mc_i32)fd;
			pfd.events = MC_POLLIN;
			pfd.revents = 0;
			mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
			if (pr <= 0 || (pfd.revents & MC_POLLIN) == 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}

			mc_i64 rr = mc_sys_read((mc_i32)fd, resp, sizeof(resp));
			(void)mc_sys_close((mc_i32)fd);
			if (rr <= 0) return 0;
			rn = (mc_usize)rr;
		}

		if (rn < 12) return 0;
		if (resp[0] != (mc_u8)(id >> 8) || resp[1] != (mc_u8)(id & 0xFFu)) return 0;
		mc_u16 flags = (mc_u16)(((mc_u16)resp[2] << 8) | (mc_u16)resp[3]);
		if ((flags & 0x8000u) == 0) return 0;
		mc_u16 qd = (mc_u16)(((mc_u16)resp[4] << 8) | (mc_u16)resp[5]);
		mc_u16 an = (mc_u16)(((mc_u16)resp[6] << 8) | (mc_u16)resp[7]);
		if (qd != 1 || an == 0) return 0;

		mc_usize off = 12;
		mc_usize noff = 0;
		if (!dns_name_skip(resp, rn, off, &noff)) return 0;
		off = noff;
		if (off + 4 > rn) return 0;
		off += 4; // qtype+qclass

		for (mc_u16 i = 0; i < an; i++) {
			if (!dns_name_skip(resp, rn, off, &noff)) return 0;
			off = noff;
			if (off + 10 > rn) return 0;
			mc_u16 atype = (mc_u16)(((mc_u16)resp[off] << 8) | (mc_u16)resp[off + 1]);
			mc_u16 aclass = (mc_u16)(((mc_u16)resp[off + 2] << 8) | (mc_u16)resp[off + 3]);
			mc_u16 rdlen = (mc_u16)(((mc_u16)resp[off + 8] << 8) | (mc_u16)resp[off + 9]);
			off += 10;
			if (off + rdlen > rn) return 0;
			if (atype == 0x001cu && aclass == 0x0001u && rdlen == 16) {
				mc_memcpy(out_ip, resp + off, 16);
				return 1;
			}
			off += rdlen;
		}

		return 0;
	}

	return 0;
}

static int set_nonblock(mc_i32 fd, int enabled) {
	mc_i64 fl = mc_sys_fcntl(fd, MC_F_GETFL, 0);
	if (fl < 0) return 0;
	if (enabled) fl |= MC_O_NONBLOCK;
	else fl &= ~((mc_i64)MC_O_NONBLOCK);
	mc_i64 r = mc_sys_fcntl(fd, MC_F_SETFL, fl);
	return r >= 0;
}

static int connect_with_timeout(mc_i32 fd, const void *sa, mc_u32 salen, mc_u32 timeout_ms) {
	if (timeout_ms == 0) {
		mc_i64 r = mc_sys_connect(fd, sa, salen);
		return r >= 0;
	}

	if (!set_nonblock(fd, 1)) return 0;
	mc_i64 r = mc_sys_connect(fd, sa, salen);
	if (r >= 0) {
		(void)set_nonblock(fd, 0);
		return 1;
	}
	if (r != (mc_i64)-MC_EINPROGRESS) {
		(void)set_nonblock(fd, 0);
		return 0;
	}

	struct mc_pollfd pfd;
	pfd.fd = fd;
	pfd.events = MC_POLLOUT;
	pfd.revents = 0;
	mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
	if (pr <= 0 || (pfd.revents & MC_POLLOUT) == 0) {
		(void)set_nonblock(fd, 0);
		return 0;
	}

	mc_i32 err = 0;
	mc_u32 errlen = (mc_u32)sizeof(err);
	r = mc_sys_getsockopt(fd, MC_SOL_SOCKET, MC_SO_ERROR, &err, &errlen);
	(void)set_nonblock(fd, 0);
	if (r < 0) return 0;
	if (err != 0) return 0;
	return 1;
}



static int url_encode(const char *in, char *out, mc_usize cap) {
	static const char hex[] = "0123456789ABCDEF";
	mc_usize j = 0;
	for (mc_usize i = 0; in && in[i]; i++) {
		mc_u8 c = (mc_u8)in[i];
		int safe = 0;
		if ((c >= (mc_u8)'A' && c <= (mc_u8)'Z') || (c >= (mc_u8)'a' && c <= (mc_u8)'z') || (c >= (mc_u8)'0' && c <= (mc_u8)'9')) safe = 1;
		if (c == (mc_u8)'-' || c == (mc_u8)'_' || c == (mc_u8)'.' || c == (mc_u8)'~') safe = 1;
		if (safe) {
			if (j + 1 >= cap) return 0;
			out[j++] = (char)c;
		} else {
			if (j + 3 >= cap) return 0;
			out[j++] = '%';
			out[j++] = hex[(c >> 4) & 0xFu];
			out[j++] = hex[c & 0xFu];
		}
	}
	if (cap == 0) return 0;
	out[j] = 0;
	return 1;
}

static const char *json_skip_ws(const char *p) {
	while (p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
	return p;
}

static int json_parse_string(const char *p, char *out, mc_usize cap, const char **out_next) {
	if (!p || *p != '"') return 0;
	p++;
	mc_usize j = 0;
	while (*p) {
		char c = *p++;
		if (c == '"') {
			if (cap) out[j < cap ? j : (cap - 1)] = 0;
			if (out_next) *out_next = p;
			return (j < cap);
		}
		if (c == '\\') {
			char e = *p;
			if (e == 0) return 0;
			p++;
			if (e == 'n') c = '\n';
			else if (e == 't') c = '\t';
			else if (e == 'r') c = '\r';
			else if (e == 'b') c = '\b';
			else if (e == 'f') c = '\f';
			else if (e == '"') c = '"';
			else if (e == '\\') c = '\\';
			else if (e == '/') c = '/';
			else if (e == 'u') {
				// Skip 4 hex digits (very minimal; emit '?')
				for (int k = 0; k < 4; k++) {
					char h = *p;
					if (h == 0) return 0;
					p++;
				}
				c = '?';
			} else {
				c = e;
			}
		}
		if (j + 1 >= cap) return 0;
		out[j++] = c;
	}
	return 0;
}

static int json_extract_string_value(const char *json, const char *key, char *out, mc_usize cap) {
	if (!json || !key || !out || cap == 0) return 0;
	const char *p = json;
	while (*p) {
		// find opening quote
		if (*p != '"') {
			p++;
			continue;
		}
		p++;
		// match key (pointer-walk; avoids p[i] indexing)
		const char *q = p;
		const char *k = key;
		while (*k && *q && *q == *k) {
			q++;
			k++;
		}
		if (*k == 0 && *q == '"') {
			p = q + 1;
			p = json_skip_ws(p);
			if (*p != ':') continue;
			p++;
			p = json_skip_ws(p);
			if (*p != '"') return 0;
			return json_parse_string(p, out, cap, MC_NULL);
		}
		// skip to end of this string
		while (*p && *p != '"') {
			if (*p == '\\' && p[1]) p += 2;
			else p++;
		}
		if (*p == '"') p++;
	}
	return 0;
}

static int json_opensearch_first_title(const char *json, char *out, mc_usize cap) {
	// Expect: [ "query", ["Title"], ... ]
	const char *p = json_skip_ws(json);
	if (!p || *p != '[') return 0;
	p++;
	p = json_skip_ws(p);
	if (*p != '"') return 0;
	char tmp[256];
	if (!json_parse_string(p, tmp, sizeof(tmp), &p)) return 0;
	p = json_skip_ws(p);
	if (*p != ',') return 0;
	p++;
	p = json_skip_ws(p);
	if (*p != '[') return 0;
	p++;
	p = json_skip_ws(p);
	if (*p == ']') return 0;
	if (*p != '"') return 0;
	return json_parse_string(p, out, cap, MC_NULL);
}

static int http_parse_status(const char *hdr, mc_usize hdr_len, int *out_status) {
	if (!hdr || hdr_len < 12 || !out_status) return 0;
	// "HTTP/1.1 200"
	int s = 0;
	mc_usize i = 0;
	while (i < hdr_len && hdr[i] != ' ') i++;
	while (i < hdr_len && hdr[i] == ' ') i++;
	for (int k = 0; k < 3; k++) {
		if (i >= hdr_len) return 0;
		char c = hdr[i++];
		if (c < '0' || c > '9') return 0;
		s = s * 10 + (c - '0');
	}
	*out_status = s;
	return 1;
}

static int header_has_token_ci(const char *hdr, mc_usize hdr_len, const char *needle) {
	// naive case-insensitive substring search
	mc_usize nlen = mc_strlen(needle);
	if (nlen == 0 || hdr_len < nlen) return 0;
	for (mc_usize i = 0; i + nlen <= hdr_len; i++) {
		int ok = 1;
		for (mc_usize j = 0; j < nlen; j++) {
			char a = hdr[i + j];
			char b = needle[j];
			if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
			if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
			if (a != b) {
				ok = 0;
				break;
			}
		}
		if (ok) return 1;
	}
	return 0;
}

static int http_chunked_decode(const char *in, mc_usize in_len, char *out, mc_usize out_cap, mc_usize *out_len) {
	mc_usize o = 0;
	mc_usize i = 0;
	while (i < in_len) {
		// read hex size
		mc_u64 sz = 0;
		int any = 0;
		while (i < in_len) {
			char c = in[i];
			if (c == '\r' || c == '\n' || c == ';') break;
			int hv = mc_hexval((mc_u8)c);
			if (hv < 0) return 0;
			sz = (sz << 4) | (mc_u64)hv;
			any = 1;
			i++;
		}
		if (!any) return 0;
		// skip to end of line
		while (i < in_len && in[i] != '\n') i++;
		if (i >= in_len) return 0;
		i++; // skip \n
		if (sz == 0) {
			// done; ignore trailers
			if (out_len) *out_len = o;
			if (o < out_cap) out[o] = 0;
			return 1;
		}
		if (sz > (mc_u64)(in_len - i)) return 0;
		if (o + (mc_usize)sz + 1 > out_cap) return 0;
		mc_memcpy(out + o, in + i, (mc_usize)sz);
		o += (mc_usize)sz;
		i += (mc_usize)sz;
		// expect CRLF after chunk
		if (i + 1 >= in_len) return 0;
		if (in[i] == '\r') i++;
		if (i >= in_len || in[i] != '\n') return 0;
		i++;
	}
	return 0;
}


static int cstr_cat2(char *dst, mc_usize cap, const char *a, const char *b) {
	if (!dst || cap == 0) return 0;
	if (!a) a = "";
	if (!b) b = "";
	mc_usize al = mc_strlen(a);
	mc_usize bl = mc_strlen(b);
	if (al + bl + 1 > cap) return 0;
	mc_memcpy(dst, a, al);
	mc_memcpy(dst + al, b, bl);
	dst[al + bl] = 0;
	return 1;
}

static int cstr_cat3(char *dst, mc_usize cap, const char *a, const char *b, const char *c) {
	if (!dst || cap == 0) return 0;
	if (!a) a = "";
	if (!b) b = "";
	if (!c) c = "";
	mc_usize al = mc_strlen(a);
	mc_usize bl = mc_strlen(b);
	mc_usize cl = mc_strlen(c);
	if (al + bl + cl + 1 > cap) return 0;
	mc_memcpy(dst, a, al);
	mc_memcpy(dst + al, b, bl);
	mc_memcpy(dst + al + bl, c, cl);
	dst[al + bl + cl] = 0;
	return 1;
}



static void join_query(int argc, char **argv, int start, char *out, mc_usize cap) {
	mc_usize n = 0;
	for (int i = start; i < argc && argv[i]; i++) {
		if (i > start && n + 1 < cap) out[n++] = '_';
		for (const char *p = argv[i]; *p && n + 1 < cap; p++) {
			out[n++] = (*p == ' ') ? '_' : *p;
		}
	}
	if (cap) out[n < cap ? n : (cap - 1)] = 0;
}

// Performs a TLS 1.3 handshake and returns the decrypted HTTP response bytes.
// Performs a TLS 1.3 handshake and returns the decrypted HTTP response bytes.
static int https_get_raw(const char *argv0, const char *host, const char *path,
	char *out, mc_usize out_cap, mc_usize *out_len) {
	if (!argv0 || !host || !path || !out || !out_len) return 0;
	*out_len = 0;
	mc_usize host_len = mc_strlen(host);
	if (host_len == 0 || host_len > 255u) return 0;
	mc_usize path_len = mc_strlen(path);
	if (path_len == 0 || path[0] != '/' || path_len > 2048u) return 0;

	mc_u8 dns_server[16];
	if (!resolv_conf_pick_v6(dns_server)) {
		(void)parse_ipv6_literal("2001:4860:4860::8888", dns_server);
	}

	mc_u8 dst_ip[16];
	if (!parse_ipv6_literal(host, dst_ip)) {
		if (!dns6_resolve_first_aaaa(argv0, dns_server, 53, host, 5000, dst_ip)) {
			mc_u8 dns2[16];
			(void)parse_ipv6_literal("2001:4860:4860::8844", dns2);
			if (!dns6_resolve_first_aaaa(argv0, dns2, 53, host, 5000, dst_ip)) {
				return 0;
			}
		}
	}

	struct mc_sockaddr_in6 dst;
	mc_memset(&dst, 0, sizeof(dst));
	dst.sin6_family = (mc_u16)MC_AF_INET6;
	dst.sin6_port = mc_htons(443);
	for (int k = 0; k < 16; k++) dst.sin6_addr.s6_addr[k] = dst_ip[k];

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_STREAM | MC_SOCK_CLOEXEC, MC_IPPROTO_TCP);
	if (fd < 0) return 0;
	if (!connect_with_timeout((mc_i32)fd, &dst, (mc_u32)sizeof(dst), 5000)) {
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	struct mc_tls13_client c;
	mc_tls13_client_init(&c, (mc_i32)fd, 5000);
	if (mc_tls13_client_handshake(&c, host, host_len) != 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	// Send HTTP/1.1 request.
	char req[4096];
	mc_usize req_len = 0;
	{
		static const char p0[] = "GET ";
		static const char p1[] = " HTTP/1.1\r\nHost: ";
		static const char p2[] = "\r\nUser-Agent: monacc-wtf\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
		mc_usize l0 = sizeof(p0) - 1u;
		mc_usize l1 = sizeof(p1) - 1u;
		mc_usize l2 = sizeof(p2) - 1u;
		mc_usize need = l0 + path_len + l1 + host_len + l2;
		if (need > sizeof(req)) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		mc_memcpy(req + req_len, p0, l0);
		req_len += l0;
		mc_memcpy(req + req_len, path, path_len);
		req_len += path_len;
		mc_memcpy(req + req_len, p1, l1);
		req_len += l1;
		mc_memcpy(req + req_len, host, host_len);
		req_len += host_len;
		mc_memcpy(req + req_len, p2, l2);
		req_len += l2;
	}

	if (mc_tls13_client_write_app(&c, (const mc_u8 *)req, req_len) < 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	for (;;) {
		mc_u8 buf[8192];
		mc_i64 rn = mc_tls13_client_read_app(&c, buf, sizeof(buf));
		if (rn > 0) {
			mc_usize n = (mc_usize)rn;
			if (*out_len + n > out_cap) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}
			mc_memcpy(out + *out_len, buf, n);
			*out_len += n;
			continue;
		}
		if (rn == 0) break;
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	(void)mc_sys_close((mc_i32)fd);
	if (*out_len < out_cap) out[*out_len] = 0;
	return 1;
}

static int wiki_get_summary(const char *argv0, const char *lang, const char *title, char *out, mc_usize cap) {
	char host[64];
	if (!cstr_cat2(host, sizeof(host), lang, ".wikipedia.org")) return -1;
	char enc_title[256];
	if (!url_encode(title, enc_title, sizeof(enc_title))) return -1;
	char path[512];
	if (!cstr_cat2(path, sizeof(path), "/api/rest_v1/page/summary/", enc_title)) return -1;

	static char resp[262144];
	mc_usize rn = 0;
	if (!https_get_raw(argv0, host, path, resp, sizeof(resp) - 1u, &rn)) return -1;

	// Split headers/body
	mc_usize hdr_end = 0;
	for (mc_usize i = 0; i + 3 < rn; i++) {
		if (resp[i] == '\r' && resp[i + 1] == '\n' && resp[i + 2] == '\r' && resp[i + 3] == '\n') {
			hdr_end = i + 4;
			break;
		}
	}
	if (hdr_end == 0) return -1;
	int status = 0;
	if (!http_parse_status(resp, hdr_end, &status)) return -1;

	const char *body = resp + hdr_end;
	mc_usize body_len = rn - hdr_end;

	char body2[262144];
	mc_usize body2_len = 0;
	const char *use_body = body;
	mc_usize use_len = body_len;
	if (header_has_token_ci(resp, hdr_end, "transfer-encoding: chunked")) {
		if (!http_chunked_decode(body, body_len, body2, sizeof(body2), &body2_len)) return -1;
		use_body = body2;
		use_len = body2_len;
	} else {
		// ensure NUL termination for string search
		if (body_len + 1 > sizeof(body2)) return -1;
		mc_memcpy(body2, body, body_len);
		body2[body_len] = 0;
		use_body = body2;
		use_len = body_len;
	}
	(void)use_len;

	if (status == 404) return 0;
	if (status != 200) return -1;

	if (!json_extract_string_value(use_body, "extract", out, cap)) return -1;
	return 1;
}

static int wiki_search(const char *argv0, const char *lang, const char *query, char *out_title, mc_usize cap) {
	char host[64];
	if (!cstr_cat2(host, sizeof(host), lang, ".wikipedia.org")) return 0;
	char enc_q[256];
	if (!url_encode(query, enc_q, sizeof(enc_q))) return 0;
	char path[768];
	if (!cstr_cat3(path, sizeof(path), "/w/api.php?action=opensearch&search=", enc_q, "&limit=1&format=json")) return 0;

	static char resp[262144];
	mc_usize rn = 0;
	if (!https_get_raw(argv0, host, path, resp, sizeof(resp) - 1u, &rn)) return 0;

	mc_usize hdr_end = 0;
	for (mc_usize i = 0; i + 3 < rn; i++) {
		if (resp[i] == '\r' && resp[i + 1] == '\n' && resp[i + 2] == '\r' && resp[i + 3] == '\n') {
			hdr_end = i + 4;
			break;
		}
	}
	if (hdr_end == 0) return 0;
	int status = 0;
	if (!http_parse_status(resp, hdr_end, &status)) return 0;
	if (status != 200) return 0;

	const char *body = resp + hdr_end;
	mc_usize body_len = rn - hdr_end;

	char body2[262144];
	mc_usize body2_len = 0;
	const char *use_body = body;
	if (header_has_token_ci(resp, hdr_end, "transfer-encoding: chunked")) {
		if (!http_chunked_decode(body, body_len, body2, sizeof(body2), &body2_len)) return 0;
		use_body = body2;
	} else {
		if (body_len + 1 > sizeof(body2)) return 0;
		mc_memcpy(body2, body, body_len);
		body2[body_len] = 0;
		use_body = body2;
	}

	return json_opensearch_first_title(use_body, out_title, cap);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "wtf";
	const char *lang = "en";
	int i = 1;
	if (i < argc && mc_streq(argv[i], "-l")) {
		if (i + 1 < argc) {
			lang = argv[i + 1];
			i += 2;
		} else {
			return 1;
		}
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
