#include "mc_min.h"

// Implement missing syscalls and functions
#define MC_SYS_pipe 22
#define MC_SYS_dup2 33
#define MC_SYS_fork 57
#define MC_SYS_execve 59
#define MC_SYS_wait4 61

static inline mc_i64 sys_pipe(int *fd) {
    return mc_syscall1(MC_SYS_pipe, (mc_i64)fd);
}
static inline mc_i64 sys_dup2(int oldfd, int newfd) {
    return mc_syscall2(MC_SYS_dup2, oldfd, newfd);
}
static inline mc_i64 sys_fork(void) {
    return mc_syscall1(MC_SYS_fork, 0);
}
static inline mc_i64 sys_execve(const char *filename, char *const argv[], char *const envp[]) {
    return mc_syscall3(MC_SYS_execve, (mc_i64)filename, (mc_i64)argv, (mc_i64)envp);
}
static inline mc_i64 sys_wait4(mc_i32 pid, int *status, int options, void *rusage) {
    return mc_syscall4(MC_SYS_wait4, pid, (mc_i64)status, options, (mc_i64)rusage);
}

mc_usize mc_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (mc_usize)(p - s);
}

int mc_streq(const char *a, const char *b) {
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

void *mc_memcpy(void *dst, const void *src, mc_usize n) {
    char *d = (char *)dst;
    const char *s = (const char *)src;
    for (mc_usize i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

mc_i64 mc_write_str(mc_i32 fd, const char *s) {
    return mc_sys_write(fd, s, mc_strlen(s));
}

void mc_exit(mc_i32 code) {
    mc_syscall1(MC_SYS_exit, code);
    __builtin_unreachable();
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
		if (*p != '"') {
			p++;
			continue;
		}
		p++;
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
		while (*p && *p != '"') {
			if (*p == '\\' && p[1]) p += 2;
			else p++;
		}
		if (*p == '"') p++;
	}
	return 0;
}

static int json_opensearch_first_title(const char *json, char *out, mc_usize cap) {
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

static int run_curl(const char *url, char *out, mc_usize cap) {
    int pipefd[2];
    if (sys_pipe(pipefd) < 0) return 0;

    mc_i64 pid = sys_fork();
    if (pid < 0) {
        mc_sys_close(pipefd[0]);
        mc_sys_close(pipefd[1]);
        return 0;
    }

    if (pid == 0) {
        // Child
        mc_sys_close(pipefd[0]);
        sys_dup2(pipefd[1], 1); // stdout -> pipe
        mc_sys_close(pipefd[1]);

        char *const args[] = { "/usr/bin/curl", "-s", "-f", (char*)url, MC_NULL };
        char *const env[] = { MC_NULL };
        sys_execve(args[0], args, env);
        mc_exit(127);
    }

    // Parent
    mc_sys_close(pipefd[1]);

    mc_usize total = 0;
    for (;;) {
        if (total >= cap - 1) break;
        mc_i64 r = mc_sys_read(pipefd[0], out + total, cap - 1 - total);
        if (r <= 0) break;
        total += r;
    }
    out[total] = 0;
    mc_sys_close(pipefd[0]);

    int status = 0;
    sys_wait4((mc_i32)pid, &status, 0, MC_NULL);

    // check status
    if ((status & 0x7f) == 0 && ((status & 0xff00) >> 8) == 0) {
        return 1;
    }
    return 0;
}

static int wiki_get_summary(const char *lang, const char *title, char *out, mc_usize cap) {
	char host[64];
	if (!cstr_cat2(host, sizeof(host), lang, ".wikipedia.org")) return -1;
	char enc_title[256];
	if (!url_encode(title, enc_title, sizeof(enc_title))) return -1;
	char url[1024];
	if (!cstr_cat3(url, sizeof(url), "https://", host, "/api/rest_v1/page/summary/")) return -1;

    mc_usize ul = mc_strlen(url);
    mc_usize el = mc_strlen(enc_title);
    if (ul + el + 1 > sizeof(url)) return -1;
    mc_memcpy(url + ul, enc_title, el);
    url[ul + el] = 0;

    static char resp[262144];
    if (!run_curl(url, resp, sizeof(resp))) return 0;

    if (!json_extract_string_value(resp, "extract", out, cap)) return -1;
    return 1;
}

static int wiki_search(const char *lang, const char *query, char *out_title, mc_usize cap) {
	char host[64];
	if (!cstr_cat2(host, sizeof(host), lang, ".wikipedia.org")) return 0;
	char enc_q[256];
	if (!url_encode(query, enc_q, sizeof(enc_q))) return 0;

    char url[1024];
    if (!cstr_cat3(url, sizeof(url), "https://", host, "/w/api.php?action=opensearch&search=")) return 0;

    mc_usize ul = mc_strlen(url);
    mc_usize el = mc_strlen(enc_q);
    if (ul + el + 1 > sizeof(url)) return 0;
    mc_memcpy(url + ul, enc_q, el);
    ul += el;

    const char *suffix = "&limit=1&format=json";
    mc_usize sl = mc_strlen(suffix);
    if (ul + sl + 1 > sizeof(url)) return 0;
    mc_memcpy(url + ul, suffix, sl);
    url[ul + sl] = 0;

	static char resp[262144];
	if (!run_curl(url, resp, sizeof(resp))) return 0;

	return json_opensearch_first_title(resp, out_title, cap);
}

int main(int argc, char **argv, char **envp) {
	(void)envp;
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
	int rc = wiki_get_summary(lang, query, extract, sizeof(extract));
	if (rc == 0) {
		char found[256];
		if (wiki_search(lang, query, found, sizeof(found))) {
			rc = wiki_get_summary(lang, found, extract, sizeof(extract));
		}
	}

	if (rc <= 0) return 1;

	(void)mc_write_str(1, extract);
	if (extract[0] && extract[mc_strlen(extract) - 1] != '\n') (void)mc_write_str(1, "\n");
	return 0;
}

void _start(void) {
    mc_i64 *sp;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(sp));
    long argc = *sp;
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    int ret = main((int)argc, argv, envp);
    mc_exit(ret);
}
