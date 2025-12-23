#include "mc_min.h"
#include "mc_min.h"
#include <wmmintrin.h>

// AES-NI Key Expansion Helper
static inline __m128i aes_128_key_exp(__m128i key, __m128i key_gen_res) {
	key_gen_res = _mm_shuffle_epi32(key_gen_res, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, key_gen_res);
}

void mc_aes128_init(mc_aes128_ctx *ctx, const mc_u8 key[MC_AES128_KEY_SIZE]) {
	__m128i k = _mm_loadu_si128((const __m128i*)key);
	_mm_storeu_si128((__m128i*)&ctx->rk[0], k);

	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x01));
	_mm_storeu_si128((__m128i*)&ctx->rk[4], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x02));
	_mm_storeu_si128((__m128i*)&ctx->rk[8], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x04));
	_mm_storeu_si128((__m128i*)&ctx->rk[12], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x08));
	_mm_storeu_si128((__m128i*)&ctx->rk[16], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x10));
	_mm_storeu_si128((__m128i*)&ctx->rk[20], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x20));
	_mm_storeu_si128((__m128i*)&ctx->rk[24], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x40));
	_mm_storeu_si128((__m128i*)&ctx->rk[28], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x80));
	_mm_storeu_si128((__m128i*)&ctx->rk[32], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x1B));
	_mm_storeu_si128((__m128i*)&ctx->rk[36], k);
	k = aes_128_key_exp(k, _mm_aeskeygenassist_si128(k, 0x36));
	_mm_storeu_si128((__m128i*)&ctx->rk[40], k);
}

void mc_aes128_encrypt_block(const mc_aes128_ctx *ctx, const mc_u8 in[MC_AES128_BLOCK_SIZE], mc_u8 out[MC_AES128_BLOCK_SIZE]) {
	__m128i m = _mm_loadu_si128((const __m128i*)in);
	
	m = _mm_xor_si128(m, _mm_loadu_si128((const __m128i*)&ctx->rk[0]));
	
	// We loops through 9 rounds
	for (int i = 1; i < 10; i++) {
		m = _mm_aesenc_si128(m, _mm_loadu_si128((const __m128i*)&ctx->rk[i*4]));
	}
	
	// Last round
	m = _mm_aesenclast_si128(m, _mm_loadu_si128((const __m128i*)&ctx->rk[40]));
	
	_mm_storeu_si128((__m128i*)out, m);
}

// mc_aes128_decrypt_block removed as it is unused.
