// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include <stdlib.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/mman.h>
#endif
#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"
#include "cryptonight.h"

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#if USE_INT128

#if __GNUC__ == 4 && __GNUC_MINOR__ >= 4 && __GNUC_MINOR__ < 6
typedef unsigned int uint128_t __attribute__ ((__mode__ (TI)));
#else
typedef __uint128_t uint128_t;
#endif

#endif

#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

#pragma pack(push, 1)
union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint8_t k[64];
		uint8_t init[INIT_SIZE_BYTE];
	};
};
#pragma pack(pop)

static void do_blake_hash(const void* input, size_t len, char* output) {
	blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
	groestl(input, len * 8, (uint8_t*)output);
}

static void do_jh_hash(const void* input, size_t len, char* output) {
	int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
	assert((SUCCESS == r));
}

static void do_skein_hash(const void* input, size_t len, char* output) {
	int r = skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
	assert((SKEIN_SUCCESS == r));
}

extern int fast_aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern int aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern int aesb_pseudo_round_mut(uint8_t *val, uint8_t *expandedKey);
extern int fast_aesb_pseudo_round_mut(uint8_t *val, uint8_t *expandedKey);

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
		do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash
};

static inline void mul_sum_xor_dst(const uint8_t* a, uint8_t* c, uint8_t* dst) {
	uint64_t hi, lo;
#ifdef __amd64
	__asm__("mul %%rdx":
	"=a" (lo), "=d" (hi):
	"a" (*(uint64_t *)a), "d" (*(uint64_t *)dst));
#else
	lo = mul128(((uint64_t*) a)[0], ((uint64_t*) dst)[0], &hi);
#endif
	lo += ((uint64_t*) c)[1];
	hi += ((uint64_t*) c)[0];

	((uint64_t*) c)[0] = ((uint64_t*) dst)[0] ^ hi;
	((uint64_t*) c)[1] = ((uint64_t*) dst)[1] ^ lo;
	((uint64_t*) dst)[0] = hi;
	((uint64_t*) dst)[1] = lo;
}

static inline void xor_blocks(uint8_t* a, const uint8_t* b) {
#if USE_INT128
	*((uint128_t*) a) ^= *((uint128_t*) b);
#else
	((uint64_t*) a)[0] ^= ((uint64_t*) b)[0];
	((uint64_t*) a)[1] ^= ((uint64_t*) b)[1];
#endif
}

static inline void xor_blocks_dst(const uint8_t* a, const uint8_t* b, uint8_t* dst) {
#if USE_INT128
	*((uint128_t*) dst) = *((uint128_t*) a) ^ *((uint128_t*) b);
#else
	((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
	((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
#endif
}

struct cryptonight_ctx {
	union cn_slow_hash_state state;
	uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(16)));
	uint8_t a[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t b[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	oaes_ctx* aes_ctx;
	uint32_t iterations;
	uint32_t algoMask;
	uint32_t scratchpadSize;
};

struct cryptonight_aesni_ctx {
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(16)));
    uint64_t a[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint64_t b[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(16)));
    oaes_ctx* aes_ctx;
    uint32_t iterations;
    uint32_t algoMask;
    uint32_t scratchpadSize;
};

void cryptonight_hash_dumb(void* output, const void* input, struct cryptonight_ctx* ctx, uint8_t* scratchpad) {
	size_t i, j;
	keccak1600(input, 76, (uint8_t *)&ctx->state.hs);
	if (!ctx->aes_ctx)
		ctx->aes_ctx = (oaes_ctx*) oaes_alloc();
	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
	
	oaes_key_import_data(ctx->aes_ctx, ctx->state.hs.b, AES_KEY_SIZE);
	for (i = 0; (i < ctx->scratchpadSize); i += INIT_SIZE_BYTE) {
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 0], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 1], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 2], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 3], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 4], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 5], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 6], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 7], ctx->aes_ctx->key->exp_data);
		memcpy(&scratchpad[i], ctx->text, INIT_SIZE_BYTE);
	}
	
	xor_blocks_dst(&ctx->state.k[0], &ctx->state.k[32], ctx->a);
	xor_blocks_dst(&ctx->state.k[16], &ctx->state.k[48], ctx->b);

	for (i = 0; (i < ctx->iterations / 2); ++i) {
		/* Dependency chain: address -> read value ------+
		 * written value <-+ hard function (AES or MUL) <+
		 * next address  <-+
		/* Iteration 1 */
		j = ((uint32_t *)ctx->a)[0] & ctx->algoMask;
		aesb_single_round(&scratchpad[j], ctx->c, ctx->a);
		xor_blocks_dst(ctx->c, ctx->b, &scratchpad[j]);
		/* Iteration 2 */
		mul_sum_xor_dst(ctx->c, ctx->a, &scratchpad[((uint32_t *)ctx->c)[0] & ctx->algoMask]); 
		/* Iteration 3 */
		j = ((uint32_t *)ctx->a)[0] & ctx->algoMask;
		aesb_single_round(&scratchpad[j], ctx->b, ctx->a);
		xor_blocks_dst(ctx->b, ctx->c, &scratchpad[j]);
		/* Iteration 4 */
		mul_sum_xor_dst(ctx->b, ctx->a, &scratchpad[((uint32_t *)ctx->b)[0] & ctx->algoMask]);
	}

	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
	oaes_key_import_data(ctx->aes_ctx, &ctx->state.hs.b[32], AES_KEY_SIZE);
	for (i = 0; (i < ctx->scratchpadSize); i += INIT_SIZE_BYTE) {
		xor_blocks(&ctx->text[0 * AES_BLOCK_SIZE], &scratchpad[i + 0 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[0 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[1 * AES_BLOCK_SIZE], &scratchpad[i + 1 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[1 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[2 * AES_BLOCK_SIZE], &scratchpad[i + 2 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[2 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[3 * AES_BLOCK_SIZE], &scratchpad[i + 3 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[3 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[4 * AES_BLOCK_SIZE], &scratchpad[i + 4 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[4 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[5 * AES_BLOCK_SIZE], &scratchpad[i + 5 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[5 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[6 * AES_BLOCK_SIZE], &scratchpad[i + 6 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[6 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[7 * AES_BLOCK_SIZE], &scratchpad[i + 7 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[7 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
	}
	memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
	keccakf((uint64_t*)(&ctx->state.hs), 24);
	/*memcpy(hash, &state, 32);*/	
	//if((ctx->state.hs.b[0] & 3) == 1) exit(0);
	extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
	//memcpy(output, ctx->state.hs.b, 32);
}

#include <x86intrin.h>

static inline void ExpandAESKey256_sub1(__m128i *tmp1, __m128i *tmp2)
{
	__m128i tmp4;
	*tmp2 = _mm_shuffle_epi32(*tmp2, 0xFF);
	tmp4 = _mm_slli_si128(*tmp1, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	*tmp1 = _mm_xor_si128(*tmp1, *tmp2);
}

static inline void ExpandAESKey256_sub2(__m128i *tmp1, __m128i *tmp3)
{
	__m128i tmp2, tmp4;

	tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x00);
	tmp2 = _mm_shuffle_epi32(tmp4, 0xAA);
	tmp4 = _mm_slli_si128(*tmp3, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	*tmp3 = _mm_xor_si128(*tmp3, tmp2);
}

// Special thanks to Intel for helping me
// with ExpandAESKey256() and its subroutines
static inline void ExpandAESKey256(char *keybuf)
{
	__m128i tmp1, tmp2, tmp3, *keys;

	keys = (__m128i *)keybuf;

	tmp1 = _mm_load_si128((__m128i *)keybuf);
	tmp3 = _mm_load_si128((__m128i *)(keybuf+0x10));

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[2] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[3] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[4] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[5] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[6] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[7] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[8] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[9] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[10] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[11] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[12] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[13] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[14] = tmp1;
}

void cryptonight_hash_aesni(void *restrict output, const void *restrict input, struct cryptonight_ctx *restrict ct0, uint8_t *restrict scratchpad)
{
    struct cryptonight_aesni_ctx *ctx = (struct cryptonight_aesni_ctx *)ct0;

    uint8_t ExpandedKey[256];
    size_t i, j;

    keccak1600(input, 76, (uint8_t *)&ctx->state.hs);
    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    memcpy(ExpandedKey, ctx->state.hs.b, AES_KEY_SIZE);
    ExpandAESKey256(ExpandedKey);

    __m128i *longoutput, *expkey, *xmminput;
	longoutput = (__m128i *)scratchpad;
	expkey = (__m128i *)ExpandedKey;
	xmminput = (__m128i *)ctx->text;

    //for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
    //    aesni_parallel_noxor(&scratchpad[i], ctx->text, ExpandedKey);

    for (i = 0; likely(i < ctx->scratchpadSize); i += INIT_SIZE_BYTE)
    {
		for(j = 0; j < 10; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}
		_mm_store_si128(&(longoutput[(i >> 4)]), xmminput[0]);
		_mm_store_si128(&(longoutput[(i >> 4) + 1]), xmminput[1]);
		_mm_store_si128(&(longoutput[(i >> 4) + 2]), xmminput[2]);
		_mm_store_si128(&(longoutput[(i >> 4) + 3]), xmminput[3]);
		_mm_store_si128(&(longoutput[(i >> 4) + 4]), xmminput[4]);
		_mm_store_si128(&(longoutput[(i >> 4) + 5]), xmminput[5]);
		_mm_store_si128(&(longoutput[(i >> 4) + 6]), xmminput[6]);
		_mm_store_si128(&(longoutput[(i >> 4) + 7]), xmminput[7]);
    }

	for (i = 0; i < 2; i++)
    {
	    ctx->a[i] = ((uint64_t *)ctx->state.k)[i] ^  ((uint64_t *)ctx->state.k)[i+4];
	    ctx->b[i] = ((uint64_t *)ctx->state.k)[i+2] ^  ((uint64_t *)ctx->state.k)[i+6];
    }

	__m128i b_x = _mm_load_si128((__m128i *)ctx->b);
    uint64_t a[2] __attribute((aligned(16))), b[2] __attribute((aligned(16)));
    a[0] = ctx->a[0];
    a[1] = ctx->a[1];

	for(i = 0; __builtin_expect(i < ctx->iterations, 1); i++)
	{
	__m128i c_x = _mm_load_si128((__m128i *)&scratchpad[a[0] & ctx->algoMask]);
	__m128i a_x = _mm_load_si128((__m128i *)a);
	uint64_t c[2];
	c_x = _mm_aesenc_si128(c_x, a_x);

	_mm_store_si128((__m128i *)c, c_x);
	__builtin_prefetch(&scratchpad[c[0] & ctx->algoMask], 0, 1);

	b_x = _mm_xor_si128(b_x, c_x);
	_mm_store_si128((__m128i *)&scratchpad[a[0] & ctx->algoMask], b_x);

	uint64_t *nextblock = (uint64_t *)&scratchpad[c[0] & ctx->algoMask];
	uint64_t b[2];
	b[0] = nextblock[0];
	b[1] = nextblock[1];

	{
	  uint64_t hi, lo;
	 // hi,lo = 64bit x 64bit multiply of c[0] and b[0]

	  __asm__("mulq %3\n\t"
		  : "=d" (hi),
		"=a" (lo)
		  : "%a" (c[0]),
		"rm" (b[0])
		  : "cc" );

	  a[0] += hi;
	  a[1] += lo;
	}
	uint64_t *dst = &scratchpad[c[0] & ctx->algoMask];
	dst[0] = a[0];
	dst[1] = a[1];

	a[0] ^= b[0];
	a[1] ^= b[1];
	b_x = c_x;
	__builtin_prefetch(&scratchpad[a[0] & ctx->algoMask], 0, 3);
	}

    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    memcpy(ExpandedKey, &ctx->state.hs.b[32], AES_KEY_SIZE);
    ExpandAESKey256(ExpandedKey);

    //for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
    //    aesni_parallel_xor(&ctx->text, ExpandedKey, &scratchpad[i]);

    for (i = 0; __builtin_expect(i < ctx->scratchpadSize, 1); i += INIT_SIZE_BYTE)
	{
		xmminput[0] = _mm_xor_si128(longoutput[(i >> 4)], xmminput[0]);
		xmminput[1] = _mm_xor_si128(longoutput[(i >> 4) + 1], xmminput[1]);
		xmminput[2] = _mm_xor_si128(longoutput[(i >> 4) + 2], xmminput[2]);
		xmminput[3] = _mm_xor_si128(longoutput[(i >> 4) + 3], xmminput[3]);
		xmminput[4] = _mm_xor_si128(longoutput[(i >> 4) + 4], xmminput[4]);
		xmminput[5] = _mm_xor_si128(longoutput[(i >> 4) + 5], xmminput[5]);
		xmminput[6] = _mm_xor_si128(longoutput[(i >> 4) + 6], xmminput[6]);
		xmminput[7] = _mm_xor_si128(longoutput[(i >> 4) + 7], xmminput[7]);

		for(j = 0; j < 10; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}

	}

    memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
	keccakf(&ctx->state.hs, 24);
    extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
}

struct cryptonight_ctx* cryptonight_ctx(AlgoConfig AlgoConfig){
	struct cryptonight_ctx *ret;

#ifdef _WIN32
	ret = calloc(1, sizeof(*ret));
#else
	ret = mmap(0, sizeof(*ret), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB|MAP_POPULATE, 0, 0);
	if (ret == MAP_FAILED)
		ret = calloc(1, sizeof(*ret));
	if (ret) {
		madvise(ret, sizeof(*ret), MADV_RANDOM|MADV_WILLNEED|MADV_HUGEPAGE);
		if (!geteuid())
			mlock(ret, sizeof(*ret));
	}
#endif

	ret->iterations = AlgoConfig.iterations;
	ret->algoMask = AlgoConfig.algoMask;
	ret->scratchpadSize = AlgoConfig.scratchpadSize;

	return ret;
}
