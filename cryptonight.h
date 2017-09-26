#ifndef __CRYPTONIGHT_H
#define __CRYPTONIGHT_H


typedef struct _AlgoConfig
{	
	uint32_t scratchpadSize;
	uint32_t iterations;
	uint32_t algoMask;
} AlgoConfig;

struct cryptonight_ctx;

typedef void (cryptonight_func)(void *output, const void *input, struct cryptonight_ctx *ctx, uint8_t *scratchpad);
cryptonight_func cryptonight_hash_dumb;
cryptonight_func cryptonight_hash_aesni;

struct cryptonight_ctx *cryptonight_ctx(AlgoConfig AlgoConfig);


#endif
