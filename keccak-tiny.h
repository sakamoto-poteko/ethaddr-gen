#ifndef KECCAK_FIPS202_H
#define KECCAK_FIPS202_H
#define __STDC_WANT_LIB_EXT1__ 1
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif 

int keccak3_256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

#ifdef __cplusplus
}
#endif 

#endif
