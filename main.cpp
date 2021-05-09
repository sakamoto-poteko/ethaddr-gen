#include <cstdio>
#include <climits>
#include <cmath>
#include <iostream>
#include <iomanip>

#include <mbedtls/ecdsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <immintrin.h>

#include "keccak-tiny.h"

static void dump_buf(const char *title, unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s", title);
    for (i = 0; i < len; i++)
        printf("%c%c", "0123456789ABCDEF"[buf[i] / 16],
               "0123456789ABCDEF"[buf[i] % 16]);
    printf("\n");
}

static void dump_pubkey(const char *title, mbedtls_ecdsa_context *key)
{
    unsigned char buf[300];
    size_t len;

    if (mbedtls_ecp_point_write_binary(&key->grp, &key->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf) != 0)
    {
        printf("internal error\n");
        return;
    }

    dump_buf(title, buf, len);

    char priv[256] = {0};
    if (mbedtls_mpi_write_string(&key->d, 16, priv, 256, &len) != 0)
    {
        printf("internal error\n");
        return;
    }
    printf("priv: %s\n", priv);

    char hash[32] = {0};
    keccak3_256((std::uint8_t *)hash, 32, buf + 1, len - 1);

    dump_buf("addr: ", (unsigned char *)hash, 32);
}

int main()
{
    int ret;

    mbedtls_ecdsa_context ecctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecdsa_init(&ecctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
    mbedtls_ecdsa_genkey(&ecctx, MBEDTLS_ECP_DP_SECP256K1, mbedtls_ctr_drbg_random, &ctr_drbg);

    dump_pubkey("  + Public key: ", &ecctx);

    return 0;
}
