#include <cstdio>
#include <climits>
#include <cmath>

#include <iostream>
#include <iomanip>
#include <chrono>

#include <omp.h>

#include <mbedtls/ecdsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <immintrin.h>

#include "keccak-tiny.h"

static void print_hex(unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%c%c", "0123456789ABCDEF"[buf[i] / 16], "0123456789ABCDEF"[buf[i] % 16]);
    }
}

int generate_key(const int thread_id, const std::uint64_t max_iteration, bool *terminate)
{
    int rc;

    mbedtls_ecdsa_context ecctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecdsa_init(&ecctx);
    mbedtls_entropy_init(&entropy);

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

    std::uint64_t counter = 0;
    bool satisfied = false;

    __attribute__((aligned(64))) std::uint8_t hash[32];
    __attribute__((aligned(64))) std::uint8_t public_key_binary[384];
    size_t public_key_binary_len;

    while (!satisfied && counter++ < max_iteration && !*terminate)
    {
        rc = mbedtls_ecdsa_genkey(&ecctx, MBEDTLS_ECP_DP_SECP256K1, mbedtls_ctr_drbg_random, &ctr_drbg);

        mbedtls_ecp_point_write_binary(&(ecctx.grp), &(ecctx.Q), MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &public_key_binary_len, public_key_binary, sizeof(public_key_binary));

        keccak3_256(hash, 32, public_key_binary + 1, public_key_binary_len - 1);

        // satisfied = true;

        const std::uint8_t *address = hash + 12;

        // if (*(std::uint32_t *)(address + 16) == 0x88888888 /* && *(std::uint32_t *)(hash + 28) == 0x36363636*/)
        if (*(std::uint16_t *)(address + 18) == 0x8888  && *(std::uint16_t *)(hash + 0) == 0x6666)
        {
            satisfied = true;
        }
    }

    if (satisfied)
    {
#pragma omp critical
        {
            char priv[256] = {0};
            size_t len;
            mbedtls_mpi_write_string(&(ecctx.d), 16, priv, 256, &len) != 0;
            printf("[thread %d]:\nPrivate key: %s\nAddress: ", thread_id, priv);
            print_hex(hash + 12, 20);
            printf("\n");
        }
        return 0;
    }

    return 1;
}

int main()
{
    int nthreads = 0;
    int tid = 0;
    bool terminate = false;

    std::uint64_t max = 1'000'000'000;
    nthreads = ::omp_get_num_threads();

    std::uint64_t batchsize = 200'000;
    std::uint64_t batchcount = max / batchsize;

#pragma omp parallel for schedule(static) shared(terminate)
    for (int i = 0; i < batchcount; ++i)
    {
        if (terminate)
        {
            continue;
        }

        auto start = std::chrono::high_resolution_clock::now();

        tid = ::omp_get_thread_num();
        int result = generate_key(tid, batchsize, &terminate);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = end - start;
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        double key_per_second = batchsize / (duration_ms / 1000.);

        if (result == 0)
        {
            terminate = true;
        }


#pragma omp critical
        printf("Batch %d finished. Avg %f keys per second\n", i, key_per_second);
    }

    return 0;
}
