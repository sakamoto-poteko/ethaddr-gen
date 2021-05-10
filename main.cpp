#include <cstdio>
#include <climits>
#include <cmath>

#include <iostream>
#include <iomanip>
#include <chrono>

#include <omp.h>

#include <ippcp.h>

#include "secp256k1.h"

#include <immintrin.h>

#include "keccak-tiny.h"

static const std::size_t IPP_PRNG_SIZE_MAX = 512;
static const int PRIVATE_KEY_SIZE = 32;
// static const std::uint64_t ONE = 0x01lu;

static void print_hex(const std::uint8_t *buf, const std::size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%c%c", "0123456789ABCDEF"[buf[i] / 16], "0123456789ABCDEF"[buf[i] % 16]);
    }
}

static void print_address(const std::uint8_t *private_key, const std::uint8_t *public_key_full_hash)
{
#pragma omp critical
    {
        printf("Private key:\t");
        print_hex(private_key, PRIVATE_KEY_SIZE);
        printf("\nAddress:\t");
        print_hex(public_key_full_hash + 12, 20);
        printf("\n");
    }
}

static int generate_key(const std::uint64_t max_iteration, bool *terminate)
{
    int rc;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey public_key;
    std::uint8_t private_key[PRIVATE_KEY_SIZE];

    IppStatus status;

    // generate random
    Ipp8u prng_data[IPP_PRNG_SIZE_MAX];
    IppsPRNGState *prng = reinterpret_cast<IppsPRNGState *>(prng_data);
    status = ippsPRNGInit(160, prng);
    status = ippsPRNGenRDRAND(reinterpret_cast<Ipp32u *>(private_key), PRIVATE_KEY_SIZE * 8, prng);

    std::uint64_t counter = 0;
    bool satisfied = false;

    std::uint8_t public_key_full_hash[32];
    std::uint8_t public_key_binary[384];

    while (!satisfied && counter++ < max_iteration && !*terminate)
    {
        // add one to last few bytes every time
        std::uint64_t *pk_end = reinterpret_cast<std::uint64_t *>(private_key + (PRIVATE_KEY_SIZE - sizeof(std::uint64_t)));
        *pk_end += 1;
        // +1 without carry. it's uint64 so you don't need carry anyway. wrap is fine.

        size_t public_key_binary_len = 384;

        rc = secp256k1_ec_pubkey_create(ctx, &public_key, private_key);
        secp256k1_ec_pubkey_serialize(ctx, public_key_binary, &public_key_binary_len, &public_key, SECP256K1_EC_UNCOMPRESSED);

        keccak3_256(public_key_full_hash, 32, public_key_binary + 1, public_key_binary_len - 1);

        const std::uint8_t *address = public_key_full_hash + 12;

        // if (*(std::uint32_t *)(address + 16) == 0x88888888 /* && *(std::uint32_t *)(hash + 28) == 0x36363636*/)
        if ((*(std::uint32_t *)(address + 16) & 0xFFFFFF00) == 0x88888800 && (*(std::uint32_t *)(address + 0) & 0x00FFFFFF) == 0x00666666)
        // if ((*(std::uint32_t *)(address + 16) & 0xFFFF0000) == 0x88880000)
        // if ((*(std::uint32_t *)(address + 0) & 0x000000FF) == 0x00000088)
        // if (*(std::uint8_t *)(address + 19) == 0x88)
        {
            satisfied = true;
        }
    }

    secp256k1_context_destroy(ctx);

    if (satisfied)
    {
        print_address(private_key, public_key_full_hash);
        return 0;
    }

    return 1;
}

static double compute_probability50_addresses_count(double difficulty)
{
    return std::floor(std::log(0.5) / std::log(1. - (1. / difficulty)));
}

static double compute_probability(double difficulty, std::uint64_t attempts)
{
    double prob = 1 - std::pow(1. - (1. / difficulty), attempts);
    return std::round(10000. * prob) / 100.;
};

static double compute_difficulty(unsigned int length)
{
    return std::pow(16, length);
};

int main()
{
    int prng_size = 0;
    ippsPRNGGetSize(&prng_size);
    if (prng_size > IPP_PRNG_SIZE_MAX || !prng_size)
    {
        throw;
    }

    bool terminate = false;

    const int pattern_length = 12;
    const double difficulty = compute_difficulty(pattern_length);
    const double prob50addrs = compute_probability50_addresses_count(difficulty);

    std::uint64_t max = 1'000'000'000'000'000;
    int nthreads = ::omp_get_max_threads();

    std::uint64_t batchsize = 1'000'000;
    std::uint64_t batchcount = max / batchsize;
    std::uint64_t finished_batches = 0;

    printf("Scheduling %d batches for %d threads, batch size %d\n", batchcount, nthreads, batchsize);
    printf("50%% probability addresses: %.0f, difficulty: %.0f\n", prob50addrs, difficulty);

    auto master_start = std::chrono::high_resolution_clock::now();

#pragma omp parallel for schedule(dynamic, 1) shared(terminate)
    for (int i = 0; i < batchcount; ++i)
    {
        if (terminate)
        {
            continue;
        }

        int tid = ::omp_get_thread_num();

        auto start = std::chrono::high_resolution_clock::now();

        int result = generate_key(batchsize, &terminate);
        if (result == 0)
        {
            terminate = true;
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = end - start;
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        double duration_s = duration_ms / 1000.;
        double key_per_second = batchsize / duration_s;

        double prob = compute_probability(difficulty, (finished_batches + 1) * batchsize);

#pragma omp atomic update
        ++finished_batches;

#pragma omp critical
        printf("Batch %d finished in %.2fs. Avg %.2f keys per second. Prob %.4f%%\n", i, duration_s, key_per_second, prob);
    }

    auto master_end = std::chrono::high_resolution_clock::now();
    auto master_duration = master_end - master_start;
    auto master_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(master_duration).count();
    double master_duration_s = master_duration_ms / 1000.;
    double master_key_per_second = batchsize * finished_batches / master_duration_s;
    printf("Total %d batch executed in %.2fs. Avg %.2f keys per second\n", finished_batches, master_duration_s, master_key_per_second);

    return 0;
}
