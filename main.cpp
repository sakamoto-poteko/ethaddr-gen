#include <cstdio>
#include <climits>
#include <cmath>
#include <mkl/mkl.h>

int main()
{
    MKLVersion Version;

    mkl_get_version(&Version);

    printf("Major version:           %d\n", Version.MajorVersion);
    printf("Minor version:           %d\n", Version.MinorVersion);
    printf("Update version:          %d\n", Version.UpdateVersion);
    printf("Product status:          %s\n", Version.ProductStatus);
    printf("Build:                   %s\n", Version.Build);
    printf("Platform:                %s\n", Version.Platform);
    printf("Processor optimization:  %s\n", Version.Processor);
    printf("================================================================\n");
    printf("\n");

    static_assert(sizeof(int) == 4, "LP64 model required");

    double r[1000]; /* buffer for random numbers */
    double s;       /* average */
    VSLStreamStatePtr stream;
    int i, j;

    /* Initializing */
    s = 0.0;
    vslNewStream(&stream, VSL_BRNG_R250, 777);

    auto neg = 0;
    auto pos = 0;
    auto zero = 0;

    int appr[256] = {};

    /* Generating */
    for (i = 0; i < 10000000; i++)
    {
        unsigned char privateKey[32];
        auto status = viRngUniform(VSL_RNG_METHOD_UNIFORM_STD, stream, 8, (int *)privateKey, INT_MIN, INT_MAX);
        if (status != VSL_ERROR_OK)
        {
            throw;
        }

        for (int i = 0; i < 32; ++i)
        {
            appr[privateKey[i]]++;
        }
    }

    /* Deleting the stream */
    vslDeleteStream(&stream);

    double sum = 0.;

    for (int i = 0; i < 256; ++i)
    {
        printf("%d ", appr[i]);
        sum += appr[i];
    }
    printf("\n");

    auto mean = sum / 256.;

    auto var = 0.;
    for (int i = 0; i < 256; ++i) {
        auto diff = appr[i] - mean;
        auto v = diff * diff;
        var += v;
    }
    auto stdev = sqrt(var);

    printf("mean %f, stdev %f\n", mean, stdev);

    return 0;
}
