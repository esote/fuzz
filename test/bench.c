/* benchmark fuzz(). */

#include <sys/time.h>

#include <err.h>
#include <stdio.h>

#include "fuzz.h"

#define N	1e5

int
main(void)
{
	struct timeval t0, t1;
	struct fuzz *f;
	long double t;
	size_t i;

	if ((f = fuzz_init("[1,1000,0]", "[", "]", ',')) == NULL) {
		err(1, "fuzz_init");
	}

	if (gettimeofday(&t0, NULL) == -1) {
		err(1, "gettimeofday");
	}

	for (i = 0; i < N; i++) {
		fuzz(f, NULL);
	}

	if (gettimeofday(&t1, NULL) == -1) {
		err(1, "gettimeofday");
	}

	fuzz_free(f);

	t = t1.tv_sec - t0.tv_sec + 1e-6 * (long double)(t1.tv_usec - t0.tv_usec);
	printf("%.0f calls in %.4Lfs, %.2Lf op/s\n", N, t, N / t);
	return 0;
}
