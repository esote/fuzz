/* self-fuzzing test code. Generates fuzz strings to pass as arguments to
 * fuzz_init(). Run with valgrind to check invalid writes or unfreed data. */

#include <err.h>
#include <string.h>
#include <time.h>

#include "fuzz.h"

#define STR(S)	#S
#define XSTR(S)	STR(S)

#define LONG	100
#define SMALL	2
#define N	5e4
#define TIMEOUT	(3 * 60)

int
main(void)
{
	char input[LONG], start[SMALL], end[SMALL], delim;
	char *s;
	struct fuzz *f1, *f2, *f3;
	size_t i, w;
	time_t t, now;

	if ((t = time(NULL)) == -1) {
		err(1, "time");
	}

	f1 = fuzz_init("[" XSTR(RAND_ANY) "," XSTR(LONG) ",0]", "[", "]", ',');

	if (f1 == NULL) {
		err(1, "fuzz_init");
	}

	f2 = fuzz_init("[" XSTR(RAND_ANY) "," XSTR(SMALL) ",0]", "[", "]", ',');

	if (f2 == NULL) {
		err(1, "fuzz_init");
	}

	for (i = 0; i < N;) {
		if ((now = time(NULL)) == -1) {
			err(1, "time");
		} else if (now - t >= TIMEOUT) {
			warnx("timeout reached");
			break;
		}

		if ((s = fuzz(f1, &w)) == NULL) {
			err(1, "fuzz");
		}

		(void)memcpy(input, s, w);

		if ((s = fuzz(f2, &w)) == NULL) {
			err(1, "fuzz");
		}

		(void)memcpy(start, s, w);

		if ((s = fuzz(f2, &w)) == NULL) {
			err(1, "fuzz");
		}

		(void)memcpy(end, s, w);

		if ((s = fuzz(f2, NULL)) == NULL) {
			err(1, "fuzz");
		}

		delim = s[0];

		if ((f3 = fuzz_init(input, start, end, delim)) != NULL) {
			i++;
			if (fuzz(f3, NULL) == NULL) {
				err(1, "fuzz");
			}
			fuzz_free(f3);
		}
	}

	fuzz_free(f1);
	fuzz_free(f2);
}
