/* example usage. Generate HTTP request strings with a random path and host. */

#include <err.h>
#include <stdio.h>

#include "fuzz.h"

int
main(void)
{
	char *tmpl;
	char *s;
	struct fuzz *f;

	tmpl = "GET /[0,20,0] HTTP/1.1\nHost: []\n\n";

	if ((f = fuzz_init(tmpl, "[", "]", ',')) == NULL) {
		err(1, "fuzz_init");
	}

	if ((s = fuzz(f, NULL)) == NULL) {
		err(1, "fuzz");
	}

	puts(s);

	fuzz_free(f);
}
