#ifndef FUZZ_H
#define FUZZ_H

#include <stddef.h>
#include <stdint.h>

#define RAND_NO_NUL	0 /* default */
#define RAND_ANY	1
#define RAND_PRINT	2

struct param {
	uint32_t c_lower;
	uint32_t c_upper;
	uint32_t n_lower;
	uint32_t n_upper;
};

struct fuzz {
	size_t n;
	size_t *indices;
	struct param *p;
	char *input;
	size_t input_l;
	char *buf;
};

struct fuzz *	fuzz_init(char const *, char const *, char const *, char);
void		fuzz_free(struct fuzz *);
char *		fuzz(struct fuzz *, size_t *);

#endif
