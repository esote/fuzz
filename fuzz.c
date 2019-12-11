/*
 * fuzz is string fuzzing library.
 * Copyright (C) 2019 Esote
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#if defined(LIBBSD)
#include <bsd/stdlib.h>
#elif defined(LIBSODIUM)
#include <sodium.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"

#if !defined(__OpenBSD__) \
	&& !defined(__FreeBSD__) \
	&& !defined(LIBBSD) \
	&& !defined(LIBSODIUM)
#define BAD_RAND
#endif

static int	params(char *, char *, char *, struct param *);
static uint32_t	rrand(uint32_t, uint32_t);

struct fuzz *
fuzz_init(char const *input, char const *start, char const *end, char delim)
{
	struct fuzz *f;
	char *s;
	char *e;
	char d[2];
	size_t start_l, end_l;
	size_t max_l;

	if (input == NULL || start == NULL || end == NULL) {
		errno = EINVAL;
		return NULL;
	}

	start_l = strlen(start);
	end_l = strlen(end);

	if (start_l == 0 || end_l == 0) {
		errno = EINVAL;
		return NULL;
	}

	d[0] = delim;
	d[1] = '\0';

	if ((f = calloc(1, sizeof(struct fuzz))) == NULL) {
		return NULL;
	}

	f->input_l = strlen(input);

	if ((f->input = malloc(f->input_l + 1)) == NULL) {
		goto err;
	}

	(void)memcpy(f->input, input, f->input_l + 1);

	if ((f->indices = calloc(1, sizeof(size_t))) == NULL) {
		goto err;
	}

	f->n = 1;
	max_l = 1;

	for (s = strstr(f->input, start); s != NULL; s = strstr(s, start)) {
		if ((e = strstr(s + start_l, end)) == NULL) {
			s += start_l;
			continue;
		}

		f->p = realloc(f->p, f->n * sizeof(struct param));

		if (f->p == NULL) {
			goto err;
		}

		if (params(s + start_l, e, d, &f->p[f->n - 1]) == -1) {
			goto err;
		}

		max_l += f->p[f->n - 1].n_upper;

		f->indices = realloc(f->indices, (f->n + 1) * sizeof(size_t));

		if (f->indices == NULL) {
			goto err;
		}

		f->indices[f->n] = (size_t)(s - f->input);
		f->n++;

		e += end_l;
		f->input_l -= (size_t)(e - s);
		(void)memmove(s, e, strlen(e) + 1);
	}

	f->indices = realloc(f->indices, (f->n + 1) * sizeof(size_t));

	if (f->indices == NULL) {
		goto err;
	}

	max_l += f->input_l;
	f->indices[f->n] = f->input_l + 1;
	f->n++;

	/* Release the trimmed portions. */
	if ((f->input = realloc(f->input, f->input_l + 1)) == NULL) {
		goto err;
	}

	if ((f->buf = malloc(max_l)) == NULL) {
		goto err;
	}

	return f;
err:
	fuzz_free(f);
	return NULL;
}

static int
params(char *start, char *end, char *delim, struct param *p)
{
	char *c;
	char *e;
	char *l;
	char *t;
	size_t n;
	uint32_t b;

	p->c_lower = 1;
	p->c_upper = UINT8_MAX;
	p->n_lower = 1;
	p->n_upper = 10;

	n = (size_t)(end - start);

	if ((c = malloc(n + 1)) == NULL) {
		return -1;
	}

	(void)memcpy(c, start, n);
	c[n] = '\0';

	n = 0;

	for (t = strtok_r(c, delim, &l); t != NULL; t = strtok_r(NULL, delim, &l)) {
		b = (uint32_t)strtoul(t, &e, 0);

		if (errno == EINVAL || errno == ERANGE) {
			goto err;
		} else if (t == e) {
			errno = EINVAL;
			goto err;
		}

		switch (n++) {
		case 0:
			switch (b) {
			case RAND_NO_NUL:
				break;
			case RAND_ANY:
				p->c_lower = 0;
				break;
			case RAND_PRINT:
				p->c_lower = ' ';
				p->c_upper = '~';
				break;
			default:
				errno = ERANGE;
				goto err;
			}
			break;
		case 1:
			p->n_upper = b;
			break;
		case 2:
			p->n_lower = b;
			break;
		default:
			errno = ERANGE;
			goto err;
		}
	}

	free(c);

	if (p->c_upper <= p->c_lower || p->n_upper <= p->n_lower) {
		errno = EINVAL;
		return -1;
	}

	p->c_upper -= p->c_lower;
	p->n_upper -= p->n_lower;

#if defined(BAD_RAND) && RAND_MAX < UINT32_MAX
	if (p->n_upper >= RAND_MAX) {
		errno = ERANGE;
		return -1;
	}
#endif

	return 0;
err:
	free(c);
	return -1;
}

void
fuzz_free(struct fuzz *f)
{
	if (f != NULL) {
		free(f->indices);
		free(f->p);
		free(f->input);
		free(f->buf);
		free(f);
	}
}

static uint32_t
rrand(uint32_t lower, uint32_t upper)
{
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(LIBBSD)
	return arc4random_uniform(upper) + lower;
#elif defined(LIBSODIUM)
	return randombytes_uniform(upper) + lower;
#else
	return (uint32_t)rand() % (upper - lower + 1) + lower;
#endif
}

char *
fuzz(struct fuzz *f, size_t *w)
{
	uint8_t *buf;
	size_t i, off;
	uint32_t n;

	if (f == NULL) {
		errno = EINVAL;
		return NULL;
	}

	off = 0;

	for (i = 1; i < f->n - 1; i++) {
		(void)memcpy(f->buf + off + f->indices[i - 1],
			f->input + f->indices[i - 1],
			f->indices[i] - f->indices[i - 1]);

		n = rrand(f->p[i - 1].n_lower, f->p[i - 1].n_upper);

		buf = (uint8_t *)f->buf + off + f->indices[i];
		off += n;

		for (; n > 0; n--) {
			buf[n - 1] = (uint8_t)rrand(f->p[i - 1].c_lower,
				f->p[i - 1].c_upper);
		}
	}

	(void)memcpy(f->buf + off + f->indices[f->n - 2],
		f->input + f->indices[f->n - 2],
		f->indices[f->n - 1] - f->indices[f->n - 2]);

	if (w != NULL) {
		*w = f->input_l + off + 1;
	}

	return f->buf;
}
