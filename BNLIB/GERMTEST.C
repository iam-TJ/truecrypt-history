/*
 * germtest.c - Random Sophie Germain prime generator.
 *
 * Copyright (c) 1995  Colin Plumb.  All rights reserved.
 * For licensing and other legal details, see the file legal.c.
 *
 * This generates random Sophie Germain primes using the command
 * line as a seed value.  It uses George Marsaglia's "mother of all
 * random number generators" to (using the command line as a seed)
 * to pick the starting search value and then searches sequentially
 * for the next Sophie Germain prime p (a prime such that q = (p-1)/2
 * is also prime).
 *
 * This is a really good way to burn a lot of CPU cycles.
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#if !NO_STRING_H
#include <string.h>
#elif HAVE_STRINGS_H
#include <strings.h>
#endif
#if NEED_MEMORY_H
#include <memory.h>
#endif

#include "bn.h"
#include "germain.h"
#include "sieve.h"

#include "cputime.h"

#define BNDEBUG 1

#include "bnprint.h"
#define bndPut(prompt, bn) bnPrint(stdout, prompt, bn, "\n")
#define bndPrintf printf

/*
 * Generate random numbers according to George Marsaglia's
 * Mother Of All Random Number Generators.  This has a
 * period of 0x17768215025F82EA0378038A03A203CA7FFF,
 * or decimal 2043908804452974490458343567652678881935359.
 */
static unsigned mstate[8];
static unsigned mcarry;
static unsigned mindex;

static unsigned
mRandom(void)
{
	unsigned long t;

	t = mcarry +
	    mstate[ mindex     ] * 1941ul +
	    mstate[(mindex+1)&7] * 1860ul +
	    mstate[(mindex+2)&7] * 1812ul +
	    mstate[(mindex+3)&7] * 1776ul +
	    mstate[(mindex+4)&7] * 1492ul +
	    mstate[(mindex+5)&7] * 1215ul +
	    mstate[(mindex+6)&7] * 1066ul +
	    mstate[(mindex+7)&7] * 12013ul;
	mcarry = (unsigned)(t >> 16);	/* 0 <= mcarry <= 0x5a87 */
	mindex = (mindex-1) & 7;
	return mstate[mindex] = (unsigned)(t & 0xffff);
}

/*
 * Initialize the RNG based on the given seed.
 * A zero-length seed will produce pretty lousy numbers,
 * but it will work.
 */
static void
mSeed(unsigned char const *seed, unsigned len)
{
	unsigned i;

	for (i = 0; i < 8; i++)
		mstate[i] = 0;
	mcarry = 1;
	while (len--) {
		mcarry += *seed++;
		(void)mRandom();
	}
}


/*
 * Generate a bignum of a specified length, with the given
 * high and low 8 bits. "High" is merged into the high 8 bits of the
 * number.  For example, set it to 0x80 to ensure that the number is
 * exactly "bits" bits long (i.e. 2^(bits-1) <= bn < 2^bits).
 * "Low" is merged into the low 8 bits.  For example, set it to
 * 1 to ensure that you generate an odd number.  "High" is merged
 * into the high bits; set it to 0x80 to ensure that the high bit
 * is set in the returned value.
 */
static int
genRandBn(struct BigNum *bn, unsigned bits, unsigned char high,
unsigned char low, unsigned char const *seed, unsigned len)
{
	unsigned char buf[64];
	unsigned bytes;
	unsigned l = 0;	/* Current position */
	unsigned i;

	bnSetQ(bn, 0);
	mSeed(seed, len);

	bytes = (bits+7) / 8;	/* Number of bytes to use */

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (unsigned char)mRandom();
	buf[sizeof(buf)-1] |= low;

	while (bytes > sizeof(buf)) {
		bytes -= sizeof(buf);
		/* Merge in low half of high bits, if necessary */
		if (bytes == 1 && (bits & 7))
			buf[0] |= high << (bits & 7);
		if (bnInsertBigBytes(bn, buf, l, sizeof(buf)) < 0)
			return -1;
		l += sizeof(buf);
		for (i = 0; i < sizeof(buf); i++)
			buf[i] = (unsigned char)mRandom();
	}

	/* Do the final "bytes"-long section, using the tail bytes in buf */
	/* Mask off excess high bits */
	buf[sizeof(buf)-bytes] &= 255 >> (-bits & 7);
	/* Merge in specified high bits */
	buf[sizeof(buf)-bytes] |= high >> (-bits & 7);
	if (bytes > 1 && (bits & 7))
		buf[sizeof(buf)-bytes+1] |= high << (bits & 7);
	/* Merge in the appropriate bytes of the buffer */
	if (bnInsertBigBytes(bn, buf+sizeof(buf)-bytes, l, bytes) < 0)
		return -1;
	return 0;
}

struct Progress {
	FILE *f;
	unsigned column;
	unsigned wrap;
};

/* Print a progress indicator, with line-wrap */
static int
genProgress(void *arg, int c)
{
	struct Progress *p = arg;
	if (++p->column > p->wrap) {
		putc('\n', p->f);
		p->column = 1;
	}
	putc(c, p->f);
	fflush(p->f);
	return 0;
}

static int
genSophieGermain(struct BigNum *bn, unsigned bits,
	unsigned char const *seed, unsigned len, FILE *f)
{
#if CLOCK_AVAIL
	timetype start, stop;
	unsigned long s;
#endif
	int i;
	unsigned char s1[1024], s2[1024];
	unsigned p1, p2;
	struct BigNum step;
	struct Progress progress;

	if (f)
		fprintf(f, "Generating a %u-bit Sophie Germain prime with \"%.*s\"\n",
			bits, (int)len, (char *)seed);
	progress.f = f;
	progress.column = 0;
	progress.wrap = 78;

	/* Find p - choose a starting place */
	if (genRandBn(bn, bits, 0xC0, 3, seed, len) < 0)
		return -1;
#if BNDEBUG /* DEBUG - check that sieve works properly */
	bnBegin(&step);
	bnSetQ(&step, 2);
	sieveBuild(s1, 1024, bn, 2, 0);
	sieveBuildBig(s2, 1024, bn, &step, 0);
	p1 = p2 = 0;
	if (s1[0] != s2[0])
		printf("Difference: s1[0] = %x s2[0] = %x\n", s1[0], s2[0]);
	do {
		p1 = sieveSearch(s1, 1024, p1);
		p2 = sieveSearch(s2, 1024, p2);

		if (p1 != p2)
			printf("Difference: p1 = %u p2 = %u\n", p1, p2);
	} while (p1 && p2);

	bnEnd(&step);
#endif
	/* And search for a prime */
#if CLOCK_AVAIL
	gettime(&start);
#endif
	i = germainPrimeGen(bn, f ? genProgress : 0, (void *)&progress);
	if (i < 0)
		return -1;
#if CLOCK_AVAIL
	gettime(&stop);
#endif
	if (f) {
		putc('\n', f);
		fprintf(f, "%d modular exponentiations performed.\n", i);
	}
#if CLOCK_AVAIL
	subtime(stop, start);
	s = sec(stop);
	bndPrintf("%u-bit time = %lu.%03u sec.", bits, s, msec(stop));
	if (s > 60) {
		putchar(' ');
		putchar('(');
		if (s > 3600)
			printf("%u:%02u", (unsigned)(s/3600),
			       (unsigned)(s/60%60));
		else
			printf("%u", (unsigned)(s/60));
		printf(":%02u)", (unsigned)(s%60));
	}
	putchar('\n');
#endif

	bndPut("p = ", bn);

	return 0;
}

/* Copy the command line to the buffer. */
static unsigned
copy(unsigned char *buf, int argc, char **argv)
{
	unsigned pos, len;
	
	pos = 0;
	while (--argc) {
		len = strlen(*++argv);
		memcpy(buf, *argv, len);
		buf += len;
		pos += len;
		if (argc > 1) {
			*buf++ = ' ';
			pos++;
		}
	}
	return pos;
}

int
main(int argc, char **argv)
{
	unsigned len;
	struct BigNum bn;
	unsigned char buf[1024];

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <seed>\n", argv[0]);
		fputs("\
<seed> should be a a string of bytes to be hashed to seed the prime\n\
generator.  Note that unquoted whitespace between words will be counted\n\
as a single space.  To include multiple spaces, quote them.\n", stderr);
		return 1;
	}

	len = copy(buf, argc, argv);

	bnInit();
	bnBegin(&bn);
	
	genSophieGermain(&bn, 0x100, buf, len, stdout);
	genSophieGermain(&bn, 0x200, buf, len, stdout);
	genSophieGermain(&bn, 0x300, buf, len, stdout);
	genSophieGermain(&bn, 0x400, buf, len, stdout);
	genSophieGermain(&bn, 0x500, buf, len, stdout);
	genSophieGermain(&bn, 0x600, buf, len, stdout);
#if 0
	/* These get *really* slow */
	genSophieGermain(&bn, 0x600, buf, len, stdout);
	genSophieGermain(&bn, 0x800, buf, len, stdout);
	genSophieGermain(&bn, 0xc00, buf, len, stdout);
	/* Like, plan on a *week* or more for this one. */
	genSophieGermain(&bn, 0x1000, buf, len, stdout);
#endif

	bnEnd(&bn);

	return 0;
}
