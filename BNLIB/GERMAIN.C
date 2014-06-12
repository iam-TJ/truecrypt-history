/*
 * Sophie Germain prime generation using the bignum library and sieving.
 *
 * Copyright (c) 1995  Colin Plumb.  All rights reserved.
 * For licensing and other legal details, see the file legal.c.
 */
#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H 0
#endif
#if HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * Some compilers complain about #if FOO if FOO isn't defined,
 * so do the ANSI-mandated thing explicitly...
 */
#ifndef NO_ASSERT_H
#define NO_ASSERT_H 0
#endif
#if !NO_ASSERT_H
#include <assert.h>
#else
#define assert(x) (void)0
#endif

#ifndef BNDEBUG
#define BNDEBUG 0
#endif
#if BNDEBUG
#include <stdio.h>
#endif

#include "bn.h"
#include "germain.h"
#include "jacobi.h"
#include "lbnmem.h"	/* For lbnMemWipe */
#include "sieve.h"

#include "kludge.h"

/* Size of the sieve area (can be up to 65536/8 = 8192) */
#define SIEVE 8192

/*
 * Helper function that does the slow primality test.
 * bn is the input bignum; a and e are temporary buffers that are
 * allocated by the caller to save overhead.  bn2 is filled with
 * a copy of 2*bn+1 if bn is found to be prime.
 *
 * Returns 0 if both bn abd bn2 are prime, >0 if not prime, and -1 on
 * error (out of memory).  If not prime, the return value is the number
 * of modular exponentiations performed.   Prints a '+' or '-' on the
 * given FILE (if any) for each test that is passed by bn, and a '*'
 * for each test that is passed by bn2.
 *
 * The testing consists of strong pseudoprimality tests, to the bases 2,
 * 3, 5, 7, 11, 13 and 17.  (Also called Miller-Rabin, although that's not
 * technically correct if we're using fixed bases.)  Some people worry
 * that this might not be enough.  Number theorists may wish to generate
 * primality proofs, but for random inputs, this returns non-primes with a
 * probability which is quite negligible, which is good enough.
 *
 * It has been proved (see Carl Pomerance, "On the Distribution of
 * Pseudoprimes", Math. Comp. v.37 (1981) pp. 587-593) that the number
 * of pseudoprimes (composite numbers that pass a Fermat test to the
 * base 2) less than x is bounded by:
 * exp(ln(x)^(5/14)) <= P_2(x)	### CHECK THIS FORMULA - it looks wrong! ###
 * P_2(x) <= x * exp(-1/2 * ln(x) * ln(ln(ln(x))) / ln(ln(x))).
 * Thus, the local density of Pseudoprimes near x is at most
 * exp(-1/2 * ln(x) * ln(ln(ln(x))) / ln(ln(x))), and at least
 * exp(ln(x)^(5/14) - ln(x)).  Here are some values of this function
 * for various k-bit numbers x = 2^k:
 * Bits	Density <=	Bit equivalent	Density >=	Bit equivalent
 *  128	3.577869e-07	 21.414396	4.202213e-37	 120.840190
 *  192	4.175629e-10	 31.157288	4.936250e-56	 183.724558
 *  256 5.804314e-13	 40.647940	4.977813e-75	 246.829095
 *  384 1.578039e-18	 59.136573	3.938861e-113	 373.400096
 *  512 5.858255e-24	 77.175803	2.563353e-151	 500.253110
 *  768 1.489276e-34	112.370944	7.872825e-228	 754.422724
 * 1024 6.633188e-45	146.757062	1.882404e-304	1008.953565
 *
 * As you can see, there's quite a bit of slop between these estimates.
 * In fact, the density of pseudoprimes is conjectured to be closer
 * to the square of that upper bound.  E.g. the density of pseudoprimes
 * of size 256 is around 3 * 10^-27.  The density of primes is very
 * high, from 0.005636 at 256 bits to 0.001409 at 1024 bits, i.e.
 * more than 10^-3.
 *
 * For those people used to cryptographic levels of security where the
 * 56 bits of DES key space is too small because it's exhaustible with
 * custom hardware searching engines, note that you are not generating
 * 50,000,000 primes per second on each of 56,000 custom hardware chips
 * for several hours.  The chances that another Dinosaur Killer asteroid
 * will land today is about 10^-11 or 2^-36, so it would be better to
 * spend your time worrying about *that*.  Well, okay, there should be
 * some derating for the chance that astronomers haven't seen it yet, but
 * I think you get the idea.  For a good feel about the probability of
 * various events, I have heard that a good book is by E'mile Borel,
 * "Les Probabilite's et la vie".  (The 's are accents, not apostrophes.)
 *
 * For more on the subject, try "Finding Four Million Large Random Primes",
 * by Ronald Rivest, in Advancess in Cryptology: Proceedings of Crypto '90.
 * He used a small-divisor test, then a Fermat test to the base 2, and then
 * 8 iterations of a Miller-Rabin test.  About 718 million random 256-bit
 * integers were generated, 43,741,404 passed the small divisor test,
 * 4,058,000 passed the Fermat test, and all 4,058,000 passed all 8
 * iterations of the Miller-Rabin test, proving their primality beyond most
 * reasonable doubts.
 *
 * If the probability of getting a pseudoprime is some small p, then
 * the probability of not getting it in t trials is (1-p)^t.  Remember
 * that, for small p, (1-p)^(1/p) ~ 1/e, the base of natural logarithms.
 * (This is more commonly expressed as e = lim_{x\to\infty} (1+1/x)^x.)
 * Thus, (1-p)^t ~ e^(-p*t) = exp(-p*t).  So the odds of being able to
 * do this many tests without seeing a pseudoprime if you assume that
 * p = 10^-6 (one in a million) is one in 57.86.  If you assume that
 * p = 2*10^-6, it's one in 3347.6.  So it's implausible that the
 * density of pseudoprimes is much more than one millionth the density
 * of primes.
 *
 * He also gives a theoretical argument that the chance of finding a
 * 256-bit non-prime which satisfies one Fermat test to the base 2 is less
 * than 10^-22.  The small divisor test improves this number, and if the
 * numbers are 512 bits (as needed for a 1024-bit key) the odds of failure
 * shrink to about 10^-44.  Thus, he concludes, for practical purposes
 * *one* Fermat test to the base 2 is sufficient.
 */
static int
germainPrimeTest(struct BigNum const *bn, struct BigNum *bn2, struct BigNum *e,
	struct BigNum *a, int (*f)(void *arg, int c), void *arg)
{
	int err;
	unsigned i;
	int j;
	unsigned k, l;
	static unsigned const primes[] = {2, 3, 5, 7, 11, 13, 17};

#if BNDEBUG	/* Debugging */
	/*
	 * This is debugging code to test the sieving stage.
	 * If the sieving is wrong, it will let past numbers with
	 * small divisors.  The prime test here will still work, and
	 * weed them out, but you'll be doing a lot more slow tests,
	 * and presumably excluding from consideration some other numbers
	 * which might be prime.  This check just verifies that none
	 * of the candidates have any small divisors.  If this
	 * code is enabled and never triggers, you can feel quite
	 * confident that the sieving is doing its job.
	 */
	i = bnModQ(bn, 15015);	/* 15015 = 3 * 5 * 7 * 11 * 13 */
	if (!(i % 3)) printf("bn div by 3!");
	if ((i % 3) == 1) printf("bn2 div by 3!");
	if (!(i % 5)) printf("bn div by 5!");
	if ((i % 5) == 2) printf("bn2 div by 5!");
	if (!(i % 7)) printf("bn div by 7!");
	if ((i % 7) == 3) printf("bn2 div by 7!");
	if (!(i % 11)) printf("bn div by 11!");
	if ((i % 11) == 5) printf("bn2 div by 11!");
	if (!(i % 13)) printf("bn div by 13!");
	if ((i % 13) == 6) printf("bn2 div by 13!");
	i = bnModQ(bn, 7429);	/* 7429 = 17 * 19 * 23 */
	if (!(i % 17)) printf("bn div by 17!");
	if ((i % 17) == 8) printf("bn2 div by 17!");
	if (!(i % 19)) printf("bn div by 19!");
	if ((i % 19) == 9) printf("bn2 div by 19!");
	if (!(i % 23)) printf("bn div by 23!");
	if ((i % 23) == 11) printf("bn2 div by 23!");
	i = bnModQ(bn, 33263);	/* 33263 = 29 * 31 * 37 */
	if (!(i % 29)) printf("bn div by 29!");
	if ((i % 29) == 14) printf("bn2 div by 29!");
	if (!(i % 31)) printf("bn div by 31!");
	if ((i % 31) == 15) printf("bn2 div by 31!");
	if (!(i % 37)) printf("bn div by 37!");
	if ((i % 37) == 18) printf("bn2 div by 37!");
#endif
	/*
	 * First, check whether bn is prime.  This uses a fast primality
	 * test which usually obviates the need to do one of the
	 * confirmation tests later.  See prime.c for a full explanation.
	 * We check bn first because it's one bit smaller, saving one
	 * modular squaring, and because we might be able to save another
	 * when testing it.  (1/4 of the time.)  A small speed hack,
	 * but finding big Sophie Germain primes is *slow*.
	 */
	if (bnCopy(e, bn) < 0)
		return -1;
	(void)bnSubQ(e, 1);
	l = bnLSWord(e);

	j = 1;	/* Where to start in prime array for strong prime tests */

	if (l & 7) {
		bnRShift(e, 1);
		if (bnTwoExpMod(a, e, bn) < 0)
			return -1;
		if ((l & 7) == 6) {
			/* bn == 7 mod 8, expect +1 */
			if (bnBits(a) != 1)
				return 1;	/* Not prime */
			k = 1;
		} else {
			/* bn == 3 or 5 mod 8, expect -1 == bn-1 */
			if (bnAddQ(a, 1) < 0)
				return -1;
			if (bnCmp(a, bn) != 0)
				return 1;	/* Not prime */
			k = 1;
			if (l & 4) {
				/* bn == 5 mod 8, make odd for strong tests */
				bnRShift(e, 1);
				k = 2;
			}
		}
	} else {
		/* bn == 1 mod 8, expect 2^((bn-1)/4) == +/-1 mod bn */
		bnRShift(e, 2);
		if (bnTwoExpMod(a, e, bn) < 0)
			return -1;
		if (bnBits(a) == 1) {
			j = 0;	/* Re-do strong prime test to base 2 */
		} else {
			if (bnAddQ(a, 1) < 0)
				return -1;
			if (bnCmp(a, bn) != 0)
				return 1;	/* Not prime */
		}
		k = 2 + bnMakeOdd(e);
	}

	/*
	 * It's prime!  Print a success indicator and check bn2.
	 * The success indicator we print is the sign of Jacobi(2,bn2),
	 * which is available to us in l.  bn2 = 2*bn + 1.  Since bn is
	 * odd, bn2 must be == 3 mod 4, so the options modulo 8 are 3 and 7.
	 * 3 if bn == 1 mod 4, 7 if bn == 3 mod 4.  The signs of the
	 * Jacobi symbol are - and + in thse two cases.  Set l to be
	 * a flag, 1 if the symbol is positive.
	 */
	l = (l >> 1) & 1;
	if (f && (err = f(arg, "-+"[l])) < 0)
		return err;

	/*
	 * Now check bn2.  Since bn2 == 3 mod 4, a strong pseudoprimality
	 * test boils down to looking at a^((bn2-1)/2) mod bn and seeing
	 * if it's +/-1.  Of course, that exponent is just bn...
	 */
	if (bnCopy(bn2, bn) < 0 || bnAdd(bn2, bn) < 0)
		return -1;
	(void)bnAddQ(bn2, 1);	/* Can't overflow */
	if (bnTwoExpMod(a, bn, bn2) < 0)
		return -1;
	if (l) {	/* Expect + */
		if (bnBits(a) != 1)
			return 2;	/* Not prime */
	} else {
		if (bnAddQ(a, 1) < 0)
			return -1;
		if (bnCmp(a, bn2) != 0)
			return 2;	/* Not prime */
	}

	/*
	 * Success!  We have found a key!  Now go on to confirmation
	 * tests...  k is the amount by which e has already been shifted
	 * down.  j = 1 unless the test to the base 2 could stand to
	 * be re-done, in which case it's 0.
	 */
	k += bnMakeOdd(e);
	for (i = j; i < sizeof(primes)/sizeof(*primes); i++) {
		if (f && (err = f(arg, '*')) < 0)
			return err;

		/* Check that bn is a strong pseudoprime */
		(void)bnSetQ(a, primes[i]);
		if (bnExpMod(a, a, e, bn) < 0)
			return -1;

		if (bnBits(a) != 1) {
			l = k;
			for (;;) {
				if (bnAddQ(a, 1) < 0)
					return -1;
				if (bnCmp(a, bn) == 0)	/* Was result bn-1? */
					break;	/* Prime */
				if (!--l)
					return 2*i+1;	/* Failed, not prime */
				/* This part is executed once, on average. */
				(void)bnSubQ(a, 1);	/* Restore a */
				if (bnSquare(a, a) < 0 || bnMod(a, a, bn) < 0)
					return -1;
				if (bnBits(a) == 1)
					return 2*i+1;	/* Failed, not prime */
			}
		}

		/* Okay, that was prime - print success indicator */
		j = bnJacobiQ(primes[i], bn2);
		if (f && (err = f(arg, j < 0 ? '-' : '+')) < 0)
			return err;
		/* If we're re-doing the base 2, we're done. */
		if (!i)
			continue;	/* Already done next part */

		/* Check that p^bn == Jacobi(p,bn2) (mod bn2) */
		(void)bnSetQ(a, primes[i]);
		if (bnExpMod(a, a, bn, bn2) < 0)
			return -1;
		/*
		 * FIXME:  Actually, we don't need to compute the Jacobi
		 * sumbol externally... it never happens that a = +/-1
		 * but it's the wrong one.  So we can just look at a and
		 * use its sign.  Find a proof somewhere.
		 */
		if (j < 0) {
			/* Not a quadratic residue, should have a =  bn2-1 */
			if (bnAddQ(a, 1) < 0)
				return -1;
			if (bnCmp(a, bn2) != 0)	/* Was result bn2-1? */
				return 2*i+2;	/* Mismatch -> failed */
		} else {
			/* Quadratic residue, should have a = 1 */
			if (bnBits(a) != 1)
				return 2*i+2;	/* Mismatch -> failed */
		}
		/* It worked (to the base primes[i]) */
	}

	/* Print final success indicator */
	if (f && (err = f(arg, '*')) < 0)
		return err;
	return 0;	/* Prime! */
}

/*
 * Modifies the bignum to return the next Sohpie Germain prime >= the
 * input value.  Sohpie Germain primes are number such that p is
 * prime and (p-1)/2 is also prime.
 *
 * Returns >=0 on success or -1 on failure (out of memory).  On success,
 * the return value is the number of modular exponentiations performed
 * (excluding the final confirmations).  This never gives up searching.
 *
 * The FILE *f argument, if non-NULL, has progress indicators written
 * to it.  A dot (.) is written every time a primeality test is failed,
 * a plus (+) or minus (-) when the smaller prime of the pair passes a
 * test, and a star (*) when the larger one does.  Finally, a slash (/)
 * is printed when the sieve was emptied without finding a prime and is
 * being refilled.
 *
 * Apologies to structured programmers for all the GOTOs.
 */
int
germainPrimeGen(struct BigNum *bn2, int (*f)(void *arg, int c), void *arg)
{
	int retval;
	unsigned p, prev;
	struct BigNum a, e, bn;
	int modexps = 0;
#ifdef MSDOS
	unsigned char *sieve;
#else
	unsigned char sieve[SIEVE];
#endif

#ifdef MSDOS
	sieve = lbnMemAlloc(SIEVE);
	if (!sieve)
		return -1;
#endif

	bnBegin(&a);
	bnBegin(&e);
	bnBegin(&bn);

	/*
	 * Obviously, the prime we find must be odd.  Further, (p-1)/2
	 * must be odd, so p == 3 (mod 3).  Finally, p != 0 (mod 3),
	 * and (p-1)/2 != 0 (mod 3), meaning that p != 1 (mod 3).  Thus,
	 * p == 11 (mod 12).  Increase bn2 to have this property, and
	 * search is steps of 12.  (Actually, we work with the smaller
	 * bn, and increase it to 5 mod 6, then search in steps of 6.)
	 */
	if (bnCopy(&bn, bn2) < 0)
		goto failed;
	bnRShift(&bn, 1);
	p = bnModQ(&bn, 6);
	if (bnAddQ(&bn, 5-p) < 0)
		goto failed;

	for (;;) {
		if (sieveBuild(sieve, SIEVE, &bn, 6, 1) < 0)
			goto failed;

		p = prev = 0;
		if (sieve[0] & 1 || (p = sieveSearch(sieve, SIEVE, p)) != 0) {
			do {
				/*
				 * Adjust bn to have the right value,
				 * incrementing in steps of < 65536.
				 * 10922 = 65536/6.
				 */
				assert(p >= prev);
				prev = p-prev;	/* Delta - add 6*prev to bn */
#if SIEVE*8*6 >= 65536
				while (prev > 10922) {
					if (bnAddQ(&bn, 6*10922) < 0)
						goto failed;
					prev -= 10922;
				}
#endif
				if (bnAddQ(&bn, 6*prev) < 0)
					goto failed;
				prev = p;

				/* Okay, do the strong tests. */
				retval = germainPrimeTest(&bn, bn2, &e, &a,
				                          f, arg);
				if (retval <= 0)
					goto done;
				modexps += retval;
				if (f && (retval = f(arg, '.')) < 0)
					goto done;

				/* And try again */
				p = sieveSearch(sieve, SIEVE, p);
			} while (p);
		}

		/* Ran out of sieve space - increase bn and keep trying. */
#if SIEVE*8*6 >= 65536
		p = ((SIEVE-1)*8+7) - prev;	/* Number of steps (of 6) */
		while (p >= 10922) {
			if (bnAddQ(&bn, 6*10922) < 0)
				goto failed;
			p -= 10922;
		}
		if (bnAddQ(&bn, 6*(p+1)) < 0)
			goto failed;
#else
		if (bnAddQ(&bn, SIEVE*8*6 - prev) < 0)
			goto failed;
#endif
		/*
		 * Make sure bn2 is up to date for checkpoint/restart
		 * operation triggered by calling f with '/'.
		 */
		if (bnCopy(bn2, &bn) < 0 || bnAdd(bn2, &bn) < 0)
			goto failed;
		(void)bnAddQ(bn2, 1);	/* Can't overflow */
		if (f && (retval = f(arg, '/')) < 0)
			goto done;
	} /* for (;;) */

failed:
	retval = -1;
done:
	bnEnd(&bn);
	bnEnd(&e);
	bnEnd(&a);
#ifdef MSDOS
	lbnMemFree(sieve, SIEVE);
#else
	lbnMemWipe(sieve, sizeof(sieve));
#endif
	return retval < 0 ? retval : modexps;
}
