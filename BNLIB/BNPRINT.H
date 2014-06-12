#ifndef BNPRINT_H
#define BNPRINT_H

#include <stdio.h>
struct BigNum;

#ifdef __cplusplus
extern "C" {
#endif

int bnPrint(FILE *f, char const *prefix, struct BigNum const *bn,
	char const *suffix);

#ifdef __cplusplus
}
#endif

#endif /* BNPRINT_H */
