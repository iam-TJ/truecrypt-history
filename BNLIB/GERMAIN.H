struct BigNum;

#ifdef __cplusplus
extern "C" {
#endif

/* Generate a Sophie Germain prime */
int germainPrimeGen(struct BigNum *bn, int (*f)(void *arg, int c), void *arg);

#ifdef __cplusplus
}
#endif
