#ifndef _BLOWFISH_DEFINED

#define _BLOWFISH_DEFINED

/* Blowfish global constants */

#define BLOWFISH_BLOCKSIZE			8

/* Blowfish-SK default key setup iterations */

#define BLOWFISH_KEYSETUP_ITERATIONS	10

/* Blowfish constants */

#define BLOWFISH_SBOX_SIZE			256		/* Number of S-box entries */
#define BLOWFISH_SBOX_SIZE_BYTES	( BLOWFISH_SBOX_SIZE * 4 )
#define BLOWFISH_PARRAY_SIZE		18		/* Number of P-array entries */
#define BLOWFISH_PARRAY_SIZE_BYTES	( BLOWFISH_PARRAY_SIZE * 4 )
#define BLOWFISH_KEYSIZE_BYTES		( ( BLOWFISH_SBOX_SIZE_BYTES * 4 ) + \
										BLOWFISH_PARRAY_SIZE_BYTES )

/* A structure to hold the Blowfish key */

typedef struct {
	LONG P[ BLOWFISH_PARRAY_SIZE ];			/* P-array */
	LONG S1[ BLOWFISH_SBOX_SIZE ],
		 S2[ BLOWFISH_SBOX_SIZE ],
		 S3[ BLOWFISH_SBOX_SIZE ],
		 S4[ BLOWFISH_SBOX_SIZE ];			/* S-boxes */
	} BLOWFISH_KEY;

/* Prototypes for functions in BLOWFISH.C */

void blowfishEncrypt( BLOWFISH_KEY *key, BYTE *data );
void blowfishDecrypt( BLOWFISH_KEY *key, BYTE *data );
int blowfishKeyInit( BLOWFISH_KEY *key, BYTE *userKey, int userKeyLength );
int blowfishKeyInitSK( BLOWFISH_KEY *key, BYTE *userKey, int userKeyLength, int keySetupIterations );

#endif /* _BLOWFISH_DEFINED */
