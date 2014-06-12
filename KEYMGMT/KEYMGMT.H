/****************************************************************************
*																			*
*				cryptlib Key Management Structures and Prototypes 			*
*						Copyright Peter Gutmann 1996						*
*																			*
****************************************************************************/

#ifndef _KEYMGMT_DEFINED

#define _KEYMGMT_DEFINED

/* A structure to hold general key-related information for the xxxGetKey()
   functions */

typedef struct {
	/* Key ID information */
	void *keyID;				/* The key/user ID */
	int keyIDsize;				/* The size of the key/user ID */
	BOOLEAN isKeyID;			/* Whether this is a key ID */

	/* Miscellaneous information */
	BOOLEAN isPublicKey;		/* Whether we want the public key */
	void *password;				/* Password to decrypt the private key */
	int passwordSize;			/* The size of the password */
	} GETKEY_INFO;

/* Prototypes for external key read functions */

KEYSET_SUBTYPE pgpGetKeysetType( FILE *filePtr );
int pgpGetKey( FILE *filePtr, CRYPT_CONTEXT *cryptContext,
			   const GETKEY_INFO *getKeyInfo );
KEYSET_SUBTYPE x509GetKeysetType( FILE *filePtr );
int x509GetKey( FILE *filePtr, CRYPT_CONTEXT *cryptContext,
				const GETKEY_INFO *getKeyInfo );

#endif /* _KEYMGMT_DEFINED */
