/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#define SFS_DISKKEY_SIZE		128
#define E4M_DISKKEY_SIZE		288

#if E4M_DISKKEY_SIZE > SFS_DISKKEY_SIZE
#define MAX_DISKKEY E4M_DISKKEY_SIZE
#else
#define MAX_DISKKEY SFS_DISKKEY_SIZE
#endif

#define MAX_PASSWORD			100

#define E4M_DISK_IV_SIZE		32

#define MAX_DISK_IV E4M_DISK_IV_SIZE

/* The encryption algorithm ID.  */
#define NONE				0
#define MDCSHA				1
#define RESERVED0                       32
#define RESERVED1                       33
#define RESERVED2                       34
#define RESERVED3                       35
#define TRIPLEDES			36
#define IDEA				37
#define BLOWFISH			38
#define DES56				39
#define CAST				40

/* Length of scheduled keys */
#define IDEA_KS				104
#define DES_KS				128
#define TRIPLEDES_KS			(DES_KS*3)
#define BLOWFISH_KS			4168
#define MDCSHA_KS			320
#define CAST_KS				128

#define MAX_EXPANDED_KEY		4168

#include "des.h"
#include "blowfish.h"
#include "idea.h"
#include "sha.h"
#include "sha1.h"
#include "cast.h"

/* _cdecl is needed here because the device driver defaults to stdcall */
typedef void (_cdecl * sector_func) (unsigned long *, unsigned long, unsigned long,
				     unsigned char *, unsigned char *, int);

typedef struct keyInfo_t
{
	int noIterations;	/* No.of times to iterate setup */
	int keyLength;		/* Length of the key */
	char userKey[MAX_PASSWORD];	/* Max pass, WITHOUT +1 for the NULL */
	char key_salt[20];	/* Key setup IV */
	char key[MAX_DISKKEY];	/* The keying material itself */
	char encrKey[MAX_DISKKEY];	/* The encrypted key */
	long keyCheck;		/* Key check */
} KEY_INFO, *PKEY_INFO;

typedef struct CRYPTO_INFO_t
{
	/* cipher information */
	int cipher;
	sector_func encrypt_sector;
	sector_func decrypt_sector;
	unsigned char iv[MAX_DISK_IV];
	unsigned char ks[MAX_EXPANDED_KEY];

	/* volume information */
	int master_key_offset;
	int master_decrypted_key[MAX_DISKKEY];
	char key_salt[20];
	int noIterations;
	int voltype;
	int pkcs5;

} CRYPTO_INFO, *PCRYPTO_INFO;

#define decipher_block(cipher, data, ks) \
{\
	if (cipher == BLOWFISH) BF_decrypt ((void *) data, (void *) ks); \
	else if (cipher == IDEA) ideaCrypt ((void *) data,(void *)  data, (void *) ((char *) ks + IDEA_KS)); \
	else if (cipher == DES56) des_encrypt ((void *) data, (void *) ks, 0); \
	else if (cipher == CAST) CAST_ecb_encrypt((void *) data,(void *) data,(void*)ks,0);  \
	else if (cipher == TRIPLEDES) des_ecb3_encrypt ((void *) data,(void *) data, (void *) ks, \
		(void*)((char*)ks+DES_KS),(void*)((char*)ks+DES_KS*2),0); \
}

#define encipher_block(cipher, data, ks) \
{\
	if (cipher == BLOWFISH) BF_encrypt ((void *) data, (void *) ks); \
	else if (cipher == IDEA) ideaCrypt ((void *) data, (void *) data, (void *) ks); \
	else if (cipher == DES56) des_encrypt ((void *) data, (void *) ks, 1); \
	else if (cipher == CAST) CAST_ecb_encrypt((void *) data,(void *) data,(void*)ks,1);  \
	else if (cipher == TRIPLEDES) des_ecb3_encrypt ((void *) data,(void *) data, (void *) ks, \
		(void*)((char*)ks+DES_KS),(void*)((char*)ks+DES_KS*2),1); \
}

#define init_cipher(cipher, key, ks) \
{\
	if (cipher == BLOWFISH) BF_set_key ((void*)ks, 32, (void*) key); \
	else if (cipher == IDEA) ideaExpandKey ((void*) key, (void*)ks, (void *) ((char *) ks + IDEA_KS)); \
	else if (cipher == DES56) des_key_sched ((void*) key, (void*)ks); \
	else if (cipher == CAST) CAST_set_key((void*)ks, 16, (void*)key); \
	else if (cipher == TRIPLEDES) {  \
		des_key_sched ((void*) key, (void*)ks); \
		des_key_sched ((void*) ((char*)key+8), (void*)((char*)ks+DES_KS)); \
		des_key_sched ((void*) ((char*)key+16), (void*)((char*)ks+DES_KS*2)); \
	} \
}

#define is_valid_e4m_cipher(cipher) \
	(cipher == BLOWFISH || \
	 cipher == IDEA || \
	cipher == DES56 || \
	cipher == CAST || \
	cipher == TRIPLEDES)

/* Everything below this line is automatically updated by the -mkproto-tool- */

PCRYPTO_INFO crypto_open (void);
void crypto_loadkey (PKEY_INFO keyInfo, char *lpszUserKey, int nUserKeyLen);
void crypto_close (PCRYPTO_INFO cryptoInfo);
int get_block_size (int cipher);
int get_key_size (int cipher);
char *get_cipher_name (int cipher);
