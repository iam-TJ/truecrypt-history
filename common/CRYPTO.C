/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"
#include "crypto.h"
#include "random.h"

PCRYPTO_INFO
crypto_open ()
{
	/* Do the crt allocation */
	PCRYPTO_INFO cryptoInfo = e4malloc (sizeof (CRYPTO_INFO));
	if (cryptoInfo == NULL)
		return NULL;

	cryptoInfo->cipher = -1;
	return cryptoInfo;
}

void
crypto_loadkey (PKEY_INFO keyInfo, char *lpszUserKey, int nUserKeyLen)
{
	keyInfo->keyLength = nUserKeyLen;
	burn (keyInfo->userKey, sizeof (keyInfo->userKey));
	memcpy (keyInfo->userKey, lpszUserKey, nUserKeyLen);
}

void
crypto_close (PCRYPTO_INFO cryptoInfo)
{
	burn (cryptoInfo, sizeof (CRYPTO_INFO));
	e4mfree (cryptoInfo);
}

int
get_block_size (int cipher)
{
	if (cipher);		/* remove warning */
	return 8;
}

int
get_key_size (int cipher)
{
	if (cipher == DES56)
		return 8;
	else if (cipher == IDEA)
		return 16;
	else if (cipher == BLOWFISH)
		return 32;
	else if (cipher == TRIPLEDES)
		return 24;
	else if (cipher == CAST)
		return 16;
	else if (cipher == MDCSHA)
		return 64;
	else
	{
		return 0;
	}
}

char *
get_cipher_name (int cipher)
{
	if (cipher == BLOWFISH)
		return "BLOWFISH";
	else if (cipher == IDEA)
		return "IDEA";
	else if (cipher == DES56)
		return "DES56";
	else if (cipher == TRIPLEDES)
		return "TRIPLEDES";
	else if (cipher == CAST)
		return "CAST";
	else if (cipher == MDCSHA)
		return "MDCSHA";
	else if (cipher == NONE)
		return "NONE";
	else
		return "UNKNOWN";
}
