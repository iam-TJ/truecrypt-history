/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <time.h>

#include "crypto.h"
#include "random.h"
#include "endian.h"
#include "fat.h"
#include "volumes1.h"

/* new format2 */
#include "pkcs5.h"

#define MDCSHA_IVSIZE           SHA_DIGESTSIZE
#define MDCSHA_KEYSIZE          SHA_BLOCKSIZE
#define MDCSHA_BLOCKSIZE        SHA_DIGESTSIZE

/* The size of the key buffer.  Note that increasing this value will result
   in a significant increase in the setup time, so it will be necessary to
   make a corresponding decrease in the iteration count */

#define KEYBUFFER_SIZE          256

/* Encrypt data in CFB mode */
void
EncryptCFB (unsigned char *iv, unsigned char *auxKey,
	    unsigned char *buffer, int noBytes)
{
	int i, ivCount;

	while (noBytes)
	{
		ivCount = (noBytes > MDCSHA_BLOCKSIZE) ? MDCSHA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ShaTransform0 ((unsigned long *) iv, (unsigned long *) auxKey);

		/* XOR the buffer contents with the encrypted IV */
		for (i = 0; i < ivCount; i++)
			buffer[i] ^= iv[i];

		/* Shift ciphertext into IV */
		memcpy (iv, buffer, ivCount);

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
	}

}

/* Decrypt data in CFB mode.  Note that the transformation can be made faster
   (but less clear) with temp = buffer, buffer ^= iv, iv = temp all in one
   loop */
void
DecryptCFB (unsigned char *iv, unsigned char *auxKey,
	    unsigned char *buffer, int noBytes)
{
	unsigned char temp[MDCSHA_BLOCKSIZE];
	int i, ivCount;

	while (noBytes)
	{
		ivCount = (noBytes > MDCSHA_BLOCKSIZE) ? MDCSHA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ShaTransform0 ((unsigned long *) iv, (unsigned long *) auxKey);

		/* Save ciphertext */
		memcpy (temp, buffer, ivCount);

		/* XOR the buffer contents with the encrypted IV */
		for (i = 0; i < ivCount; i++)
			buffer[i] ^= iv[i];

		/* Shift ciphertext into IV */
		memcpy (iv, temp, ivCount);

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
	}

	/* Clean up */
	burn (temp, MDCSHA_BLOCKSIZE);
}


_inline unsigned long
DecryptXor (unsigned long input, unsigned long *reg1, unsigned long reg2)
{
	unsigned long tmp = input;
	input = *reg1;
	*reg1 = tmp;

	input = input ^ reg2;
	input = input ^ *reg1;

	return input;
}

_inline unsigned long
EncryptXor (unsigned long input, unsigned long *reg1, unsigned long reg2)
{
	input = input ^ *reg1;
	input = input ^ reg2;
	*reg1 = input;

	return input;
}

void
  _cdecl
EncryptSector (unsigned long *data,
	       unsigned long secNo,
	       unsigned long noSectors,
	       unsigned char *auxKey,
	       unsigned char *iv,
	       int cipher)
{
	unsigned long i, j;
	unsigned long A, B, C, D, E;
	unsigned long shaDigest[5];

	if (cipher);		/* Remove warning */

	while (noSectors--)
	{
		/* reverse the sector */
		LongReverse (data, SECTOR_SIZE);

		/* setup the sector iv which is the master iv + sector number */
		A = ((unsigned long *) iv)[0];
		B = ((unsigned long *) iv)[1];
		C = ((unsigned long *) iv)[2];
		D = ((unsigned long *) iv)[3];
		E = ((unsigned long *) iv)[4];

		i = 0xffffffff - E < secNo;
		E += secNo;

		j = 0xffffffff - D < i;
		D += i;

		i = 0xffffffff - C < j;
		C += j;

		j = 0xffffffff - B < i;
		B += i;

		i = 0xffffffff - A < i;
		A += j;

		/* scramble almost the entire sector */
		for (i = 0; i < 25; i++)
		{
			data[0] = EncryptXor (data[0], &A, B);
			data[1] = EncryptXor (data[1], &B, C);
			data[2] = EncryptXor (data[2], &C, D);
			data[3] = EncryptXor (data[3], &D, E);
			data[4] = EncryptXor (data[4], &E, A);
			data += 5;
		}

		/* then scramble the remainder */
		data[0] = EncryptXor (data[0], &A, B);
		data[1] = EncryptXor (data[1], &B, C);
		data[2] = EncryptXor (data[2], &C, D);
		data += 3;

		/* rewind back to the start of the data */
		data -= SECTOR_SIZE / sizeof (long);

		/* Move the last 5 longwords into the IV */
		shaDigest[0] = D;
		shaDigest[1] = E;
		shaDigest[2] = A;
		shaDigest[3] = B;
		shaDigest[4] = C;

		/* encrypt almost the entire sector */
		for (j = 0; j < 25; j++)
		{
			ShaTransform0 (&shaDigest[0], (unsigned long *) auxKey);
			/* do iv worth of xor'ing */
			for (i = 0; i < 5; i++)
			{
				shaDigest[i] ^= data[i];
				data[i] = shaDigest[i];
			}

			data += 5;
		}

		ShaTransform0 (&shaDigest[0], (unsigned long *) auxKey);
		/* do the xor'ing of the remaining portion of the iv */
		for (i = 0; i < 3; i++)
		{
			shaDigest[i] ^= data[i];
			data[i] = shaDigest[i];
		}
		data += 3;

		/* rewind back to the start of the data */
		data -= SECTOR_SIZE / sizeof (long);

		/* reverse the sector */
		LongReverse (data, SECTOR_SIZE);

		data += SECTOR_SIZE / 4;
		secNo++;
	}
}

void
  _cdecl
DecryptSector (unsigned long *data,
	       unsigned long secNo,
	       unsigned long noSectors,
	       unsigned char *auxKey,
	       unsigned char *iv,
	       int cipher)
{
	unsigned long i, j, n;
	unsigned long A, B, C, D, E;
	unsigned long shaDigest[5];

	if (cipher);		/* Remove warning */

	while (noSectors--)
	{
		/* reverse the sector */
		LongReverse (data, SECTOR_SIZE);

		/* copy the first 5 longs into the sector iv */
		memcpy (shaDigest, data, 5 * sizeof (long));
		/* skip 20 bytes */
		data += 5;

		/* decrypt almost the entire sector */
		for (j = 0; j < 24; j++)
		{
			ShaTransform0 (&shaDigest[0], (unsigned long *) auxKey);
			/* do iv worth of xor'ing */
			for (i = 0; i < 5; i++)
			{
				n = data[i];
				data[i] = n ^ shaDigest[i];
				shaDigest[i] = n;
			}

			data += 5;
		}

		/* then decrypt the remainder */
		ShaTransform0 (&shaDigest[0], (unsigned long *) auxKey);
		/* do the xor'ing of the remaining portion of the iv */
		for (i = 0; i < 3; i++)
		{
			n = data[i];
			data[i] = n ^ shaDigest[i];
			shaDigest[i] = n;
		}
		data += 3;

		/* take the last 5 clear text longs */
		memcpy (shaDigest, data - 5, 20);

		/* rewind back to the start of the data */
		data -= SECTOR_SIZE / sizeof (data[0]);

		/* decrypt first block using last block as iv */
		ShaTransform0 (&shaDigest[0], (unsigned long *) auxKey);
		for (i = 0; i < 5; i++)
		{
			n = data[i];
			n ^= shaDigest[i];
			data[i] = n;
			shaDigest[i] = n;
		}

		/* setup the sector iv which is the master iv + sector number */
		A = ((unsigned long *) iv)[0];
		B = ((unsigned long *) iv)[1];
		C = ((unsigned long *) iv)[2];
		D = ((unsigned long *) iv)[3];
		E = ((unsigned long *) iv)[4];

		i = 0xffffffff - E < secNo;
		E += secNo;

		j = 0xffffffff - D < i;
		D += i;

		i = 0xffffffff - C < j;
		C += j;

		j = 0xffffffff - B < i;
		B += i;

		i = 0xffffffff - A < i;
		A += j;

		/* descramble almost the entire sector */
		for (i = 0; i < 25; i++)
		{
			data[0] = DecryptXor (data[0], &A, B);
			data[1] = DecryptXor (data[1], &B, C);
			data[2] = DecryptXor (data[2], &C, D);
			data[3] = DecryptXor (data[3], &D, E);
			data[4] = DecryptXor (data[4], &E, A);
			data += 5;
		}

		/* then descramble the remainder */
		data[0] = DecryptXor (data[0], &A, B);
		data[1] = DecryptXor (data[1], &B, C);
		data[2] = DecryptXor (data[2], &C, D);
		data += 3;

		/* rewind back to the start of the data */
		data -= SECTOR_SIZE / sizeof (data[0]);

		/* reverse the sector */
		LongReverse (data, SECTOR_SIZE);

		data += SECTOR_SIZE / 4;
		secNo++;
	}
}

void
InitKey (PKEY_INFO keyInfo, int doEncrypt)
{
	unsigned char keyData[KEYBUFFER_SIZE];
	unsigned char auxKey[MDCSHA_KEYSIZE];
	unsigned char iv[MDCSHA_IVSIZE];
	int count;

	/* Copy the key information into the key data buffer.  We silently
	   truncate the key length to the size of the buffer, but this
	   usually is some hundreds of bytes so it shouldn't be a problem. We
	   also correct the endianness of the keyData at this point.  From
	   here on all data is little-endian so there is no need for further
	   corrections */
	memset (keyData, 0, sizeof (keyData));
	keyData[0] = (unsigned char) (keyInfo->keyLength >> 8);
	keyData[1] = (unsigned char) keyInfo->keyLength;
	keyInfo->keyLength %= KEYBUFFER_SIZE - sizeof (unsigned short);
	memcpy (keyData + sizeof (unsigned short), keyInfo->userKey, keyInfo->keyLength);

	/* Set up the keyIV intermediate.  The SHS transformation uses both
	   the source and destination value to produce the output value (ie
	   SHS( a, b ) transforms a and b to give b'), so we simply set b,
	   the temporary intermediate, to the keyIV, and a, the auxKey, to
	   all zeroes */
	memcpy (iv, keyInfo->key_salt, MDCSHA_IVSIZE);
	memset (auxKey, 0, MDCSHA_KEYSIZE);

	/* Convert the endianness of all input data from the canonical form
	   to the local form */
	LongReverse ((unsigned long *) keyData, KEYBUFFER_SIZE);
	LongReverse ((unsigned long *) iv, MDCSHA_IVSIZE);
	if (doEncrypt)
		LongReverse ((unsigned long *) keyInfo->encrKey, SFS_DISKKEY_SIZE);
	else
		LongReverse ((unsigned long *) keyInfo->key, SFS_DISKKEY_SIZE);

	/* "Encrypt" the keyData with the given IV and then set the auxKey to
	   the encrypted keyData.  The act of encryption also sets the IV.
	   This is particularly important in the case of SHS, since although
	   only the first MDCSHS_KEYSIZE bytes are copied into the auxKey,
	   the IV is still affected by the entire buffer */
	for (count = 0; count < keyInfo->noIterations; count++)
	{
		EncryptCFB (iv, auxKey, keyData, KEYBUFFER_SIZE);
		memcpy (auxKey, keyData, MDCSHA_KEYSIZE);
	}

	/* En/decrypt the disk key with the user key and IV */
	if (doEncrypt)
		EncryptCFB (iv, auxKey, (unsigned char *) keyInfo->encrKey, SFS_DISKKEY_SIZE);
	else
		DecryptCFB (iv, auxKey, (unsigned char *) keyInfo->key, SFS_DISKKEY_SIZE);

	/* Set the key check byte to the last unsigned short of the encrypted
	   keyData. This is never used for anything (it's 191 bytes past the
	   end of the last value used to set the auxKey) so we're not
	   revealing much to an attacker */
	LongReverse ((unsigned long *) (keyData + KEYBUFFER_SIZE - sizeof (unsigned long)), sizeof (unsigned long));
	keyInfo->keyCheck = ((unsigned short) keyData[KEYBUFFER_SIZE - 2] << 8) | \
	    keyData[KEYBUFFER_SIZE - 1];

	/* Wipe key data */
	memset (keyData, 0, sizeof (keyData));
	memset (auxKey, 0, sizeof (auxKey));
	memset (iv, 0, sizeof (iv));

	/* Finally, convert the outgoing data back to the canonical form */
	if (doEncrypt)
		LongReverse ((unsigned long *) keyInfo->encrKey, SFS_DISKKEY_SIZE);
	else
		LongReverse ((unsigned long *) keyInfo->key, SFS_DISKKEY_SIZE);
}

void
SetupKey (PCRYPTO_INFO cryptoInfo, PKEY_INFO keyInfo)
{
	memcpy (cryptoInfo->iv, keyInfo->key, MDCSHA_IVSIZE);
	memcpy (cryptoInfo->ks, keyInfo->key + MDCSHA_IVSIZE, MDCSHA_KEYSIZE);

	/* Convert the data to the local endianness */
	LongReverse ((unsigned long *) cryptoInfo->iv, MDCSHA_IVSIZE);
	LongReverse ((unsigned long *) cryptoInfo->ks, MDCSHA_KEYSIZE);
}

/* _cdecl is needed here because the device driver defaults to stdcall, and
   some of the external assembler routines are implemented as stdcall */
void
  _cdecl
DummySectorStub (void *a, unsigned long b, unsigned long c,
		 void *d, void *e, int f)
{
	if (a && b && c && d && e && f);	/* Remove warning */
	/* This function provides a stub for encrypt/decrypt sector when
	   encryption is turned off */
}

void
  _cdecl
EncryptSector8 (unsigned long *data,
		unsigned long secNo,
		unsigned long noSectors,
		unsigned char *ks,
		unsigned char *iv,
		int cipher)
{
	unsigned long i, j;
	unsigned long D, E;
	unsigned long sectorIV[2];

	while (noSectors--)
	{
		/* setup the sector iv which is the master iv + sector number */
		D = ((unsigned long *) iv)[0];
		E = ((unsigned long *) iv)[1];

		i = 0xffffffff - E < secNo;
		E += secNo;

		j = 0xffffffff - D < i;
		D += i;

		/* scramble the entire sector */
		for (i = 0; i < 64; i++)
		{
			data[0] = EncryptXor (data[0], &D, E);
			data[1] = EncryptXor (data[1], &E, D);
			data += 2;
		}

		/* rewind back to the start of the data */
		data -= 128;

		/* Move the last 5 longwords into the IV */
		sectorIV[0] = D;
		sectorIV[1] = E;

		/* CBC encrypt the entire sector */
		for (j = 0; j < 64; j++)
		{
			data[0] ^= sectorIV[0];
			data[1] ^= sectorIV[1];

			encipher_block (cipher, data, ks);

			sectorIV[0] = data[0];
			sectorIV[1] = data[1];

			data += 2;
		}

		secNo++;
	}
}

void
  _cdecl
DecryptSector8 (unsigned long *data,
		unsigned long secNo,
		unsigned long noSectors,
		unsigned char *ks,
		unsigned char *iv,
		int cipher)
{
	unsigned long i, j;
	unsigned long D, E;
	unsigned long sectorIV[2];

	while (noSectors--)
	{
		/* copy the first 2 longs into the sector iv */
		memcpy (sectorIV, data, 8);
		/* skip 8 bytes */
		data += 2;

		/* CBC decrypt the rest of the sector */
		for (j = 0; j < 63; j++)
		{
			unsigned long a, b;

			a = data[0];
			b = data[1];

			decipher_block (cipher, data, ks);

			data[0] ^= sectorIV[0];
			data[1] ^= sectorIV[1];
			sectorIV[0] = a;
			sectorIV[1] = b;
			data += 2;
		}

		/* take the last 2 clear text longs */
		memcpy (sectorIV, data - 2, 8);

		/* rewind back to the start of the data */
		data -= 128;

		/* CBC decrypt first block using last block as iv */
		decipher_block (cipher, data, ks);

		data[0] ^= sectorIV[0];
		data[1] ^= sectorIV[1];

		/* setup the sector iv which is the master iv + sector number */
		D = ((unsigned long *) iv)[0];
		E = ((unsigned long *) iv)[1];

		i = 0xffffffff - E < secNo;
		E += secNo;

		j = 0xffffffff - D < i;
		D += i;

		/* descramble the entire sector */
		for (i = 0; i < 64; i++)
		{
			data[0] = DecryptXor (data[0], &D, E);
			data[1] = DecryptXor (data[1], &E, D);
			data += 2;
		}

		secNo++;
	}
}

int
VolumeReadHeader (char *dev, int *nVolType, char *lpszPassword, PCRYPTO_INFO * retInfo)
{
	unsigned char *input = (unsigned char *) dev;
	KEY_INFO keyInfo;
	PCRYPTO_INFO cryptoInfo;
	struct msdos_boot_sector bs;
	int nStatus = 0, i, j, nKeyLen, nKeyOffset;
	long x, len, id;
	char *tmp;

	cryptoInfo = *retInfo = crypto_open ();
	if (cryptoInfo == NULL)
		return ERR_OUTOFMEMORY;

	crypto_loadkey (&keyInfo, lpszPassword, strlen (lpszPassword));

	/* ID string */
	cryptoInfo->voltype = *nVolType = CheckVolumeID ((char *) input);
	if (*nVolType == -1)
	{
		nStatus = ERR_VOL_FORMAT_BAD;
		goto error;
	}

#ifdef VOLTEST
	printf ("\nVolume Type is %c%c%c%c\n", input[0], input[1], input[2], input[3]);
	printf ("-------------------\n");
#endif

	input += 4;

	memset (&bs, 0, SECTOR_SIZE);

	id = mgetWord (input);

	do
	{
		switch (id)
		{
		case 1:
			/* The Volume Information Packet */
#ifdef VOLTEST
			printf ("\nVolume Information Packet:\n");
#endif

			len = mgetWord (input);	/* Packet len */

#ifdef VOLTEST
			printf ("\tPacket len = %d\n", len);
#endif

			x = mgetWord (input);	/* Character set */

#ifdef VOLTEST
			printf ("\tCharacter set = %d\n", x);
#endif

			x = mgetWord (input);	/* Volume name length */

#ifdef VOLTEST
			printf ("\tVolume name length = %d\n", x);
#endif

			if (x > 0)
			{
				memcpy (bs.volume_label, input, x);

#ifdef VOLTEST
				printf ("\tVolume Label = %c%c%c%c%c%c%c%c%c%c%c\n",
					bs.volume_label[0], bs.volume_label[1], bs.volume_label[2], bs.volume_label[3],
					bs.volume_label[4], bs.volume_label[5], bs.volume_label[6], bs.volume_label[7],
					bs.volume_label[8], bs.volume_label[9], bs.volume_label[10]);
#endif

			}
			else
			{
				memcpy (bs.volume_label, "           ", 11);

#ifdef VOLTEST
				printf ("\tVolume Label = none\n");
#endif

			}


			if (x + 12 != len)
			{
				nStatus = ERR_VOL_FORMAT_BAD;
				goto error;
			}
			input += x;

			x = mgetLong (input);	/* Volume time */

#ifdef VOLTEST
			printf ("\tVolume time = %s\n", ctime (&x));
#endif

			x = mgetLong (input);	/* Volume serial */

#ifdef VOLTEST
			printf ("\tVolume serial = %08x\n", x);
#endif

			memcpy (bs.volume_id, input, 4);

#ifdef VOLTEST
			printf ("\tVolume time = %08x\n", *((long *) &bs.volume_id[0]));
#endif

			break;

		case 2:
			/* The Encryption Information Packet */

#ifdef VOLTEST
			printf ("\nEncryption Information Packet:\n");
#endif

			len = mgetWord (input);	/* Packet len */

#ifdef VOLTEST
			printf ("\tPacket len = %d\n", len);
#endif

			if (len != 154 && (len != 20 + 6 + E4M_DISKKEY_SIZE + 2))
			{
				nStatus = ERR_VOL_FORMAT_BAD;
				goto error;
			}

			/* new format2 */
			cryptoInfo->cipher = mgetWord (input);	/* Encryption algorithm */

#ifdef VOLTEST
			printf ("\tCipher = %s\n", get_cipher_name (cryptoInfo->cipher));
#endif

			if (*nVolType != E4M_VOLTYPE2)
			{
				if (cryptoInfo->cipher != NONE && cryptoInfo->cipher != MDCSHA)
				{
					nStatus = ERR_VOL_FORMAT_BAD;
					goto error;
				}
			}
			else
			{
				if (is_valid_e4m_cipher (cryptoInfo->cipher) == FALSE)
				{
					nStatus = ERR_VOL_FORMAT_BAD;
					goto error;
				}
			}

			x = mgetWord (input);	/* Keysetup counter */
			keyInfo.noIterations = (int) x;

#ifdef VOLTEST
			printf ("\tKeysetup counter = %d\n", x);
#endif

			memcpy (keyInfo.key_salt, input, 20);	/* Salt */

#ifdef VOLTEST
			printf ("\tKey Salt = ");
			for (x = 0; x < 20; x++)
				fprintf (stdout, "%02X", (unsigned char) input[x]);
			printf ("\n");
#endif

			input += 20;

			if (*nVolType != E4M_VOLTYPE2)
				nKeyLen = SFS_DISKKEY_SIZE;
			else
				nKeyLen = E4M_DISKKEY_SIZE;

			memcpy (keyInfo.key, input, nKeyLen);	/* Master Key */

			nKeyOffset = (int) ((unsigned long) input - (unsigned long) dev);

#ifdef VOLTEST
			printf ("\n\tEncrypted Disk Key =\n\t\t");

			{
				int i, n;
				char *vh = (char *) input;

				for (i = 0; i < nKeyLen / 16; i++)
				{
					for (n = 0; n < 16; n++)
						printf ("%02X", (unsigned char) vh[n]);
					vh += 16;
					printf ("\n\t\t");
				}
			}

			printf ("\n");
#endif

			input += nKeyLen;

			x = mgetWord (input);	/* Keycheck */


#ifdef VOLTEST
			printf ("\tKey Check Word = %d\n", x);
#endif

			keyInfo.keyCheck = x;

			if (*nVolType == SFS_VOLTYPE || *nVolType == E4M_OLD_VOLTYPE)
			{
				if (cryptoInfo->cipher != NONE)
				{
					/* Key setup for decryption */
					InitKey (&keyInfo, 0);
					SetupKey (cryptoInfo, &keyInfo);

#ifdef VOLTEST
					printf ("\tCalculated Key Check Word = %d  ", keyInfo.keyCheck);
#endif

					if (x != keyInfo.keyCheck)
					{

#ifdef VOLTEST
						printf ("Password wrong\n");
#endif

						nStatus = ERR_PASSWORD_WRONG;
						goto error;
					}

#ifdef VOLTEST
					printf ("Password correct\n");
#endif


				}
				else
				{
					memset (cryptoInfo->iv, 0, sizeof (cryptoInfo->iv));
					memset (cryptoInfo->ks, 0, sizeof (cryptoInfo->ks));
				}

				/* Changing of passwords on this volume
				   format not supported! */

			}
			else
			{
				/* new format2 */
				char dk[256];
				int pkcs5;

				x = mgetWord (input);	/* pkcs5 */

#ifdef VOLTEST
				printf ("\tPKCS5 = %s\n", x == 0 ? "pkcs5 using HMAC-SHA1" : "pkcs5 using HMAC-MD5");
#endif

				pkcs5 = (int) x;

				if (pkcs5 != 0 && pkcs5 != 1)
				{
					nStatus = ERR_VOL_FORMAT_BAD;
					goto error;
				}

				/* use pkcs5 to derive the key */
				if (pkcs5 == 0)
					derive_sha_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
					 20, keyInfo.noIterations, dk, 256);
				else
					derive_md5_key (keyInfo.userKey, keyInfo.keyLength, keyInfo.key_salt,
					 20, keyInfo.noIterations, dk, 256);

				x = *(unsigned short *) &dk[254];

#ifdef VOLTEST
				printf ("\tCalculated Key Check Word = %d  ", x);
#endif

				if (x != keyInfo.keyCheck)
				{

#ifdef VOLTEST
					printf ("Password wrong\n");
#endif

					burn (dk, 256);
					nStatus = ERR_PASSWORD_WRONG;
					goto error;
				}

#ifdef VOLTEST
				printf ("Password correct\n");
#endif

				/* Init with derived user key and decrypt
				   master disk key */
				init_cipher (cryptoInfo->cipher, dk, cryptoInfo->ks);

				j = get_block_size (cryptoInfo->cipher);
				for (i = 0; i < nKeyLen; i += j)
				{
					tmp = &keyInfo.key[i];
					decipher_block (cryptoInfo->cipher, tmp, cryptoInfo->ks);
				}

				/* These fields used to later change the
				   password if user wants to... */
				tmp = &keyInfo.key[0];
				memcpy (cryptoInfo->master_decrypted_key, keyInfo.key, nKeyLen);
				memcpy (cryptoInfo->key_salt, keyInfo.key_salt, 20);
				cryptoInfo->master_key_offset = nKeyOffset;
				cryptoInfo->pkcs5 = pkcs5;
				cryptoInfo->noIterations = keyInfo.noIterations;

				/* Init with decrypted master disk key for
				   sector decryption */
				tmp = &keyInfo.key[E4M_DISK_IV_SIZE];
				init_cipher (cryptoInfo->cipher, tmp, cryptoInfo->ks);

				/* Copy over the disk IV for the sectors */
				memcpy (cryptoInfo->iv, keyInfo.key, E4M_DISK_IV_SIZE);

				/* Clear out the temp. key buffer */
				burn (dk, 256);

			}

#ifdef VOLTEST
			printf ("\n\tDecrypted Disk IV =\n\t\t");

			{
				int i, n;
				char *vh = keyInfo.key;

				for (i = 0; i < E4M_DISK_IV_SIZE / 16; i++)
				{
					for (n = 0; n < 16; n++)
						printf ("%02X", (unsigned char) vh[n]);
					vh += 16;
					printf ("\n\t\t");
				}
			}

			printf ("\n");

			printf ("\n\tDecrypted Disk Key =\n\t\t");

			{
				int i, n;
				char *vh = &keyInfo.key[E4M_DISK_IV_SIZE];

				for (i = 0; i < (E4M_DISKKEY_SIZE - E4M_DISK_IV_SIZE) / 16; i++)
				{
					for (n = 0; n < 16; n++)
						printf ("%02X", (unsigned char) vh[n]);
					vh += 16;
					printf ("\n\t\t");
				}
			}

			printf ("\n");
#endif

			break;

		case 3:
			/* Filesystem Information Packet (only SFS format) */

#ifdef VOLTEST
			printf ("\nFilesystem Information Packet (only SFS format):\n");
#endif

			len = mgetWord (input);

#ifdef VOLTEST
			printf ("\tPacket len = %d\n", len);
#endif

			if (len != 27)
			{
				nStatus = ERR_VOL_FORMAT_BAD;
				goto error;
			}

			x = mgetWord (input);

#ifdef VOLTEST
			printf ("\tFilesystem = %d\n", x);
#endif

			if (x != 1)
			{
				nStatus = ERR_VOL_FORMAT_BAD;
				goto error;
			}

			if (cryptoInfo->cipher != NONE)
			{
				unsigned char iv[20];
				memcpy (iv, cryptoInfo->iv, 20);
				DecryptCFB (iv, cryptoInfo->ks, input, 25);
			}

			x = mgetWord (input);	/* Sector size */

#ifdef VOLTEST
			printf ("\tSector size = %d\n", x);
#endif

			*((unsigned short *) bs.sector_size) = (unsigned short) x;

			x = *input++;	/* Sectors per cluster */

#ifdef VOLTEST
			printf ("\tSectors per cluster = %d\n", x);
#endif

			bs.cluster_size = (unsigned char) x;

			x = mgetWord (input);	/* Number of boot sectors */

#ifdef VOLTEST
			printf ("\tNumber of boot sectors = %d\n", x);
#endif

			bs.reserved = (unsigned short) x;

			x = *input++;	/* Number of fat copies */

#ifdef VOLTEST
			printf ("\tNumber of fat copies = %d\n", x);
#endif

			bs.fats = (unsigned char) x;

			x = mgetWord (input);	/* Number of root dir entries */

#ifdef VOLTEST
			printf ("\tNumber of root dir entries = %d\n", x);
#endif

			*((unsigned short *) bs.dir_entries) = (unsigned short) x;

			x = mgetWord (input);	/* Number of disk sectors */

#ifdef VOLTEST
			printf ("\tNumber of disk sectors = %d\n", x);
#endif

			*((unsigned short *) bs.sectors) = (unsigned short) x;

			x = *input++;	/* Media descriptor byte */

#ifdef VOLTEST
			printf ("\tMedia descriptor byte = %x\n", x);
#endif

			bs.media = (unsigned char) x;

			x = mgetWord (input);	/* Number of sectors per FAT */

#ifdef VOLTEST
			printf ("\tNumber of sectors per FAT = %d\n", x);
#endif

			bs.fat_length = (unsigned short) x;

			x = mgetWord (input);	/* Number of sectors per
						   track */

#ifdef VOLTEST
			printf ("\tNumber of sectors per track = %d\n", x);
#endif

			bs.secs_track = (unsigned short) x;

			x = mgetWord (input);	/* Number of heads */

#ifdef VOLTEST
			printf ("\tNumber of heads = %d\n", x);
#endif

			bs.heads = (unsigned short) x;

			x = mgetLong (input);	/* Number of hidden sectors */

#ifdef VOLTEST
			printf ("\tNumber of hidden sectors = %d\n", x);
#endif

			bs.hidden = x;

			x = mgetLong (input);	/* Huge number of sectors */

#ifdef VOLTEST
			printf ("\tHuge number of sectors = %d\n", x);
#endif

			bs.total_sect = x;

			bs.boot_jump[0] = 0xeb;
			bs.boot_jump[1] = 0x3c;
			bs.boot_jump[2] = 0x90;

			memcmp (bs.system_id, "E4M  ", 8);
			bs.ext_boot_sign = 0x29;
			bs.boot_sign = 0xAA55;
			memcmp (bs.fs_type, "FAT16   ", 8);
			break;

		default:
			nStatus = ERR_VOL_FORMAT_BAD;
			goto error;
		}

		id = mgetWord (input);

	}
	while (id);

	if (*nVolType == SFS_VOLTYPE || *nVolType == E4M_OLD_VOLTYPE)
	{
		if (cryptoInfo->cipher != NONE)
		{
			/* Point at the correct sector encryption/decryption */
			cryptoInfo->encrypt_sector = &EncryptSector;
			cryptoInfo->decrypt_sector = &DecryptSector;
		}
		else
		{
			/* Point at the correct sector encryption/decryption */
			cryptoInfo->encrypt_sector = &DummySectorStub;
			cryptoInfo->decrypt_sector = &DummySectorStub;
			memset (cryptoInfo->iv, 0, sizeof (cryptoInfo->iv));
			memset (cryptoInfo->ks, 0, sizeof (cryptoInfo->ks));
		}
	}
	else
	{
		/* new format2 */
		cryptoInfo->encrypt_sector = &EncryptSector8;
		cryptoInfo->decrypt_sector = &DecryptSector8;
	}

	memcpy (dev, &bs, SECTOR_SIZE);

      error:
	if (nStatus != 0)
		crypto_close (cryptoInfo);

	burn (&keyInfo, sizeof (keyInfo));

	return nStatus;
}

void
SetVolumeID (char *dev, int nVolType)
{
	if (nVolType == SFS_VOLTYPE)
		memcpy (dev, "SFS1", 4);

	if (nVolType == E4M_OLD_VOLTYPE)
		memcpy (dev, "CAV ", 4);

	/* new format2 */
	if (nVolType == E4M_VOLTYPE2)
		memcpy (dev, "E4M2", 4);
}

int
CheckVolumeID (char *dev)
{
	if (memcmp (dev, "SFS1", 4) == 0)
		return SFS_VOLTYPE;

	if (memcmp (dev, "CAV ", 4) == 0)
		return E4M_OLD_VOLTYPE;

	/* new format2 */
	if (memcmp (dev, "E4M2", 4) == 0)
		return E4M_VOLTYPE2;

	return -1;
}

#ifndef DEVICE_DRIVER

#ifdef VOLFORMAT
extern HWND hDiskKey;
extern HWND hKeySalt;
#endif

int
VolumeWriteHeader (fatparams * ft, char *dev, int nVolType, int cipher, char *lpszPassword,
		   int pkcs5, PCRYPTO_INFO * retInfo)
{
	unsigned char *p = (unsigned char *) dev;
	unsigned long timestamp = (unsigned long) time (NULL);
	char *volume_name = "";
	KEY_INFO keyInfo;
	PCRYPTO_INFO cryptoInfo;
	int j, nKeyLen;

	if (nVolType == SFS_VOLTYPE || nVolType == E4M_OLD_VOLTYPE)
	{
		cryptoInfo = *retInfo = newkey (cipher, lpszPassword, strlen (lpszPassword), &keyInfo);
		if (cryptoInfo == NULL)
			return ERR_OUTOFMEMORY;

		nKeyLen = SFS_DISKKEY_SIZE;

		if (cryptoInfo->cipher != NONE)
		{
			/* Point at the correct sector encryption/decryption */
			cryptoInfo->encrypt_sector = &EncryptSector;
			cryptoInfo->decrypt_sector = &DecryptSector;
		}
		else
		{
			/* Point at the correct sector encryption/decryption */
			cryptoInfo->encrypt_sector = &DummySectorStub;
			cryptoInfo->decrypt_sector = &DummySectorStub;
			memset (cryptoInfo->iv, 0, sizeof (cryptoInfo->iv));
			memset (cryptoInfo->ks, 0, sizeof (cryptoInfo->ks));
		}
	}
	else
	{
		/* new format2 */
		cryptoInfo = *retInfo = newkey2 (cipher, pkcs5, lpszPassword, strlen (lpszPassword), &keyInfo);
		if (cryptoInfo == NULL)
			return ERR_OUTOFMEMORY;

		nKeyLen = E4M_DISKKEY_SIZE;

		cryptoInfo->encrypt_sector = &EncryptSector8;
		cryptoInfo->decrypt_sector = &DecryptSector8;

	}

	memset (dev, 0, SECTOR_SIZE);

	/* The Volume Information Packet */
	SetVolumeID ((char *) p, nVolType);
	p += 4;			/* The ID */
	mputWord (p, 1);	/* Packet #1 */
	j = strlen (volume_name);
	mputWord (p, 12 + j);	/* The Packet length */
	mputWord (p, 0);	/* The Character set */
	mputWord (p, j);	/* The Volume name length */
	mputBytes (p, volume_name, j);	/* The Volume name */
	mputLong (p, timestamp);/* The volume time */
	mputLong (p, timestamp);/* The volume serial number */

	/* The Encryption Information Packet */
	mputWord (p, (unsigned short) 2);	/* Packet #2 */
	j = 20 + nKeyLen;

	if (nVolType == SFS_VOLTYPE || nVolType == E4M_OLD_VOLTYPE)
		mputWord (p, 6 + j);	/* The Packet length */
	else
		mputWord (p, 6 + j + 2);	/* The Packet length */

	mputWord (p, cryptoInfo->cipher);	/* Algorithm identifier */
	mputWord (p, keyInfo.noIterations);	/* Key setup iteration
						   counter */
	mputBytes (p, keyInfo.key_salt, 20);	/* Disk key IV */
	mputBytes (p, keyInfo.encrKey, nKeyLen);	/* Disk key */
	mputWord (p, keyInfo.keyCheck);	/* Key check */

	if (nVolType != SFS_VOLTYPE && nVolType != E4M_OLD_VOLTYPE)
		mputWord (p, (unsigned short) pkcs5);	/* pkcs5 */

	if (nVolType == SFS_VOLTYPE)
	{
		/* The Filesystem Information Packet */
		mputWord (p, 3);/* Packet #3 */
		mputWord (p, 2 + 25);	/* The Packet length */
		mputWord (p, 1);/* The filesystem identifier */
		mputWord (p, ft->sector_size);	/* Sector size */
		mputByte (p, ft->cluster_size);	/* Sectors per cluster */
		mputWord (p, 1);/* Number of boot sectors */
		mputByte (p, ft->fats);	/* Number of FAT copies */
		mputWord (p, ft->dir_entries);	/* Number of root  entries  */
		mputWord (p, ft->sectors);	/* Number of sectors on disk */
		mputByte (p, ft->media);	/* Media descriptor byte */
		mputWord (p, ft->fat_length);	/* Number of sectors per FAT */
		mputWord (p, ft->secs_track);	/* Number of sectors per
						   track */
		mputWord (p, ft->heads);	/* Number of heads */
		mputLong (p, ft->hidden);	/* Number of hidden sectors */
		mputLong (p, ft->total_sect);	/* 32-bit number of sectors
						   on disk */

		if (cryptoInfo->cipher != NONE)
		{
			/* The filesystem packet is encrypted */
			unsigned char iv[20];
			memcpy (iv, cryptoInfo->iv, 20);
			EncryptCFB (iv, cryptoInfo->ks, p - 25, 25);
		}
	}


#ifdef VOLFORMAT
	{
		char tmp[64];
		BOOL dots3 = FALSE;
		int i;

		j = get_key_size (cipher);

		if (j > 21)
		{
			dots3 = TRUE;
			j = 21;
		}

		tmp[0] = 0;
		for (i = 0; i < j; i++)
		{
			char tmp2[8] =
			{0};
			sprintf (tmp2, "%02X", (int) (unsigned char) keyInfo.key[i + E4M_DISK_IV_SIZE]);
			strcat (tmp, tmp2);
		}

		if (dots3 == TRUE)
		{
			strcat (tmp, "...");
		}


		SetWindowText (hDiskKey, tmp);

		tmp[0] = 0;
		for (i = 0; i < 20; i++)
		{
			char tmp2[8];
			sprintf (tmp2, "%02X", (int) (unsigned char) keyInfo.key_salt[i]);
			strcat (tmp, tmp2);
		}

		SetWindowText (hKeySalt, tmp);
	}
#endif

	burn (&keyInfo, sizeof (keyInfo));

	return 0;

}

PCRYPTO_INFO
newkey (int cipher, char *lpszUserKey, int nUserKeyLen, PKEY_INFO keyInfo)
{
	PCRYPTO_INFO cryptoInfo = crypto_open ();
	if (cryptoInfo == NULL)
		return NULL;

	if (cipher != NONE)
	{
		memcpy (keyInfo->userKey, lpszUserKey, nUserKeyLen);
		keyInfo->keyLength = nUserKeyLen;
		keyInfo->noIterations = 200;
		cryptoInfo->cipher = cipher;

		/* Salt for the users key */
		RandgetBytes (keyInfo->key_salt, 20);
		/* The disk key itself */
		RandgetBytes (keyInfo->key, SFS_DISKKEY_SIZE);
		/* Copy it over  to the encrKey buffer for encryption */
		memcpy (keyInfo->encrKey, keyInfo->key, SFS_DISKKEY_SIZE);

		/* First use the users key to encrypt the disk key + encrypt
		   the disk key */
		InitKey (keyInfo, 1);

		/* Then load and use the disk key to encrypt the sectors */
		SetupKey (cryptoInfo, keyInfo);
	}
	else
	{
		memset (cryptoInfo->iv, 0, sizeof (cryptoInfo->iv));
		memset (cryptoInfo->ks, 0, sizeof (cryptoInfo->ks));
		cryptoInfo->cipher = cipher;
	}

	return cryptoInfo;
}

PCRYPTO_INFO
newkey2 (int cipher, int pkcs5, char *lpszUserKey, int nUserKeyLen, PKEY_INFO keyInfo)
{
	PCRYPTO_INFO cryptoInfo = crypto_open ();
	char dk[256], *tmp;
	long x;
	int j, i;

	if (cryptoInfo == NULL)
		return NULL;

	memcpy (keyInfo->userKey, lpszUserKey, nUserKeyLen);
	keyInfo->keyLength = nUserKeyLen;
	keyInfo->noIterations = 1000;
	cryptoInfo->cipher = cipher;

	/* Salt for the users key */
	RandgetBytes (keyInfo->key_salt, 20);
	/* The disk key itself */
	RandgetBytes (keyInfo->key, E4M_DISKKEY_SIZE);
	/* Copy it over  to the encrKey buffer for encryption */
	memcpy (keyInfo->encrKey, keyInfo->key, E4M_DISKKEY_SIZE);

	/* Use pkcs5 to derive the key */
	if (pkcs5 == 0)
	{
		derive_sha_key (keyInfo->userKey, keyInfo->keyLength, keyInfo->key_salt,
				20, keyInfo->noIterations, dk, 256);
	}
	else
	{
		derive_md5_key (keyInfo->userKey, keyInfo->keyLength, keyInfo->key_salt,
				20, keyInfo->noIterations, dk, 256);
	}

	/* Extract out a key check word */
	x = *(unsigned short *) &dk[254];
	keyInfo->keyCheck = x;

	/* Init with derived user key and encrypt master disk key */
	init_cipher (cryptoInfo->cipher, dk, cryptoInfo->ks);

	j = get_block_size (cryptoInfo->cipher);
	for (i = 0; i < E4M_DISKKEY_SIZE; i += j)
	{
		tmp = &keyInfo->encrKey[i];
		encipher_block (cryptoInfo->cipher, tmp, cryptoInfo->ks);
	}

	/* Init with master disk key for sector decryption */
	tmp = &keyInfo->key[E4M_DISK_IV_SIZE];
	init_cipher (cryptoInfo->cipher, tmp, cryptoInfo->ks);

	/* Copy over the disk IV for the sectors */
	memcpy (cryptoInfo->iv, keyInfo->key, E4M_DISK_IV_SIZE);

	/* Clear out the temp. key buffer */
	burn (dk, 256);

	return cryptoInfo;
}

#endif				/* !NT4_DRIVER */
