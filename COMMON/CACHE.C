/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#ifndef NT4_DRIVER
#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG
#endif

#include "crypto.h"
#include "fat.h"
#include "volumes1.h"
#include "apidrvr.h"

#include "cache.h"

#define CACHE_SIZE 4

char szDriverPassword[CACHE_SIZE][MAX_PASSWORD + 1];
int nDriverPasswordLen[CACHE_SIZE];
int nPasswordIdx = 0;

int
VolumeReadHeaderCache (BOOL bCache, char *dev, int *nVolType, char *lpszPassword, int nPasswordLen,
		       PCRYPTO_INFO * retInfo)
{
	/* Attempt to recognize volumes using mount password */
	int nReturnCode = VolumeReadHeader (dev, nVolType, lpszPassword, retInfo);
	int i;

	if (nReturnCode == ERR_PASSWORD_WRONG)
	{
		/* Attempt to recognize volumes from cached passwords */
		for (i = 0; i < CACHE_SIZE; i++)
		{
			if (nDriverPasswordLen[i] > 0)
			{
				nReturnCode = VolumeReadHeader (dev, nVolType, szDriverPassword[i], retInfo);

				if (nReturnCode != ERR_PASSWORD_WRONG)
					break;
			}

		}
	}

	/* Save mount passwords back into cache if asked to do so */
	if (bCache == TRUE && nPasswordLen > 0 && nReturnCode == 0)
	{
		for (i = 0; i < CACHE_SIZE; i++)
		{
			if (nDriverPasswordLen[i] > 0 && nDriverPasswordLen[i] == nPasswordLen &&
			    memcmp (szDriverPassword[i], lpszPassword, nPasswordLen) == 0)
				break;
		}

		if (i == CACHE_SIZE)
		{
			/* Store the password */
			memcpy (szDriverPassword[nPasswordIdx], lpszPassword, nPasswordLen);

			/* Add in the null as we made room for this */
			szDriverPassword[nPasswordIdx][nPasswordLen] = 0;

			/* Save the length for later */
			nDriverPasswordLen[nPasswordIdx] = nPasswordLen;

			/* Try another slot */
			nPasswordIdx = (nPasswordIdx + 1) % CACHE_SIZE;
		}
	}

	return nReturnCode;
}

void
WipeCache ()
{
	burn (szDriverPassword, sizeof (szDriverPassword));
	burn (nDriverPasswordLen, sizeof (nDriverPasswordLen));
	nPasswordIdx = 0;
}
