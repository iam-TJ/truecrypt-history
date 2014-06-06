/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "volumes1.h"
#include "password.h"
#include "apidrvr.h"
#include "dlgcode.h"
#include "pkcs5.h"
#include "endian.h"

#include <io.h>

void
VerifyPasswordAndUpdate (HWND hwndDlg, HWND hButton, HWND hPassword,
			 HWND hVerify, char *szPassword,
			 char *szVerify, int nVolType)
{
	char szTmp1[MAX_PASSWORD + 1];
	char szTmp2[MAX_PASSWORD + 1];
	int k = GetWindowTextLength (hPassword);
	BOOL bEnable = FALSE;

	if (hwndDlg);		/* Remove warning */

	GetWindowText (hPassword, szTmp1, sizeof (szTmp1));
	GetWindowText (hVerify, szTmp2, sizeof (szTmp2));

	if (strcmp (szTmp1, szTmp2) != 0)
		bEnable = FALSE;
	else
	{
		if (isE4M (nVolType) == TRUE)
		{
			if (k >= 8)
				bEnable = TRUE;
			else
				bEnable = FALSE;
		}
		if (nVolType == SFS_VOLTYPE)
		{
			char *lpszTmp = strchr (szTmp1, ' ');
			int x = k - (lpszTmp - &szTmp1[0]);
			if (k >= 10 && lpszTmp && x > 1)
				bEnable = TRUE;
			else
				bEnable = FALSE;
		}
	}

	if (szPassword != NULL)
		memcpy (szPassword, szTmp1, sizeof (szTmp1));

	if (szVerify != NULL)
		memcpy (szVerify, szTmp2, sizeof (szTmp2));

	burn (szTmp1, sizeof (szTmp1));
	burn (szTmp2, sizeof (szTmp2));

	EnableWindow (hButton, bEnable);
}

int
ChangePwd (char *lpszVolume, char *lpszOldPassword, char *lpszPassword)
{
	int nDosLinkCreated = 0, nStatus, nVolType;
	char szDiskFile[E4M_MAX_PATH], szCFDevice[E4M_MAX_PATH];
	char szDosDevice[E4M_MAX_PATH];
	char buffer[SECTOR_SIZE], boot[SECTOR_SIZE];
	PCRYPTO_INFO cryptoInfo = NULL;
	void *dev = INVALID_HANDLE_VALUE;
	OPEN_TEST_STRUCT driver;
	DISKIO_STRUCT win9x_r0;
	diskio_f write, read;
	DWORD dwError;
	BOOL bDevice;

	CreateFullVolumePath (szDiskFile, lpszVolume, &bDevice);

	if (nCurrentOS == WIN_NT || bDevice == FALSE)
	{
		write = (diskio_f) _lwrite;
		read = (diskio_f) _lread;

		if (bDevice == FALSE)
		{
			strcpy (szCFDevice, szDiskFile);
		}
		else
		{
			nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
			if (nDosLinkCreated != 0)
			{
				return nDosLinkCreated;
			}
		}

		dev = CreateFile (szCFDevice, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	}
	else
	{
		write = (diskio_f) win9x_io;
		read = (diskio_f) win9x_io;

		if (OpenDevice (lpszVolume, &driver) == FALSE)
		{
			return ERR_OS_ERROR;
		}
		else if (driver.secstart == driver.seclast)
		{
			return ERR_ACCESS_DENIED;
		}

		win9x_r0.devicenum = driver.device;
		win9x_r0.sectorstart = driver.secstart;

		dev = &win9x_r0;
	}

	if (dev == INVALID_HANDLE_VALUE)
	{
		return ERR_OS_ERROR;
	}


	WaitCursor ();

	win9x_r0.mode = 0;

	/* Read in volume */
	nStatus = (*read) ((HFILE) dev, buffer, sizeof (buffer));
	if (nStatus != sizeof (buffer))
	{
		nStatus = ERR_VOL_SIZE_WRONG;
		goto error;
	}

	memcpy (boot, buffer, SECTOR_SIZE);

	/* Parse header */
	nStatus = VolumeReadHeader (buffer, &nVolType, lpszOldPassword, &cryptoInfo);
	if (nStatus != 0)
	{
		cryptoInfo = NULL;
		goto error;
	}

	if (nVolType == E4M_OLD_VOLTYPE)
	{
		nStatus = ERR_PASSWORD_CHANGE_VOL_VERSION;
	}
	else if (nVolType != E4M_VOLTYPE2)
	{
		nStatus = ERR_PASSWORD_CHANGE_VOL_TYPE;
	}
	else
	{
		/* Change password now */

		char dk[256];
		unsigned short x;
		char encrKey[E4M_DISKKEY_SIZE + sizeof (short)];
		char *tmp;
		int i, j;

		if (dev != &win9x_r0)
		{
			nStatus = _llseek ((HFILE) dev, 0, FILE_BEGIN);

			if (nStatus != 0)
			{
				nStatus = ERR_VOL_SEEKING;
				goto error;
			}
		}

		win9x_r0.mode = 1;
		win9x_r0.sectorstart -= 1;

		/* use pkcs5 to derive the key */
		if (cryptoInfo->pkcs5 == 0)
			derive_sha_key (lpszPassword, strlen (lpszPassword), cryptoInfo->key_salt,
				     20, cryptoInfo->noIterations, dk, 256);
		else
			derive_md5_key (lpszPassword, strlen (lpszPassword), cryptoInfo->key_salt,
				     20, cryptoInfo->noIterations, dk, 256);

		/* Init with derived user key and encrypt master disk key */
		init_cipher (cryptoInfo->cipher, dk, cryptoInfo->ks);

		memcpy (encrKey, cryptoInfo->master_decrypted_key, E4M_DISKKEY_SIZE);

		j = get_block_size (cryptoInfo->cipher);
		for (i = 0; i < E4M_DISKKEY_SIZE; i += j)
		{
			tmp = &encrKey[i];
			encipher_block (cryptoInfo->cipher, tmp, cryptoInfo->ks);
		}

		/* Extract out a key check word */
		x = *(unsigned short *) &dk[254];
		tmp = &encrKey[E4M_DISKKEY_SIZE];
		mputWord (tmp, x);

		memcpy (boot + cryptoInfo->master_key_offset, encrKey, sizeof (encrKey));

		/* Write out new encrypted key + key check */
		nStatus = (*write) ((HFILE) dev, boot, SECTOR_SIZE);

		burn (dk, sizeof (dk));
		burn (encrKey, sizeof (encrKey));

		if (nStatus != SECTOR_SIZE)
		{
			nStatus = ERR_VOL_WRITING;
			goto error;
		}

		/* That's it done... */
		nStatus = 0;
	}

      error:

	burn (buffer, sizeof (buffer));

	if (cryptoInfo != NULL)
		crypto_close (cryptoInfo);

	dwError = GetLastError ();

	if (dev != &win9x_r0)
	{
		CloseHandle ((HANDLE) dev);

		if (bDevice == TRUE && nDosLinkCreated != 0)
		{
			int x = RemoveFakeDosName (szDiskFile, szDosDevice);
			if (x != 0)
			{
				dwError = GetLastError ();
				nStatus = x;
			}
		}
	}

	SetLastError (dwError);

	NormalCursor ();

	return nStatus;
}
