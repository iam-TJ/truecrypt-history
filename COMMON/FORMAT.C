/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "volumes1.h"
#include "progress.h"
#include "apidrvr.h"
#include "dlgcode.h"

int
FormatVolume (char *lpszFilename,
	      BOOL bDevice,
	      long size,
	      int nVolType,
	      char *lpszPassword,
	      int cipher,
	      int pkcs5,
	      fatparams * ft,
	      HWND hwndDlg)
{
	int i, j = 0, nStatus;
	PCRYPTO_INFO cryptoInfo;
	void *dev = INVALID_HANDLE_VALUE;
	OPEN_TEST_STRUCT driver;
	DISKIO_STRUCT win9x_r0;
	DWORD dwError;
	diskio_f write;

	if (nCurrentOS == WIN_NT || bDevice == FALSE)
	{
		write = (diskio_f) _lwrite;

		if (bDevice == TRUE)
		{
			dev = CreateFile (lpszFilename, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		}
		else
		{
			/* We could support FILE_ATTRIBUTE_HIDDEN as an
			   option! */
			dev = CreateFile (lpszFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		}

		if (dev == INVALID_HANDLE_VALUE)
		{
			return ERR_OS_ERROR;
		}
	}
	else
	{
		write = (diskio_f) win9x_io;

		if (OpenDevice (lpszFilename, &driver) == FALSE)
		{
			return ERR_OS_ERROR;
		}

		win9x_r0.devicenum = driver.device;
		win9x_r0.sectorstart = driver.secstart;
		win9x_r0.mode = 1;

		dev = &win9x_r0;
	}


	if (nVolType != SFS_VOLTYPE)
		size -= SECTOR_SIZE;

	ft->num_sectors = size / SECTOR_SIZE;
	memcpy (ft->volume_name, "           ", 11);

	for (i = 1; i < 128; i <<= 1)
	{
		j = ft->num_sectors / i;
		if (j <= 65535)
			break;

	}

	InitProgressBar (j);

	/* Calculate the fats, root dir etc, and update ft */
	GetFatParams (ft);

	/* Copies any header structures into ft->header, but does not do any
	   disk io */
	nStatus = VolumeWriteHeader (ft,
				     ft->header,
				     nVolType,
				     cipher,
				     lpszPassword,
				     pkcs5,
				     &cryptoInfo);

	if (nStatus != 0)
		return nStatus;

	KillTimer (hwndDlg, 0xff);

	/* This does the disk io, both copying out the header, init the
	   sectors, and writing the FAT tables etc */
	nStatus = Format (ft, (HFILE) dev, nVolType, cryptoInfo, i, write);

	dwError = GetLastError();

	crypto_close (cryptoInfo);

	if (dev != &win9x_r0)
		CloseHandle (dev);

	if (nStatus!=0)
		SetLastError(dwError);
	
	return nStatus;

}
