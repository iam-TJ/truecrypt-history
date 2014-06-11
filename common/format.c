#include "e4mdefs.h"

#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "volumes1.h"

extern void InitProgressBar (int nRange);

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
  HANDLE dev;

  if (bDevice == TRUE)
    {
      dev = CreateFile (lpszFilename, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }
  else
    {
      /* We could support FILE_ATTRIBUTE_HIDDEN as an option! */
      dev = CreateFile (lpszFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    }

  if (dev == INVALID_HANDLE_VALUE)
    {
      return ERR_OS_ERROR;
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

  GetFatParams (ft);

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

  nStatus = Format (ft, (HFILE) dev, nVolType, cryptoInfo, i);

  crypto_close (cryptoInfo);
  CloseHandle (dev);

  return nStatus;

}
