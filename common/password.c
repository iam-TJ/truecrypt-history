#include "e4mdefs.h"

#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "volumes1.h"

#include "dlgcode.h"

#include "password.h"

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

  if (hwndDlg);			/* Remove warning */

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
OpenVolume (char *lpszVolume, int *dev, int *nDosLinkCreated)
{
  char szDiskFile[E4M_MAX_PATH], szCFDevice[E4M_MAX_PATH];
  char *lpszFilename = szCFDevice;
  BOOL bDevice;

  *nDosLinkCreated = ERR_OS_ERROR;

  CreateFullVolumePath (szDiskFile, lpszVolume, &bDevice);

  if (bDevice == FALSE)
    {
      strcpy (szCFDevice, szDiskFile);
    }
  else
    {
      char szDosDevice[E4M_MAX_PATH];

      *nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
      if (*nDosLinkCreated != 0)
	{
	  return *nDosLinkCreated;
	}
    }

  if (bDevice == TRUE)
    {
      *dev = (int) CreateFile (lpszFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }
  else
    {
      *dev = (int) CreateFile (lpszFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }


  if (*dev == (int) INVALID_HANDLE_VALUE)
    {
      return ERR_OS_ERROR;
    }

  return 0;
}

int
CloseVolume (char *lpszVolume, int dev, int nDosLinkCreated)
{
  char szDiskFile[E4M_MAX_PATH], szCFDevice[E4M_MAX_PATH];
  char *lpszFilename = szCFDevice;
  BOOL bDevice;

  CloseHandle ((HANDLE) dev);

  CreateFullVolumePath (szDiskFile, lpszVolume, &bDevice);

  if (bDevice == TRUE && nDosLinkCreated != 0)
    {
      char szDosDevice[E4M_MAX_PATH];
      int nStatus;

      FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, TRUE);
      nStatus = RemoveFakeDosName (szDiskFile, szDosDevice);
      return nStatus;
    }

  return 0;
}

int
ChangePwd (char *lpszVolume, char *lpszOldPassword, char *lpszPassword)
{
  int nDosLinkCreated, nStatus, nVolType;
  char buffer[22 * SECTOR_SIZE], boot[SECTOR_SIZE];
  PCRYPTO_INFO cryptoInfo = NULL;
  DWORD dwError;
  int dev;

  nStatus = OpenVolume (lpszVolume, &dev, &nDosLinkCreated);
  if (nStatus != 0)
    return nStatus;

  WaitCursor ();

  /* Read in volume */

  nStatus = _lread (dev, buffer, sizeof (buffer));
  if (nStatus != sizeof (buffer))
    {
      nStatus = ERR_VOLUME_SIZE_WRONG;
      goto error;
    }

  memcpy(boot,buffer, SECTOR_SIZE);

  /* Parse header */

  nStatus = VolumeReadHeader (buffer, &nVolType, lpszOldPassword, &cryptoInfo);
  if (nStatus != 0)
    {
      cryptoInfo = NULL;
      goto error;
    }

  if (nVolType == E4M_OLD_VOLTYPE)
    {
      nStatus = ERR_PASSWORD_CHANGE_VOL_TYPE;
    }
  else if (nVolType != E4M_VOLTYPE2)
    {
      nStatus = ERR_PASSWORD_CHANGE_VOL_VERSION;
    }
  else
    {
      /* Change password now */

      char dk[256];
      unsigned short x;
      char encrKey[E4M_DISKKEY_SIZE + sizeof (short)];
      char *tmp;
      int i, j;

      nStatus = _llseek (dev, 0, FILE_BEGIN);

      if (nStatus != 0)
	{
	  nStatus = ERR_VOL_SEEKING;
	  goto error;
	}

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

      memcpy(boot+cryptoInfo->master_key_offset,encrKey,sizeof (encrKey));

      /* Write out new encrypted key + key check */
      nStatus = _lwrite (dev, boot, SECTOR_SIZE);

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

  CloseVolume (lpszVolume, dev, nDosLinkCreated);

  SetLastError (dwError);

  NormalCursor ();

  return nStatus;
}
