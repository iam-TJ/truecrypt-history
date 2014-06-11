#include "e4mdefs.h"
#include "crypto.h"
#include "ntioctl.h"

#include "dismount.h"

extern HANDLE hNTDriver;

#ifdef NTSERVICE
extern void handleWin32Error (HWND dummy);
#endif

void
UnmountAllVolumes (HWND hwndDlg, DWORD * os_error, int *err)
{
  E4M_NT_MOUNT_LIST driver;
  DWORD dwResult;
  BOOL bResult;
  int i;

  *os_error = 0;
  *err = 0;

  bResult = DeviceIoControl (hNTDriver, E4M_MOUNT_LIST, &driver, sizeof (driver), &driver,
			     sizeof (driver), &dwResult, NULL);

  if (bResult == FALSE || dwResult != sizeof (driver))
    {
      *os_error = GetLastError ();
      *err = ERR_OS_ERROR;
      return;
    }

  for (i = 0; i < 26; i++)
    {
      if ((driver.ulMountedDrives & 1 << i))
	{
	  UnmountVolume (hwndDlg, i, os_error, err);
	  if (*err != 0 && *err == ERR_OS_ERROR)
	    handleWin32Error (hwndDlg);
	}
    }
}

BOOL
UnmountVolume (HWND hwndDlg, int nDosDriveNo, DWORD * os_error, int *err)
{
  E4M_NT_UNMOUNT e4mUnmount;
  char volMountName[32];
  char dosName[3];
  DWORD dwResult;
  BOOL bResult;

  *os_error = 0;
  *err = 0;

  e4mUnmount.nDosDriveNo = nDosDriveNo;

  dosName[0] = (char) (e4mUnmount.nDosDriveNo + 'A');
  dosName[1] = ':';
  dosName[2] = 0;

  sprintf (volMountName, "\\\\.\\%s", dosName);

  if (DismountVolume (hwndDlg, volMountName, os_error, err) == FALSE)
    return FALSE;

  bResult = DeviceIoControl (hNTDriver, E4M_UNMOUNT, &e4mUnmount,
    sizeof (e4mUnmount), &e4mUnmount, sizeof (e4mUnmount), &dwResult, NULL);

  if (bResult == FALSE)
    {
      *os_error = GetLastError ();
      *err = ERR_OS_ERROR;
      return FALSE;
    }

  if (e4mUnmount.nReturnCode == 0)
    {
      bResult = DefineDosDevice (DDD_REMOVE_DEFINITION, dosName, NULL);

      if (bResult == FALSE)
	{
	  *os_error = GetLastError ();
	  *err = ERR_OS_ERROR;
	  return FALSE;
	}
    }
  else
    *err = e4mUnmount.nReturnCode;

  return TRUE;
}

BOOL
DismountVolume (HWND hwndDlg, char *lpszVolMountName, DWORD * os_error, int *err)
{
  HANDLE hVolume = INVALID_HANDLE_VALUE;
  BOOL bRetry = FALSE;
  DWORD dwResult;
  int i;

  *os_error = 0;
  *err = 0;

retry:

#ifdef _DEBUG
  OutputDebugString ("mount: dismount volume ----------------->...\n");
#endif

  for (i = 0; i < 16; i++)
    {
      BOOL bResult;

#ifdef _DEBUG
      OutputDebugString ("mount: trying to open the volume...\n");
#endif
      /* Try to open a handle to the mounted volume */
      hVolume = CreateFile (lpszVolMountName, GENERIC_READ | GENERIC_WRITE,
	  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
      if (hVolume == INVALID_HANDLE_VALUE)
	{
	  *os_error = GetLastError ();
	  *err = ERR_OS_ERROR;
	  return FALSE;
	}

#ifdef _DEBUG
      OutputDebugString ("mount: trying to lock the volume...\n");
#endif
      bResult = DeviceIoControl (hVolume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL);
      if (bResult == FALSE)
	{
	  DWORD dwError = GetLastError ();
	  if (dwError != ERROR_ACCESS_DENIED)
	    {
	      *os_error = GetLastError ();
	      *err = ERR_OS_ERROR;
	      CloseHandle (hVolume);
	      return FALSE;
	    }
	  else
	    {
	      CloseHandle (hVolume);
	      hVolume = INVALID_HANDLE_VALUE;
	    }
	}
      else
	break;
    }

  if (hVolume == INVALID_HANDLE_VALUE)
    {
      if (bRetry == FALSE)
	{
	  bRetry = TRUE;
	  Sleep (1000);
	  goto retry;
	}

      *err = ERR_FILES_OPEN_LOCK;

      return FALSE;
    }

#ifdef _DEBUG
  OutputDebugString ("mount: trying to dismount the volume...\n");
#endif
  DeviceIoControl (hVolume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL);
#ifdef _DEBUG
  OutputDebugString ("mount: trying to unmount the volume...\n");
#endif

  DeviceIoControl (hVolume, E4M_UNMOUNT_PENDING, NULL, 0, NULL, 0, &dwResult, NULL);
  CloseHandle (hVolume);

#ifdef _DEBUG
  OutputDebugString ("<-------------------------------- mount: dismount volume!\n");
#endif

  return TRUE;
}
