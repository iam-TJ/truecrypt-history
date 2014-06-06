/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#define MAX_PASSWORD 

#include "apidrvr.h"
#include "dlgcode.h"
#include "dismount.h"
#include "../common/resource.h"

#include "resource.h"

#include "dir.h"
#include "setup.h"

#include <sys\types.h>
#include <sys\stat.h>

#pragma warning( disable : 4201 )
#pragma warning( disable : 4115 )

#include <shlobj.h>

#pragma warning( default : 4201 )
#pragma warning( default : 4115 )

char dlg_file_name[E4M_MAX_PATH];
BOOL bUninstall = FALSE;
BOOL bDone = FALSE;

BOOL
StatDeleteFile (char *lpszFile)
{
	struct stat st;


	if (stat (lpszFile, &st) == 0)
		return DeleteFile (lpszFile);
	else
		return TRUE;
}

BOOL
StatRemoveDirectory (char *lpszDir)
{
	struct stat st;

	if (stat (lpszDir, &st) == 0)
		return RemoveDirectory (lpszDir);
	else
		return TRUE;
}

HRESULT
CreateLink (char *lpszPathObj, char *lpszArguments,
	    char *lpszPathLink)
{
	HRESULT hres;
	IShellLink *psl;

	/* Get a pointer to the IShellLink interface.  */
	hres = CoCreateInstance (&CLSID_ShellLink, NULL,
			       CLSCTX_INPROC_SERVER, &IID_IShellLink, &psl);
	if (SUCCEEDED (hres))
	{
		IPersistFile *ppf;

		/* Set the path to the shortcut target, and add the
		   description.  */
		psl->lpVtbl->SetPath (psl, lpszPathObj);
		psl->lpVtbl->SetArguments (psl, lpszArguments);

		/* Query IShellLink for the IPersistFile interface for saving
		   the shortcut in persistent storage.  */
		hres = psl->lpVtbl->QueryInterface (psl, &IID_IPersistFile,
						    &ppf);

		if (SUCCEEDED (hres))
		{
			WORD wsz[E4M_MAX_PATH];

			/* Ensure that the string is ANSI.  */
			MultiByteToWideChar (CP_ACP, 0, lpszPathLink, -1,
					     wsz, E4M_MAX_PATH);

			/* Save the link by calling IPersistFile::Save.  */
			hres = ppf->lpVtbl->Save (ppf, wsz, TRUE);
			ppf->lpVtbl->Release (ppf);
		}
		psl->lpVtbl->Release (psl);
	}
	return hres;
}

void
GetProgramPath (HWND hwndDlg, char *path)
{
	ITEMIDLIST *i;
	HRESULT res;
	res = SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAMS, &i);
	SHGetPathFromIDList (i, path);
}


void
StatusMessage (HWND hwndDlg, char *head, char *txt)
{
	char szTmp[E4M_MAX_PATH];
	sprintf (szTmp, head, txt);
	SendMessage (GetDlgItem (hwndDlg, IDC_FILES), LB_ADDSTRING, 0, (LPARAM) szTmp);
}

void
RegMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Add Reg %s", txt);
}

void
CopyMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Copying %s", txt);
}

void
RemoveMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Removing %s", txt);
}

void
ServiceMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Service %s", txt);
}

void
IconMessage (HWND hwndDlg, char *txt)
{
	StatusMessage (hwndDlg, "Add Icon %s", txt);
}

int CALLBACK
BrowseCallbackProc(HWND hwnd,UINT uMsg,LPARAM lp, LPARAM pData) 
{
	switch(uMsg) {
	case BFFM_INITIALIZED: 
	{
	  /* WParam is TRUE since we are passing a path.
	   It would be FALSE if we were passing a pidl. */
	   SendMessage(hwnd,BFFM_SETSELECTION,TRUE,(LPARAM)pData);
	   break;
	}

	case BFFM_SELCHANGED: 
	{
		char szDir[E4M_MAX_PATH];

	   /* Set the status window to the currently selected path. */
	   if (SHGetPathFromIDList((LPITEMIDLIST) lp ,szDir)) 
	   {
		  SendMessage(hwnd,BFFM_SETSTATUSTEXT,0,(LPARAM)szDir);
	   }
	   break;
	}

	default:
	   break;
	}

	return 0;
}

BOOL
BrowseFiles2 (HWND hwndDlg, char* lpszTitle, char* lpszFileName)
{
	BROWSEINFO bi;
	LPITEMIDLIST pidl;
	LPMALLOC pMalloc;
	BOOL bOK  = FALSE;

	if (SUCCEEDED(SHGetMalloc(&pMalloc))) 
	{
		ZeroMemory(&bi,sizeof(bi));
		bi.hwndOwner = hwndDlg;
		bi.pszDisplayName = 0;
		bi.lpszTitle = lpszTitle;
		bi.pidlRoot = 0;
		bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_STATUSTEXT /*| BIF_EDITBOX*/;
		bi.lpfn = BrowseCallbackProc;
		bi.lParam = (LPARAM)lpszFileName;

		pidl = SHBrowseForFolder(&bi);
		if (pidl!=NULL) 
		{
			if (SHGetPathFromIDList(pidl,lpszFileName)==TRUE) 
			{
				bOK = TRUE;
			}

			pMalloc->lpVtbl->Free(pMalloc,pidl);
			pMalloc->lpVtbl->Release(pMalloc);
		}
	}

	return bOK;
}


void
LoadLicense (HWND hwndDlg)
{
	FILE *fp;

	fp = fopen ("license.txt", "rb");

	if (fp == NULL)
		return;
	else
	{
		long x;

		fseek (fp, 0, SEEK_END);
		x = ftell (fp);
		rewind (fp);

		if (x > 0)
		{
			char *tmp = malloc (x + 1);
			long z;

			if (tmp == NULL)
				goto exit;
			z = (long) fread (tmp, 1, x, fp);
			if (z != x)
			{
				free (tmp);
				goto exit;
			}
			else
			{
				tmp[x] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_LICENSE), tmp);
				free (tmp);
			}
		}
	}

      exit:
	fclose (fp);
}

BOOL
DoFilesInstall (HWND hwndDlg, char *szDestDir, BOOL bUninstallSupport)
{
	char *szFiles[]=
	{
	  "Avolmount.exe", "Avolformat.exe", "Avoltest.exe", "Alicense.txt",
	      "Amanual.hlp", "We4msetup.exe", "Se4mserv.exe", "De4mnt4.sys",
		"Ie4m9x.vxd", "We4m.ini", "Amanual.gid"
	};
	char szTmp[E4M_MAX_PATH];
	BOOL bOK = TRUE;
	int i;

	if (bUninstall == TRUE)
		bUninstallSupport = FALSE;

	for (i = 0; i < sizeof (szFiles) / sizeof (szFiles[0]); i++)
	{
		BOOL bResult, bSlash;
		char szDir[E4M_MAX_PATH];
		int x;

		if (bUninstallSupport == FALSE && memcmp (szFiles[i] + 1, "e4msetup", 8) == 0)
			continue;

		if (bUninstall == FALSE && memcmp (szFiles[i] + 1, "manual.gid", 10) == 0)
			continue;

		if (bUninstall == FALSE && memcmp (szFiles[i] + 1, "e4m.ini", 7) == 0)
			continue;

		if (*szFiles[i] == 'A')
			strcpy (szDir, szDestDir);
		else if (*szFiles[i] == 'S')
			GetSystemDirectory (szDir, sizeof (szDir));
		else if (*szFiles[i] == 'I')
		{
			GetSystemDirectory (szDir, sizeof (szDir));

			x = strlen (szDestDir);
			if (szDestDir[x - 1] == '\\')
				bSlash = TRUE;
			else
				bSlash = FALSE;

			if (bSlash == FALSE)
				strcat (szDir, "\\");

			strcat (szDir, "IOSUBSYS");
		}
		else if (*szFiles[i] == 'D')
		{
			GetSystemDirectory (szDir, sizeof (szDir));

			x = strlen (szDestDir);
			if (szDestDir[x - 1] == '\\')
				bSlash = TRUE;
			else
				bSlash = FALSE;

			if (bSlash == FALSE)
				strcat (szDir, "\\");

			strcat (szDir, "Drivers");
		}
		else if (*szFiles[i] == 'W')
			GetWindowsDirectory (szDir, sizeof (szDir));

		x = strlen (szDestDir);
		if (szDestDir[x - 1] == '\\')
			bSlash = TRUE;
		else
			bSlash = FALSE;

		if (bSlash == FALSE)
			strcat (szDir, "\\");

		if ((*szFiles[i] == 'D' || *szFiles[i] == 'S') && nCurrentOS != WIN_NT)
			continue;

		if (*szFiles[i] == 'I' && nCurrentOS == WIN_NT)
			continue;

		sprintf (szTmp, "%s%s", szDir, szFiles[i] + 1);

		if (bUninstall == FALSE)
			CopyMessage (hwndDlg, szTmp);
		else
			RemoveMessage (hwndDlg, szTmp);

		if (bUninstall == FALSE)
			bResult = CopyFile (szFiles[i] + 1, szTmp, FALSE);
		else
		{
			bResult = StatDeleteFile (szTmp);
		}

		if (bResult == FALSE)
		{
			LPVOID lpMsgBuf;
			DWORD dwError = GetLastError ();
			char szTmp2[700];

			FormatMessage (
					      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
					      NULL,
					      dwError,
				 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
					      (char *) &lpMsgBuf,
					      0,
					      NULL
				);


			if (bUninstall == FALSE)
				sprintf (szTmp2, "The installation of '%s' has failed. %s Do you want to continue with the Install?",
					 szTmp, lpMsgBuf);
			else
				sprintf (szTmp2, "The uninstallation of '%s' has failed. %s Do you want to continue with the Uninstall?",
					 szTmp, lpMsgBuf);

			LocalFree (lpMsgBuf);

			if (MessageBox (hwndDlg, szTmp2, lpszTitle, MB_YESNO | MB_ICONHAND) != IDYES)
				return FALSE;
		}

	}

	return bOK;
}

BOOL
DoRegInstall (HWND hwndDlg, char *szDestDir, BOOL bInstallType, BOOL bUninstallSupport)
{
	char szDir[E4M_MAX_PATH], *key;
	HKEY hkey = 0;
	BOOL bSlash, bOK = FALSE;
	DWORD dw;
	int x;

	strcpy (szDir, szDestDir);
	x = strlen (szDestDir);
	if (szDestDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szDir, "\\");

	if (nCurrentOS == WIN_NT)
	{
		/* 9/9/99 FIX This code should no longer be needed as we use
		   the "services" api to install the driver now, rather than
		   setting the registry by hand */

		/* Install device driver */
		key = "SYSTEM\\CurrentControlSet\\Services\\e4mnt4";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		dw = 1;
		if (RegSetValueEx (hkey, "Type", 0, REG_DWORD, (BYTE *) & dw, 4) != ERROR_SUCCESS)
			goto error;

		dw = 1;
		if (RegSetValueEx (hkey, "Start", 0, REG_DWORD, (BYTE *) & dw, 4) != ERROR_SUCCESS)
			goto error;

		dw = 1;
		if (RegSetValueEx (hkey, "ErrorControl", 0, REG_DWORD, (BYTE *) & dw, 4) != ERROR_SUCCESS)
			goto error;

		if (RegSetValueEx (hkey, "Group", 0, REG_SZ, (BYTE *) "Primary disk", 13) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;
	}

	if (bInstallType == TRUE)
	{
		char szTmp[E4M_MAX_PATH];

		key = "SOFTWARE\\Classes\\e4m_volume\\DefaultIcon";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		sprintf (szTmp, "%svolmount.exe", szDir);
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = "SOFTWARE\\Classes\\e4m_volume\\Shell\\open\\command";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		sprintf (szTmp, "%svolmount.exe /e /b /v %c1", szDir, '%');
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = "SOFTWARE\\Classes\\.vol";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		strcpy (szTmp, "e4m_volume");
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;
	}


	if (bUninstallSupport == TRUE)
	{
		char szTmp[E4M_MAX_PATH];

		key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\E4M";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		GetWindowsDirectory (szDir, sizeof (szDir));

		x = strlen (szDir);
		if (szDir[x - 1] == '\\')
			bSlash = TRUE;
		else
			bSlash = FALSE;

		if (bSlash == FALSE)
			strcat (szDir, "\\");

		sprintf (szTmp, "%se4msetup.exe /u", szDir);
		if (RegSetValueEx (hkey, "UninstallString", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		strcpy (szTmp, "E4M");
		if (RegSetValueEx (hkey, "DisplayName", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;
	}

	bOK = TRUE;

      error:
	if (hkey != 0)
		RegCloseKey (hkey);

	if (bOK == FALSE)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "The installation of the registry entries has failed", lpszTitle, MB_ICONHAND);
	}

	return bOK;
}

BOOL
DoRegUninstall (HWND hwndDlg)
{
	BOOL bOK = FALSE;

	if (RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\e4m_volume\\Shell\\open\\command") != ERROR_SUCCESS)
		goto error;

	if (RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\e4m_volume\\Shell\\open") != ERROR_SUCCESS)
		goto error;

	if (RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\e4m_volume\\Shell") != ERROR_SUCCESS)
		goto error;

	if (RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\e4m_volume\\DefaultIcon") != ERROR_SUCCESS)
		goto error;

	if (RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\e4m_volume") != ERROR_SUCCESS)
		goto error;

	if (RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\.vol") != ERROR_SUCCESS)
		goto error;

	if (RegDeleteKey (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\E4M") != ERROR_SUCCESS)
		goto error;

	bOK = TRUE;

      error:

	if (bOK == FALSE && GetLastError ()!= ERROR_NO_TOKEN && GetLastError ()!= ERROR_FILE_NOT_FOUND
	    && GetLastError ()!= ERROR_PATH_NOT_FOUND)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "The uninstallation of the registry entries has failed", lpszTitle, MB_ICONHAND);
	}
	else
		bOK = TRUE;

	return bOK;

}

BOOL
DoServiceUninstall (HWND hwndDlg, char *lpszService)
{
	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;
	SERVICE_STATUS status;
	char szTmp[128];
	int x;

	if (nCurrentOS != WIN_NT)
		return TRUE;
	else
		memset (&status, 0, sizeof (status));	/* Keep VC6 quiet */

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, lpszService, SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	sprintf (szTmp, "stopping %s", lpszService);
	ServiceMessage (hwndDlg, szTmp);

#define WAIT_PERIOD 3

	for (x = 0; x < WAIT_PERIOD; x++)
	{
		bRet = QueryServiceStatus (hService, &status);
		if (bRet != TRUE)
			goto error;

		if (status.dwCurrentState != SERVICE_START_PENDING &&
		    status.dwCurrentState != SERVICE_STOP_PENDING &&
		    status.dwCurrentState != SERVICE_CONTINUE_PENDING)
			break;

		Sleep (1000);
	}

	if (status.dwCurrentState != SERVICE_STOPPED)
	{
		bRet = ControlService (hService, SERVICE_CONTROL_STOP, &status);
		if (bRet == FALSE)
			goto try_delete;

		for (x = 0; x < WAIT_PERIOD; x++)
		{
			bRet = QueryServiceStatus (hService, &status);
			if (bRet != TRUE)
				goto error;

			if (status.dwCurrentState != SERVICE_START_PENDING &&
			    status.dwCurrentState != SERVICE_STOP_PENDING &&
			  status.dwCurrentState != SERVICE_CONTINUE_PENDING)
				break;

			Sleep (1000);
		}

		if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING)
			goto error;
	}

      try_delete:
	sprintf (szTmp, "deleting %s", lpszService);
	ServiceMessage (hwndDlg, szTmp);

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, lpszService, SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	bRet = DeleteService (hService);
	if (bRet == FALSE)
		goto error;

	bOK = TRUE;

      error:
	if (bOK == FALSE && GetLastError ()!= ERROR_SERVICE_DOES_NOT_EXIST)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "The uninstallation of the device driver has failed", lpszTitle, MB_ICONHAND);
	}
	else
		bOK = TRUE;

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	return bOK;
}

BOOL
DoDriverUnload (HWND hwndDlg)
{
	BOOL bOK = TRUE;
	int status;

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR && GetLastError ()!= ERROR_FILE_NOT_FOUND)
		{
			handleWin32Error (hwndDlg);
			AbortProcess (IDS_NODRIVER);
		}

		if (status != ERR_OS_ERROR)
		{
			handleError (NULL, status);
			AbortProcess (IDS_NODRIVER);
		}
	}

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DWORD dwError;
		int x;


		if (nCurrentOS == WIN_NT)
		{
			ServiceMessage (hwndDlg, "unmounting any drives");

			if (UnmountAllVolumes (hwndDlg, &dwError, &x) == FALSE)
			{
				bOK = FALSE;
				MessageBox (hwndDlg, "Volumes are still mounted; all volumes must be unmounted before uninstallation can continue", lpszTitle, MB_ICONHAND);
			}
		}
		else
		{

			MOUNT_LIST_STRUCT driver;
			DWORD dwResult;
			BOOL bResult;

			bResult = DeviceIoControl (hDriver, MOUNT_LIST, &driver, sizeof (driver), &driver,
					  sizeof (driver), &dwResult, NULL);

			if (bResult == TRUE)
			{
				if (driver.ulMountedDrives != 0)
				{
					bOK = FALSE;
					MessageBox (hwndDlg, "Volumes are still mounted; all volumes must be unmounted before uninstallation can continue", lpszTitle, MB_ICONHAND);
				}
			}
			else
			{
				bOK = FALSE;
				handleWin32Error (hwndDlg);
			}
		}

		CloseHandle (hDriver);
		hDriver = INVALID_HANDLE_VALUE;

	}

	return bOK;
}

BOOL
DoServiceInstall (HWND hwndDlg)
{
	BOOL bOK = FALSE;

	ServiceMessage (hwndDlg, "installing e4mservice");
	ServiceMessage (hwndDlg, "starting e4mservice");

	if (CheckService ()== FALSE)
		goto error;

	bOK = TRUE;

      error:
	if (bOK == FALSE)
	{
		MessageBox ((HWND) hwndDlg, "The installation of the service has failed", lpszTitle, MB_ICONHAND);
	}

	return bOK;
}

BOOL
DoDriverInstall (HWND hwndDlg)
{
	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet, bSlash;
	char szDir[E4M_MAX_PATH];
	int x;

	if (nCurrentOS != WIN_NT)
		return TRUE;

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	GetSystemDirectory (szDir, sizeof (szDir));

	x = strlen (szDir);
	if (szDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szDir, "\\");

	strcat (szDir, "Drivers\\e4mnt4.sys");

	ServiceMessage (hwndDlg, "installing e4mnt4");

	hService = CreateService (hManager, "e4mnt4", "e4mnt4",
				  SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
				  szDir, NULL, NULL, NULL, NULL, NULL
		);
	if (hService == NULL)
		goto error;
	else
		CloseServiceHandle (hService);

	hService = OpenService (hManager, "e4mnt4", SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	ServiceMessage (hwndDlg, "starting e4mnt4");

	bRet = StartService (hService, 0, NULL);
	if (bRet == FALSE)
		goto error;

	bOK = TRUE;

      error:
	if (bOK == FALSE && GetLastError ()!= ERROR_SERVICE_ALREADY_RUNNING)
	{
		handleWin32Error (hwndDlg);
		MessageBox (hwndDlg, "The installation of the device driver has failed", lpszTitle, MB_ICONHAND);
	}
	else
		bOK = TRUE;

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	return bOK;
}

BOOL
DoShortcutsInstall (HWND hwndDlg, char *szDestDir, BOOL bProgGroup)
{
	char szLinkDir[E4M_MAX_PATH], szDir[E4M_MAX_PATH];
	char szTmp[E4M_MAX_PATH], szTmp2[E4M_MAX_PATH];
	BOOL bSlash, bOK = FALSE;
	HRESULT hOle;
	int x;

	if (bUninstall == FALSE && bProgGroup == FALSE)
		return TRUE;

	hOle = OleInitialize (NULL);

	GetProgramPath (hwndDlg, szLinkDir);

	x = strlen (szLinkDir);
	if (szLinkDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szLinkDir, "\\");

	strcat (szLinkDir, "E4M");

	if (mkfulldir (szLinkDir, TRUE) != 0)
	{
		char szTmp[E4M_MAX_PATH];
		int x;

		if (bUninstall == TRUE)
		{
			bOK = TRUE;
			goto error;
		}

		sprintf (szTmp, "The program folder '%s' does not exist. Do you want to create this folder?", szLinkDir);
		x = MessageBox (hwndDlg, szTmp, lpszTitle, MB_ICONHAND | MB_YESNO);
		if (x == IDNO)
		{
			goto error;
		}

		if (mkfulldir (szLinkDir, FALSE) != 0)
		{
			handleWin32Error (hwndDlg);
			sprintf (szTmp, "The folder '%s' could not be created", szLinkDir);
			MessageBox (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
			goto error;
		}
	}

	strcpy (szDir, szDestDir);
	x = strlen (szDestDir);
	if (szDestDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szDir, "\\");

	sprintf (szTmp, "%s%s", szDir, "volmount.exe");
	sprintf (szTmp2, "%s%s", szLinkDir, "\\Mount Volume.lnk");

	if (bUninstall == FALSE)
	{
		IconMessage (hwndDlg, szTmp2);

		if (CreateLink (szTmp, "/e /b", szTmp2) != S_OK)
			goto error;
	}
	else
	{
		RemoveMessage (hwndDlg, szTmp2);

		if (StatDeleteFile (szTmp2) == FALSE)
			goto error;
	}

	sprintf (szTmp, "%s%s", szDir, "volmount.exe");
	sprintf (szTmp2, "%s%s", szLinkDir, "\\Unmount Volume.lnk");

	if (bUninstall == FALSE)
	{
		IconMessage (hwndDlg, szTmp2);

		if (CreateLink (szTmp, "/e /b", szTmp2) != S_OK)
			goto error;
	}
	else
	{
		RemoveMessage (hwndDlg, szTmp2);

		if (StatDeleteFile (szTmp2) == FALSE)
			goto error;
	}

	sprintf (szTmp, "%s%s", szDir, "volformat.exe");
	sprintf (szTmp2, "%s%s", szLinkDir, "\\Create Volume.lnk");

	if (bUninstall == FALSE)
	{
		IconMessage (hwndDlg, szTmp2);

		if (CreateLink (szTmp, "", szTmp2) != S_OK)
			goto error;
	}
	else
	{
		RemoveMessage (hwndDlg, szTmp2);

		if (StatDeleteFile (szTmp2) == FALSE)
			goto error;
	}

	sprintf (szTmp, "%s%s", szDir, "License.txt");
	sprintf (szTmp2, "%s%s", szLinkDir, "\\License.lnk");

	if (bUninstall == FALSE)
	{
		IconMessage (hwndDlg, szTmp2);

		if (CreateLink (szTmp, "", szTmp2) != S_OK)
			goto error;
	}
	else
	{
		RemoveMessage (hwndDlg, szTmp2);

		if (StatDeleteFile (szTmp2) == FALSE)
			goto error;
	}

	sprintf (szTmp, "%s%s", szDir, "Manual.hlp");
	sprintf (szTmp2, "%s%s", szLinkDir, "\\Manual.hlp.lnk");

	if (bUninstall == FALSE)
	{
		IconMessage (hwndDlg, szTmp2);

		if (CreateLink (szTmp, "", szTmp2) != S_OK)
			goto error;
	}
	else
	{
		RemoveMessage (hwndDlg, szTmp2);

		if (StatDeleteFile (szTmp2) == FALSE)
			goto error;
	}

	if (bUninstall == TRUE)
	{
		RemoveMessage ((HWND) hwndDlg, szLinkDir);
		if (StatRemoveDirectory (szLinkDir) == FALSE)
		{
			handleWin32Error ((HWND) hwndDlg);
			goto error;
		}
	}

	bOK = TRUE;

      error:
	OleUninitialize ();

	return bOK;
}


void
RebootPrompt (HWND hwndDlg, BOOL bOK)
{
	if (bOK == TRUE)
	{
		SetWindowText (GetDlgItem ((HWND) hwndDlg, IDOK), "E&xit");

		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDCANCEL), FALSE);

		bDone = TRUE;

		if (nCurrentOS == WIN_NT)
		{
			if (bUninstall == FALSE)
				MessageBox ((HWND) hwndDlg, "The install has been successfull. Under Windows NT there is no need to reboot your machine", lpszTitle, MB_ICONHAND);
			else
				MessageBox ((HWND) hwndDlg, "The uninstall has been successfull. Under Windows NT there is no need to reboot your machine", lpszTitle, MB_ICONHAND);
		}
		else
		{
			int x;

			if (bUninstall == FALSE)
				x = MessageBox ((HWND) hwndDlg, "The install has been successfull, after you close this program you must reboot your machine", lpszTitle, MB_ICONHAND);
			else
				x = MessageBox ((HWND) hwndDlg, "The uninstall has been successfull, after you close this program you must reboot your machine", lpszTitle, MB_ICONHAND);
		}
	}
	else
	{
		if (bUninstall == FALSE)
			MessageBox ((HWND) hwndDlg, "The installation has failed", lpszTitle, MB_ICONHAND);
		else
			MessageBox ((HWND) hwndDlg, "The uninstall has failed", lpszTitle, MB_ICONHAND);
	}
}

void
DoUninstall (void *hwndDlg)
{
	BOOL bOK = TRUE;

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), FALSE);

	WaitCursor ();

	SendMessage (GetDlgItem ((HWND) hwndDlg, IDC_FILES), LB_RESETCONTENT, 0, 0);

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoServiceUninstall (hwndDlg, "e4mservice") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoServiceUninstall (hwndDlg, "e4mnt4") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoFilesInstall ((HWND) hwndDlg, dlg_file_name, FALSE) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoRegUninstall ((HWND) hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoShortcutsInstall (hwndDlg, dlg_file_name, FALSE) == FALSE)
	{
		bOK = FALSE;
	}
	else
	{
		RemoveMessage ((HWND) hwndDlg, dlg_file_name);
		if (StatRemoveDirectory (dlg_file_name) == FALSE)
		{
			handleWin32Error ((HWND) hwndDlg);
			bOK = FALSE;
		}
	}

	NormalCursor ();

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), TRUE);

	RebootPrompt (hwndDlg, bOK);

}

void
DoInstall (void *hwndDlg)
{
	BOOL bOK = TRUE;

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), FALSE);

	WaitCursor ();

	SendMessage (GetDlgItem ((HWND) hwndDlg, IDC_FILES), LB_RESETCONTENT, 0, 0);

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoServiceUninstall (hwndDlg, "e4mservice") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoServiceUninstall (hwndDlg, "e4mnt4") == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoFilesInstall ((HWND) hwndDlg, dlg_file_name, IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL))) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoRegInstall ((HWND) hwndDlg, dlg_file_name,
		IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_FILE_TYPE)),
			       IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL))) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoDriverInstall (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoServiceInstall (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (DoShortcutsInstall (hwndDlg, dlg_file_name,
				     IsButtonChecked (GetDlgItem ((HWND) hwndDlg, IDC_PROG_GROUP))) == FALSE)
	{
		bOK = FALSE;
	}

	NormalCursor ();

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), TRUE);

	RebootPrompt (hwndDlg, bOK);
}

BOOL
IsAdmin (void)
{
	HANDLE hAccessToken;
	UCHAR InfoBuffer[1024];
	PTOKEN_GROUPS ptgGroups = (PTOKEN_GROUPS) InfoBuffer;
	DWORD dwInfoBufferSize;
	PSID psidAdministrators;
	SID_IDENTIFIER_AUTHORITY siaNtAuthority = SECURITY_NT_AUTHORITY;
	BOOL bSuccess;
	UINT x;

	if (!OpenThreadToken (GetCurrentThread (), TOKEN_QUERY, TRUE,
			      &hAccessToken))
	{
		if (GetLastError ()!= ERROR_NO_TOKEN)
			return FALSE;

		/* Retry against process token if no thread token exists */
		if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY,
				       &hAccessToken))
			return FALSE;
	}

	bSuccess = GetTokenInformation (hAccessToken, TokenGroups, InfoBuffer,
					1024, &dwInfoBufferSize);

	CloseHandle (hAccessToken);

	if (!bSuccess)
		return FALSE;

	if (!AllocateAndInitializeSid (&siaNtAuthority, 2,
				       SECURITY_BUILTIN_DOMAIN_RID,
				       DOMAIN_ALIAS_RID_ADMINS,
				       0, 0, 0, 0, 0, 0,
				       &psidAdministrators))
		return FALSE;

	/* Assume that we don't find the admin SID. */
	bSuccess = FALSE;

	for (x = 0; x < ptgGroups->GroupCount; x++)
	{
		if (EqualSid (psidAdministrators, ptgGroups->Groups[x].Sid))
		{
			bSuccess = TRUE;
			break;
		}

	}

	FreeSid (psidAdministrators);
	return bSuccess;
}

BOOL WINAPI
InstallDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	if (lParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		SetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), "C:\\Program Files\\E4M");

		if (bUninstall == FALSE)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_FILES), LB_ADDSTRING, 0, (LPARAM) "By clicking 'Install', you accept"
				     " the license.");

			LoadLicense (hwndDlg);
		}

		SendMessage (GetDlgItem (hwndDlg, IDC_FILE_TYPE), BM_SETCHECK, BST_CHECKED, 0);
		SendMessage (GetDlgItem (hwndDlg, IDC_UNINSTALL), BM_SETCHECK, BST_CHECKED, 0);
		SendMessage (GetDlgItem (hwndDlg, IDC_PROG_GROUP), BM_SETCHECK, BST_CHECKED, 0);

		SetWindowText (hwndDlg, lpszTitle);

		InitDialog (hwndDlg);

		return 1;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBox (hInst, MAKEINTRESOURCE (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDOK)
		{
			char szDirname[E4M_MAX_PATH];

			if (bDone == TRUE)
			{
				EndDialog (hwndDlg, IDOK);
				return 1;
			}

			GetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), szDirname, sizeof (szDirname));

			if (bUninstall == FALSE)
			{
				if (mkfulldir (szDirname, TRUE) != 0)
				{
					char szTmp[E4M_MAX_PATH];
					int x;

					sprintf (szTmp, "The directory '%s' does not exist. Do you want to create this directory?", szDirname);
					x = MessageBox (hwndDlg, szTmp, lpszTitle, MB_ICONHAND | MB_YESNO);
					if (x == IDNO)
					{
						SetFocus (GetDlgItem (hwndDlg, IDC_DESTINATION));
						return 1;
					}

					if (mkfulldir (szDirname, FALSE) != 0)
					{
						handleWin32Error (hwndDlg);
						sprintf (szTmp, "The directory '%s' could not be created", szDirname);
						MessageBox (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
						return 1;
					}

				}
			}

			strcpy (dlg_file_name, szDirname);

			if (bUninstall == FALSE)
				_beginthread (DoInstall, 16384, (void *) hwndDlg);
			else
				_beginthread (DoUninstall, 16384, (void *) hwndDlg);

			return 1;
		}

		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}

		if (lw == IDC_BROWSE)
		{
			char szDirname[E4M_MAX_PATH];

			GetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), szDirname, sizeof (szDirname));

			if (BrowseFiles2 (hwndDlg, "Please select a folder", szDirname) == TRUE)
				SetWindowText (GetDlgItem (hwndDlg, IDC_DESTINATION), szDirname);
			
			return 1;
		}

		if (lw == IDC_DESTINATION && HIWORD (wParam) == EN_CHANGE && bDone == FALSE)
		{
			if (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_DESTINATION)) <= 0)
				EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);
			else
				EnableWindow (GetDlgItem (hwndDlg, IDOK), TRUE);
			return 1;
		}

		return 0;

	case WM_CLOSE:
		EndDialog (hwndDlg, IDCANCEL);
		return 1;
	}

	return 0;
}


int WINAPI
WINMAIN (HINSTANCE hInstance, HINSTANCE hPrevInstance, char *lpszCommandLine,
	 int nCmdShow)
{
	if (nCmdShow && hPrevInstance);	/* Remove unused parameter warning */

	lpszTitle = "Setup E4M";

	/* Call InitApp to initialize the common code */
	InitApp (hInstance);

	if (nCurrentOS == WIN_NT && IsAdmin ()!= TRUE)
		if (MessageBox (NULL, "To successfully install/uninstall E4M under Windows NT you must be running as an Administrator, "
				"do you still want to continue?", lpszTitle, MB_YESNO | MB_ICONHAND) != IDYES)
			return 0;

	if (lpszCommandLine[0] == '/' && (lpszCommandLine[1] == 'u' || lpszCommandLine[1] == 'U'))
	{
		bUninstall = TRUE;
	}

	if (bUninstall == FALSE)
	{
		/* Create the main dialog box */
		DialogBox (hInstance, MAKEINTRESOURCE (IDD_INSTALL), NULL, (DLGPROC) InstallDlgProc);
	}
	else
	{
		/* Create the main dialog box */
		DialogBox (hInstance, MAKEINTRESOURCE (IDD_UNINSTALL), NULL, (DLGPROC) InstallDlgProc);
	}

	/* Terminate */
	return 0;
}
