/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#include <stdlib.h>

#include "resource.h"
#include "crypto.h"
#include "apidrvr.h"
#include "dlgcode.h"

char szHelpFile[E4M_MAX_PATH];
HFONT hSmallFont = NULL;
HFONT hBoldFont = NULL;
HFONT hSmallBoldFont = NULL;
HFONT hTitleFont = NULL;
HFONT hFixedFont = NULL;
char *lpszTitle = NULL;
int nCurrentOS = 0;

/* Handle to the device driver */
HANDLE hDriver = INVALID_HANDLE_VALUE;
HINSTANCE hInst = NULL;
HANDLE hMutex = NULL;
HCURSOR hCursor = NULL;

ATOM hDlgClass, hSplashClass;

/* Windows dialog class */
#define WINDOWS_DIALOG_CLASS "#32770"

/* Custom class names */
#define E4M_DLG_CLASS "CustomDlg"
#define E4M_SPLASH_CLASS "SplashDlg"

void
cleanup ()
{
	/* Cleanup the GDI fonts */
	if (hFixedFont != NULL)
		DeleteObject (hFixedFont);
	if (hSmallFont != NULL)
		DeleteObject (hSmallFont);
	if (hBoldFont != NULL)
		DeleteObject (hBoldFont);
	if (hSmallBoldFont != NULL)
		DeleteObject (hSmallBoldFont);
	if (hTitleFont != NULL)
		DeleteObject (hTitleFont);
	/* Cleanup our dialog class */
	if (hDlgClass)
		UnregisterClass (E4M_DLG_CLASS, hInst);
	if (hSplashClass)
		UnregisterClass (E4M_SPLASH_CLASS, hInst);
	/* Close the device driver handle */
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		CloseHandle (hDriver);
	}

	if (hMutex != NULL)
	{
		CloseHandle (hMutex);
	}
}

void
LowerCaseCopy (char *lpszDest, char *lpszSource)
{
	int i = strlen (lpszSource);

	lpszDest[i] = 0;
	while (--i >= 0)
	{
		lpszDest[i] = (char) tolower (lpszSource[i]);
	}

}

void
UpperCaseCopy (char *lpszDest, char *lpszSource)
{
	int i = strlen (lpszSource);

	lpszDest[i] = 0;
	while (--i >= 0)
	{
		lpszDest[i] = (char) toupper (lpszSource[i]);
	}
}

void
CreateFullVolumePath (char *lpszDiskFile, char *lpszFileName, BOOL * bDevice)
{
	if (strcmp (lpszFileName, "Floppy (A:)") == 0)
		strcpy (lpszFileName, "\\Device\\Floppy0");
	else if (strcmp (lpszFileName, "Floppy (B:)") == 0)
		strcpy (lpszFileName, "\\Device\\Floppy1");

	UpperCaseCopy (lpszDiskFile, lpszFileName);

	*bDevice = FALSE;

	if (memcmp (lpszDiskFile, "\\DEVICE", sizeof (char) * 7) == 0)
	{
		strcpy (lpszDiskFile, lpszFileName);
		*bDevice = TRUE;
	}
	else if (strstr (lpszDiskFile, ".") == 0)
	{
		strcpy (lpszDiskFile, lpszFileName);	/* Normal file
							   no-extension */
		strcat (lpszDiskFile, ".vol");
	}
	else
		strcpy (lpszDiskFile, lpszFileName);	/* File with extension */

#if _DEBUG
	OutputDebugString ("CreateFullVolumePath: ");
	OutputDebugString (lpszDiskFile);
	OutputDebugString ("\n");
#endif

}

int
FakeDosNameForDevice (char *lpszDiskFile, char *lpszDosDevice, char *lpszCFDevice, BOOL bNameOnly)
{
	BOOL bDosLinkCreated = TRUE;

	sprintf (lpszDosDevice, "e4mformat%lu", GetCurrentProcessId ());

	if (bNameOnly == FALSE)
		bDosLinkCreated = DefineDosDevice (DDD_RAW_TARGET_PATH, lpszDosDevice, lpszDiskFile);

	if (bDosLinkCreated == FALSE)
	{
		return ERR_OS_ERROR;
	}
	else
		sprintf (lpszCFDevice, "\\\\.\\%s", lpszDosDevice);

	return 0;
}

int
RemoveFakeDosName (char *lpszDiskFile, char *lpszDosDevice)
{
	BOOL bDosLinkRemoved = DefineDosDevice (DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE |
			DDD_REMOVE_DEFINITION, lpszDosDevice, lpszDiskFile);
	if (bDosLinkRemoved == FALSE)
	{
		return ERR_OS_ERROR;
	}

	return 0;
}

char *
getstr (UINT nID)
{
	static char szMsg[256];
	if (LoadString (hInst, nID, szMsg, sizeof (szMsg)) == 0)
		return "";
	else
		return szMsg;
}

char *
getmultilinestr (UINT nID[4])
{
	static char szMsg[1024];
	if (nID[0])
		strcpy (szMsg, getstr (nID[0]));
	if (nID[1])
		strcat (szMsg, getstr (nID[1]));
	if (nID[2])
		strcat (szMsg, getstr (nID[2]));
	if (nID[3])
		strcat (szMsg, getstr (nID[3]));
	return szMsg;

}

void
AbortProcess (UINT nID)
{
	MessageBeep (MB_ICONEXCLAMATION);
	MessageBox (NULL, getstr (nID), lpszTitle, ICON_HAND);
	exit (1);
}

void *
err_malloc (size_t size)
{
	void *z = (void *) e4malloc (size);
	if (z)
		return z;
	AbortProcess (IDS_OUTOFMEMORY);
	return NULL;
}

char *
err_strdup (char *lpszText)
{
	int j = (strlen (lpszText) + 1) * sizeof (char);
	char *z = (char *) err_malloc (j);
	memmove (z, lpszText, j);
	return z;
}

void
handleWin32Error (HWND hwndDlg)
{
	LPVOID lpMsgBuf;
	DWORD dwError = GetLastError ();

	FormatMessage (
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			      NULL,
			      dwError,
			      MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
			      (char *) &lpMsgBuf,
			      0,
			      NULL
	    );

	MessageBox (hwndDlg, lpMsgBuf, lpszTitle, ICON_HAND);
	LocalFree (lpMsgBuf);
}

BOOL
translateWin32Error (char *lpszMsgBuf, int nSizeOfBuf)
{
	DWORD dwError = GetLastError ();

	if (FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwError,
			   MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
			   lpszMsgBuf, nSizeOfBuf, NULL))
		return TRUE;
	else
		return FALSE;
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
AboutDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	if (lParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		return 1;
	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			EndDialog (hwndDlg, 0);
			return 1;
		}
		return 0;
	case WM_CLOSE:
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
WarningDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	if (lParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		SetWindowText (GetDlgItem (hwndDlg, IDC_WARNING_TEXT), (char*) lParam);
		return 1;
	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			BOOL x = IsButtonChecked (GetDlgItem (hwndDlg, IDC_NEVER_SHOW));
			if (x == TRUE)
				EndDialog (hwndDlg, IDOK);
			else
				EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}
		return 0;
	case WM_CLOSE:
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}

BOOL
IsButtonChecked (HWND hButton)
{
	if (SendMessage (hButton, BM_GETCHECK, 0, 0) == BST_CHECKED)
		return TRUE;
	else
		return FALSE;
}

void
CheckButton (HWND hButton)
{
	SendMessage (hButton, BM_SETCHECK, BST_CHECKED, 0);
}


/*****************************************************************************
  ToSBCS: converts a unicode string to Single Byte Character String (SBCS).
  ***************************************************************************/

void
ToSBCS (LPWSTR lpszText)
{
	int j = wcslen (lpszText);
	if (j == 0)
	{
		strcpy ((char *) lpszText, "");
		return;
	}
	else
	{
		char *lpszNewText = (char *) err_malloc (j + 1);
		j = WideCharToMultiByte (CP_ACP, 0L, lpszText, -1, lpszNewText, j + 1, NULL, NULL);
		if (j > 0)
			strcpy ((char *) lpszText, lpszNewText);
		else
			strcpy ((char *) lpszText, "");
		free (lpszNewText);
	}
}

/*****************************************************************************
  ToUNICODE: converts a SBCS string to a UNICODE string.
  ***************************************************************************/

void
ToUNICODE (char *lpszText)
{
	int j = strlen (lpszText);
	if (j == 0)
	{
		wcscpy ((LPWSTR) lpszText, (LPWSTR) WIDE (""));
		return;
	}
	else
	{
		LPWSTR lpszNewText = (LPWSTR) err_malloc ((j + 1) * 2);
		j = MultiByteToWideChar (CP_ACP, 0L, lpszText, -1, lpszNewText, j + 1);
		if (j > 0)
			wcscpy ((LPWSTR) lpszText, lpszNewText);
		else
			wcscpy ((LPWSTR) lpszText, (LPWSTR) "");
		free (lpszNewText);
	}
}

/* InitDialog - initialize the applications main dialog, this function should
   be called only once in the dialogs WM_INITDIALOG message handler */
void
InitDialog (HWND hwndDlg)
{
	HDC hDC;
	int nHeight;
	LOGFONT lf;
	HMENU hMenu;

	hDC = GetDC (hwndDlg);

	nHeight = -((8 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWidth = 0;
	lf.lfEscapement = 0;
	lf.lfOrientation = 0;
	lf.lfWeight = FW_LIGHT;
	lf.lfItalic = FALSE;
	lf.lfUnderline = FALSE;
	lf.lfStrikeOut = FALSE;
	lf.lfCharSet = DEFAULT_CHARSET;
	lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	lf.lfQuality = PROOF_QUALITY;
	lf.lfPitchAndFamily = FF_DONTCARE;
	strcpy (lf.lfFaceName, "Courier");
	hSmallFont = CreateFontIndirect (&lf);
	if (hSmallFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	nHeight = -((10 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_BLACK;
	strcpy (lf.lfFaceName, "Arial");
	hSmallBoldFont = CreateFontIndirect (&lf);
	if (hSmallBoldFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	nHeight = -((16 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_ULTRALIGHT;
	strcpy (lf.lfFaceName, "Impact");
	hBoldFont = CreateFontIndirect (&lf);
	if (hBoldFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	nHeight = -((16 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_REGULAR;
	hTitleFont = CreateFontIndirect (&lf);
	if (hTitleFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	nHeight = -((10 * GetDeviceCaps (hDC, LOGPIXELSY)) / 72);
	lf.lfHeight = nHeight;
	lf.lfWidth = 0;
	lf.lfEscapement = 0;
	lf.lfOrientation = 0;
	lf.lfWeight = FW_NORMAL;
	lf.lfItalic = FALSE;
	lf.lfUnderline = FALSE;
	lf.lfStrikeOut = FALSE;
	lf.lfCharSet = DEFAULT_CHARSET;
	lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	lf.lfQuality = PROOF_QUALITY;
	lf.lfPitchAndFamily = FF_DONTCARE;
	strcpy (lf.lfFaceName, "Courier");
	hFixedFont = CreateFontIndirect (&lf);
	if (hFixedFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess (IDS_NOFONT);
	}

	hMenu = GetSystemMenu (hwndDlg, FALSE);
	AppendMenu (hMenu, MF_SEPARATOR, 0, NULL);
	AppendMenu (hMenu, MF_ENABLED | MF_STRING, IDC_ABOUT, getstr (IDS_ABOUTBOX));
}

HDC
CreateMemBitmap (HINSTANCE hInstance, HWND hwnd, char *resource)
{
	HBITMAP picture = LoadBitmap (hInstance, resource);
	HDC viewDC = GetDC (hwnd), dcMem;

	dcMem = CreateCompatibleDC (viewDC);

	SetMapMode (dcMem, MM_TEXT);

	SelectObject (dcMem, picture);

	ReleaseDC (hwnd, viewDC);

	return dcMem;
}

/* Draw the specified bitmap at the specified location - Stretch to fit. */
void
PaintBitmap (HDC pdcMem, int x, int y, int nWidth, int nHeight, HDC hDC)
{
	HGDIOBJ picture = GetCurrentObject (pdcMem, OBJ_BITMAP);

	BITMAP bitmap;
	GetObject (picture, sizeof (BITMAP), &bitmap);

	BitBlt (hDC, x, y, nWidth, nHeight, pdcMem, 0, 0, SRCCOPY);
}

LRESULT CALLBACK
SplashDlgProc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
#if 0
	static HDC dcMem;
#endif

	if (uMsg == WM_ERASEBKGND)
	{
		HDC hDC = (HDC) wParam;
		char szTmp[64];
		HGDIOBJ obj;
		WORD bx = LOWORD (GetDialogBaseUnits ());
		WORD by = HIWORD (GetDialogBaseUnits ());

#if 0
		RECT rect;
#endif

		DefDlgProc (hwnd, uMsg, wParam, lParam);


#if 0
		if (dcMem == 0)
		{
			dcMem = CreateMemBitmap (GET_INSTANCE (hwnd), hwnd, MAKEINTRESOURCE (IDB_E4M));
		}

		GetClientRect (hwnd, &rect);
		PaintBitmap (dcMem, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, hDC);
#endif

		SetBkMode (hDC, TRANSPARENT);
		SetTextColor (hDC, RGB (255, 0, 0));
		obj = SelectObject (hDC, hSmallFont);

		sprintf (szTmp, "Version %s", VERSION_STRING);
		TextOut (hDC, (65 * bx) / 4, (40 * by) / 8, szTmp, strlen (szTmp));

		strcpy (szTmp, "http://www.e4m.net  paulca@rocketmail.com");
		TextOut (hDC, (15 * bx) / 4, (45 * by) / 8, szTmp, strlen (szTmp));

		SelectObject (hDC, obj);
		return TRUE;
	}

	return DefDlgProc (hwnd, uMsg, wParam, lParam);
}

void
WaitCursor ()
{
	static HCURSOR hcWait;
	if (hcWait == NULL)
		hcWait = LoadCursor (NULL, IDC_WAIT);
	SetCursor (hcWait);
	hCursor = hcWait;
}

void
NormalCursor ()
{
	static HCURSOR hcArrow;
	if (hcArrow == NULL)
		hcArrow = LoadCursor (NULL, IDC_ARROW);
	SetCursor (hcArrow);
	hCursor = NULL;
}

void
ArrowWaitCursor ()
{
	static HCURSOR hcArrowWait;
	if (hcArrowWait == NULL)
		hcArrowWait = LoadCursor (NULL, IDC_APPSTARTING);
	SetCursor (hcArrowWait);
	hCursor = hcArrowWait;
}

LRESULT CALLBACK
CustomDlgProc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_SETCURSOR && hCursor != NULL)
	{
		SetCursor (hCursor);
		return TRUE;
	}

	return DefDlgProc (hwnd, uMsg, wParam, lParam);
}

/* InitApp - initialize the application, this function is called once in the
   applications WinMain function, but before the main dialog has been created */
void
InitApp (HINSTANCE hInstance)
{
	WNDCLASS wc;
	char *lpszTmp;
	OSVERSIONINFO os;

	/* Save the instance handle for later */
	hInst = hInstance;

	/* Pull down the windows version */
	os.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
	if (GetVersionEx (&os) == FALSE)
		AbortProcess (IDS_NO_OS_VER);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
		nCurrentOS = WIN_NT;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 0)
		nCurrentOS = WIN_95;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 10)
		nCurrentOS = WIN_98;
	else {
	/*	AbortProcess (IDS_NO_OS_VER); */
		nCurrentOS = WIN_98;
	}

	/* Get the attributes for the standard dialog class */
	if ((GetClassInfo (hInst, WINDOWS_DIALOG_CLASS, &wc)) == 0)
		AbortProcess (IDS_INIT_REGISTER);

	wc.hIcon = LoadIcon (hInstance, MAKEINTRESOURCE (IDI_E4M));
	wc.lpszClassName = E4M_DLG_CLASS;
	wc.lpfnWndProc = &CustomDlgProc;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.cbWndExtra = DLGWINDOWEXTRA;

	hDlgClass = RegisterClass (&wc);
	if (hDlgClass == 0)
		AbortProcess (IDS_INIT_REGISTER);

	wc.lpszClassName = E4M_SPLASH_CLASS;
	wc.lpfnWndProc = &SplashDlgProc;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.cbWndExtra = DLGWINDOWEXTRA;

	hSplashClass = RegisterClass (&wc);
	if (hSplashClass == 0)
		AbortProcess (IDS_INIT_REGISTER);

	GetModuleFileName (NULL, szHelpFile, sizeof (szHelpFile));
	lpszTmp = strrchr (szHelpFile, '\\');
	if (lpszTmp)
	{
		strcpy (++lpszTmp, "MANUAL.hlp");
	}

	hMutex = CreateMutex (NULL, TRUE, lpszTitle);
	if (hMutex == NULL)
	{
		handleWin32Error (NULL);
		AbortProcess (IDS_INIT_MUTEX);
	}

	if (GetLastError ()== ERROR_ALREADY_EXISTS)
	{
		AbortProcess (IDS_TWO_INSTANCES);
	}

#ifndef SETUP
	/* Setup the service if it's not present */
	if (CheckService ()== FALSE)
		AbortProcess (IDS_NOSERVICE);
#endif

}

BOOL
InstallService (SC_HANDLE schSCManager, char *SZSERVICENAME, char *SZSERVICEDISPLAYNAME)
{
	SC_HANDLE schService;

	schService = CreateService (
					   schSCManager,	/* SCManager database */
					   SZSERVICENAME,	/* name of service */
					   SZSERVICEDISPLAYNAME,	/* name to display */
					   SERVICE_ALL_ACCESS,	/* desired access */
					   SERVICE_WIN32_OWN_PROCESS,	/* service type */
					   SERVICE_AUTO_START,	/* start type */
					   SERVICE_ERROR_NORMAL,	/* error control type */
					   "e4mserv.exe",	/* service's binary */
					   NULL,	/* no load ordering
							   group */
					   NULL,	/* no tag identifier */
					   "",	/* dependencies */
					   NULL,	/* LocalSystem account */
					   NULL);	/* no password */

	if (schService != NULL)
	{
		CloseServiceHandle (schService);
		return TRUE;
	}

	return FALSE;
}

BOOL
CheckService ()
{
	SC_HANDLE schService = NULL;
	SC_HANDLE schSCManager = NULL;
	BOOL bInstall = FALSE;
	BOOL bAdmin = TRUE;
	BOOL bResult = TRUE;

	if (nCurrentOS != WIN_NT)
		return TRUE;

	schSCManager = OpenSCManager (
					     NULL,	/* machine (NULL ==
							   local) */
					     NULL,	/* database (NULL ==
							   default) */
					     SC_MANAGER_ALL_ACCESS	/* access required */
	    );

	if (schSCManager == NULL)
	{
		schSCManager = OpenSCManager (
						     NULL,	/* machine (NULL ==
								   local) */
						     NULL,	/* database (NULL ==
								   default) */
						     SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS	/* access required */
		    );

		bAdmin = FALSE;
	}

	if (schSCManager == NULL)
		goto error;

	if (bAdmin == TRUE)
		schService = OpenService (schSCManager, "e4mservice", SERVICE_ALL_ACCESS);
	else
		schService = OpenService (schSCManager, "e4mservice", SERVICE_QUERY_STATUS);

	if (schService == NULL)
	{
		BOOL bOK;

		if (bAdmin == FALSE)
		{
			handleWin32Error (NULL);
			CloseServiceHandle (schSCManager);
#ifndef SETUP
			AbortProcess (IDS_NOSERVICE);
#else
			return FALSE;
#endif
		}

		if (bInstall == TRUE)
			goto error;

		bInstall = TRUE;

		bOK = InstallService (schSCManager, "e4mservice", "E4M service");

		if (bOK == FALSE)
			goto error;

		schService = OpenService (schSCManager, "e4mservice", SERVICE_ALL_ACCESS);
	}

	if (schService != NULL)
	{
		SERVICE_STATUS status;
		BOOL bOK;
		int i;

		bOK = QueryServiceStatus (schService, &status);

		if (bOK == FALSE)
			goto error;

		if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING)
			goto success;

		if (bAdmin == FALSE)
		{
			CloseServiceHandle (schService);
			CloseServiceHandle (schSCManager);
#ifndef SETUP
			AbortProcess (IDS_SERVICE_NOT_RUNNING);
#else
			return FALSE;
#endif

		}

		bOK = StartService (schService, 0, NULL);

		if (bOK == FALSE)
			goto error;

#define WAIT_PERIOD 3

		for (i = 0; i < WAIT_PERIOD; i++)
		{
			Sleep (1000);
			bOK = QueryServiceStatus (schService, &status);

			if (bOK == FALSE)
				goto error;


			if (status.dwCurrentState == SERVICE_RUNNING)
				break;
		}

		if (i == WAIT_PERIOD)
			bOK = FALSE;

		if (bOK == FALSE)
			goto error;
		else
			goto success;
	}


      error:
	if (GetLastError ()!= 0)
		handleWin32Error (NULL);

	bResult = FALSE;

      success:
	if (schService != NULL)
		CloseServiceHandle (schService);

	if (schSCManager != NULL)
		CloseServiceHandle (schSCManager);

	return bResult;
}

BOOL
OpenDevice (char *lpszPath, OPEN_TEST_STRUCT * driver)
{
	DWORD dwResult;
	BOOL bResult;

	strcpy ((char *) &driver->wszFileName[0], lpszPath);

	if (nCurrentOS == WIN_NT)
		ToUNICODE ((char *) &driver->wszFileName[0]);

	bResult = DeviceIoControl (hDriver, OPEN_TEST,
				   driver, sizeof (OPEN_TEST_STRUCT),
				   &driver, sizeof (OPEN_TEST_STRUCT),
				   &dwResult, NULL);

	if (bResult == FALSE)
	{
		dwResult = GetLastError ();
		if (dwResult == ERROR_SHARING_VIOLATION)
			return TRUE;
		else
			return FALSE;
	}
	else
	{
		if (nCurrentOS == WIN_NT)
			return TRUE;
		else if (driver->nReturnCode == 0)
			return TRUE;
		else
		{
			SetLastError (ERROR_FILE_NOT_FOUND);
			return FALSE;
		}
	}
}

UINT _stdcall
win9x_io (HFILE hFile, char *lpBuffer, UINT uBytes)
{
	DISKIO_STRUCT *win9x_r0 = (DISKIO_STRUCT *) hFile;
	DWORD dwResult;
	BOOL bResult;
	LONG secs;

	win9x_r0->bufferad = (void *) lpBuffer;

	secs = uBytes / SECTOR_SIZE;

	win9x_r0->sectorlen = secs;

	bResult = DeviceIoControl (hDriver, DISKIO, win9x_r0, sizeof (DISKIO_STRUCT), win9x_r0,
				   sizeof (DISKIO_STRUCT), &dwResult, NULL);

	if (bResult == FALSE || win9x_r0->nReturnCode != 0)
		return (UINT) HFILE_ERROR;

	win9x_r0->sectorstart += secs;

	return uBytes;
}

int
GetAvailableFixedDisks (HWND hComboBox, char *lpszRootPath)
{
	int i, n;
	for (i = 0; i < 64; i++)
	{
		for (n = 1; n < 5; n++)
		{
			char szTmp[E4M_MAX_PATH];
			OPEN_TEST_STRUCT driver;

			sprintf (szTmp, lpszRootPath, i, n);
			if (OpenDevice (szTmp, &driver) == TRUE)
			{
				LPARAM lReturn = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) szTmp);
				lReturn = lReturn;
			}
			else
			{
				if (n == 1)
					i = 64;
				break;
			}
		}
	}

	i = SendMessage (hComboBox, CB_GETCOUNT, 0, 0);
	if (i != CB_ERR)
	{
		SendMessage (hComboBox, CB_SETCURSEL, 1, 0);
		return i;
	}
	else
		return 0;
}

int
GetAvailableRemovables (HWND hComboBox, char *lpszRootPath)
{
	char szTmp[E4M_MAX_PATH];
	int i;

	if (lpszRootPath);	/* Remove unused parameter warning */


	if (nCurrentOS != WIN_NT)
		return 0;

	if (QueryDosDevice ("A:", szTmp, sizeof (szTmp)) != 0)
	{
		SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) "Floppy (A:)");
	}
	if (QueryDosDevice ("B:", szTmp, sizeof (szTmp)) != 0)
	{
		SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) "Floppy (B:)");
	}

	i = SendMessage (hComboBox, CB_GETCOUNT, 0, 0);
	if (i != CB_ERR)
	{
		SendMessage (hComboBox, CB_SETCURSEL, 1, 0);
		return i;
	}
	else
		return 0;
}

BOOL WINAPI
RawDevicesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static char *lpszFileName;
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	if (lParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			int nCount;

			nCount = GetAvailableFixedDisks (GetDlgItem (hwndDlg, IDC_DEVICE),
				       "\\Device\\Harddisk%d\\Partition%d");
			nCount += GetAvailableRemovables (GetDlgItem (hwndDlg, IDC_DEVICE),
						      "\\Device\\Floppy%d");

			if (nCount == 0)
			{
				handleWin32Error (hwndDlg);
				MessageBox (hwndDlg, getstr (IDS_RAWDEVICES), lpszTitle, ICON_HAND);
				EndDialog (hwndDlg, IDCANCEL);
			}

			lpszFileName = (char *) lParam;
			return 1;
		}

	case WM_COMMAND:
		if (lw == IDOK || (hw == CBN_DBLCLK && lw == IDC_DEVICE))
		{
			GetWindowText (GetDlgItem (hwndDlg, IDC_DEVICE), lpszFileName, E4M_MAX_PATH);
			EndDialog (hwndDlg, IDOK);
			return 0;
		}
		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, IDCANCEL);
			return 0;
		}
		return 0;
	}

	return 0;
}

int
DriverAttach (void)
{
	/* Try to open a handle to the device driver. It will be closed
	   later. */

	if (nCurrentOS == WIN_NT)
		hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
	else
		hDriver = CreateFile (WIN9X_DRIVER_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		return ERR_OS_ERROR;
	}
	else
	{
		LONG driver = 0;
		DWORD dwResult;

		BOOL bResult = DeviceIoControl (hDriver, DRIVER_VERSION,
				   &driver, 4, &driver, 4, &dwResult, NULL);

		if (bResult == FALSE)
			return ERR_OS_ERROR;
		else if (driver != VERSION_NUM)
			return ERR_DRIVER_VERSION;
	}

	if (nCurrentOS == WIN_98)
	{
		DWORD dwResult;
		DeviceIoControl (hDriver, ALLOW_FAST_SHUTDOWN, NULL, 0, NULL, 0, &dwResult, NULL);
	}

	return 0;
}

void
CloseHelpFile (HWND hwndDlg, BOOL bHelpStarted)
{
	if (bHelpStarted == TRUE)
		WinHelp (hwndDlg, szHelpFile, HELP_QUIT, 0);
}

BOOL
BrowseFiles (HWND hwndDlg, UINT nTitleID, char *lpszFileName)
{
	OPENFILENAME ofn;

	char szFileTitle[E4M_MAX_PATH];
	*szFileTitle = *lpszFileName = 0;
	ofn.lStructSize = sizeof (OPENFILENAME);
	ofn.hwndOwner = hwndDlg;
	ofn.lpstrFilter = "E4M Files (*.vol)\0*.vol\0All Files (*.*)\0*.*\0";
	ofn.lpstrCustomFilter = NULL;
	ofn.nFilterIndex = 1;
	ofn.lpstrFile = lpszFileName;
	ofn.nMaxFile = E4M_MAX_PATH;
	ofn.lpstrFileTitle = szFileTitle;
	ofn.nMaxFileTitle = E4M_MAX_PATH;
	ofn.lpstrInitialDir = NULL;
	ofn.lpstrTitle = getstr (nTitleID);
	ofn.Flags = OFN_HIDEREADONLY | OFN_PATHMUSTEXIST;
	ofn.lpstrDefExt = "vol";

	if (!GetOpenFileName (&ofn))
		return FALSE;
	else
		return TRUE;
}


void
handleError (HWND hwndDlg, int code)
{
	char szTmp[512];

	switch (code)
	{
	case ERR_OS_ERROR:
		handleWin32Error (hwndDlg);
		break;
	case ERR_OUTOFMEMORY:
		MessageBox (hwndDlg, getstr (IDS_OUTOFMEMORY), lpszTitle, ICON_HAND);
		break;
	case ERR_PASSWORD_WRONG:
		MessageBox (hwndDlg, getstr (IDS_PASSWORD_WRONG), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_FORMAT_BAD:
		MessageBox (hwndDlg, getstr (IDS_VOL_FORMAT_BAD), lpszTitle, ICON_HAND);
		break;
	case ERR_BAD_DRIVE_LETTER:
		MessageBox (hwndDlg, getstr (IDS_BAD_DRIVE_LETTER), lpszTitle, ICON_HAND);
		break;
	case ERR_DRIVE_NOT_FOUND:
		MessageBox (hwndDlg, getstr (IDS_NOT_FOUND), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN:
		MessageBox (hwndDlg, getstr (IDS_OPENFILES_DRIVER), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN_LOCK:
		MessageBox (hwndDlg, getstr (IDS_OPENFILES_LOCK), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SIZE_WRONG:
		MessageBox (hwndDlg, getstr (IDS_VOL_SIZE_WRONG), lpszTitle, ICON_HAND);
		break;
	case ERR_COMPRESSION_NOT_SUPPORTED:
		MessageBox (hwndDlg, getstr (IDS_COMPRESSION_NOT_SUPPORTED), lpszTitle, ICON_HAND);
		break;
	case ERR_PASSWORD_CHANGE_VOL_TYPE:
		MessageBox (hwndDlg, getstr (IDS_WRONG_VOL_TYPE), lpszTitle, ICON_HAND);
		break;
	case ERR_PASSWORD_CHANGE_VOL_VERSION:
		MessageBox (hwndDlg, getstr (IDS_WRONG_VOL_VERSION), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SEEKING:
		MessageBox (hwndDlg, getstr (IDS_VOL_SEEKING), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_WRITING:
		MessageBox (hwndDlg, getstr (IDS_VOL_WRITING), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_READING:
		MessageBox (hwndDlg, getstr (IDS_VOL_READING), lpszTitle, ICON_HAND);
		break;

	case ERR_VOL_ALREADY_MOUNTED:
		MessageBox (hwndDlg, getstr (IDS_VOL_ALREADY_MOUNTED), lpszTitle, ICON_HAND);
		break;
	case ERR_FILE_OPEN_FAILED:
		MessageBox (hwndDlg, getstr (IDS_FILE_OPEN_FAILED), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_MOUNT_FAILED:
		MessageBox (hwndDlg, getstr (IDS_VOL_MOUNT_FAILED), lpszTitle, ICON_HAND);
		break;
	case ERR_NO_FREE_SLOTS:
		MessageBox (hwndDlg, getstr (IDS_NO_FREE_SLOTS), lpszTitle, ICON_HAND);
		break;
	case ERR_NO_FREE_DRIVES:
		MessageBox (hwndDlg, getstr (IDS_NO_FREE_DRIVES), lpszTitle, ICON_HAND);
		break;
	case ERR_INVALID_DEVICE:
		MessageBox (hwndDlg, getstr (IDS_INVALID_DEVICE), lpszTitle, ICON_HAND);
		break;
	case ERR_ACCESS_DENIED:
		MessageBox (hwndDlg, getstr (IDS_ACCESS_DENIED), lpszTitle, ICON_HAND);
		break;

	case ERR_DRIVER_VERSION:
		sprintf (szTmp, getstr (IDS_DRIVER_VERSION), VERSION_STRING);
		MessageBox (hwndDlg, szTmp, lpszTitle, ICON_HAND);
		break;

	default:
		sprintf (szTmp, getstr (IDS_UNKNOWN), code);
		MessageBox (hwndDlg, szTmp, lpszTitle, ICON_HAND);

	}
}
