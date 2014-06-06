/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#include "crypto.h"
#include "apidrvr.h"
#include "dlgcode.h"
#include "combo.h"
#include "../common/resource.h"

#include "resource.h"
#include "cmdline.h"
#include "volmount.h"

#include "dismount.h"

#include "Password.h"

#include <time.h>

BOOL bHelpStarted = FALSE;	/* Set if the help system has been started */
BOOL bExplore = FALSE;		/* Donot display explorer window after mount */
BOOL bBeep = FALSE;		/* Donot beep after mount */
char szFileName[E4M_MAX_PATH];	/* Volume to mount */
char szDriveLetter[3];		/* Drive Letter to mount */
BOOL bCacheInDriver = FALSE;	/* Cache any passwords we see */
BOOL bHistory = FALSE;		/* Remember all the settings */

BOOL bHistoryCmdLine = FALSE; /* History control is always disabled */

BOOL bWipe = FALSE;		/* Wipe driver passwords */
BOOL bAuto = FALSE;		/* Do everything without user input */

BOOL bQuiet = FALSE;		/* No dialogs/messages */

#define VMOUNTED 1
#define VFREE	0

#define SHOW_MOUNT 0xa
#define SHOW_UNMOUNT 0xb
#define SHOW_NOTHING 0xc

int nCurrentShowType = 0;	/* current display mode, mount, unmount etc */

void
localcleanup (void)
{
	/* Free the application title */
	if (lpszTitle != NULL)
		free (lpszTitle);

	/* Cleanup common code resources */
	cleanup ();
}

void
EndMainDlg (HWND hwndDlg)
{
	MoveEditToCombo (GetDlgItem (hwndDlg, IDC_VOLUME));

	if (IsWindow(GetDlgItem(hwndDlg, IDC_NO_HISTORY)))
		bHistory = !IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY));

	if (bHistory == TRUE)
		SaveSettings (hwndDlg);
	CloseHelpFile (hwndDlg, bHelpStarted);
	EndDialog (hwndDlg, 0);
}

void
EnableDisableButtons (HWND hwndDlg)
{
	HWND hOKButton = GetDlgItem (hwndDlg, IDOK);
	HWND hChangeButton = GetDlgItem (hwndDlg, IDC_CHANGE_PASSWORD);
	HWND hVolume = GetDlgItem (hwndDlg, IDC_VOLUME);
	LPARAM nVolumeIndex = SendMessage (hVolume, CB_GETCURSEL, 0, 0);
	BOOL bEnable = TRUE;
	WORD x;

	if (nVolumeIndex == CB_ERR)
	{
		if (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_VOLUME)) > 0)
		{
			nVolumeIndex = 0;
		}
	}

	if (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_VOLUME)) <= 0)
		nVolumeIndex = CB_ERR;

	x = LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_TREE)));
	if (x == VFREE && nVolumeIndex == CB_ERR)
		bEnable = FALSE;
	else if (x == 0xffff)
		bEnable = FALSE;

	EnableWindow (hOKButton, bEnable);

	if (nCurrentShowType != SHOW_UNMOUNT)
		EnableWindow (hChangeButton, bEnable);
}

void
OpenPageHelp (HWND hwndDlg)
{
	if (WinHelp (hwndDlg, szHelpFile, HELP_CONTENTS, 0) == TRUE)
		bHelpStarted = TRUE;
}

void
LoadSettings (HWND hwndDlg)
{
	BOOL tmp;

	GetPrivateProfileString ("LastRun", "drive_letter", "", szDriveLetter,
				 sizeof (szDriveLetter), "e4m.ini");

	bCacheInDriver = GetPrivateProfileInt ("LastRun", "cache_in_driver",
					       FALSE, "e4m.ini");

	LoadCombo (GetDlgItem (hwndDlg, IDC_VOLUME), "LastRun", "last_volume",
		   "e4m.ini");

	if (bHistoryCmdLine == TRUE)
		return;

	tmp = GetPrivateProfileInt ("LastRun", "never_save_history",
					  TRUE, "e4m.ini");

	if (tmp == TRUE)
		bHistory = FALSE;
	else
		bHistory = TRUE;
	
}

void
SaveSettings (HWND hwndDlg)
{
	char szTmp[32];
	LPARAM lLetter;

	/* Cache */
	bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_CACHE));
	sprintf (szTmp, "%d", bCacheInDriver);
	WritePrivateProfileString ("LastRun", "cache_in_driver", szTmp,
				   "e4m.ini");

	/* Drive Letter */
	lLetter = GetSelectedLong (GetDlgItem (hwndDlg, IDC_TREE));
	if (LOWORD (lLetter) != 0xffff)
	{
		szTmp[0] = (char) HIWORD (lLetter);
		szTmp[1] = ':';
		szTmp[2] = 0;
	}
	else
	{
		szTmp[0] = 0;
		szTmp[1] = 0;
		szTmp[2] = 0;
	}
	WritePrivateProfileString ("LastRun", "drive_letter", szTmp,
				   "e4m.ini");


	DumpCombo (GetDlgItem (hwndDlg, IDC_VOLUME), "LastRun", "last_volume",
		   "e4m.ini");

	WritePrivateProfileString ("LastRun", "never_save_history", "0", "e4m.ini");

}

BOOL
IsInList (HWND hTree, char nLetter, TV_ITEM * item)
{
	HTREEITEM hItem = TreeView_GetRoot (hTree);

	if (hItem == NULL)
		goto err;

	for (;;)
	{
		item->mask = TCIF_PARAM;
		item->hItem = hItem;

		if (TreeView_GetItem (hTree, item) == FALSE)
			return FALSE;
		else
		{
			if (HIWORD (item->lParam) == nLetter)
				return TRUE;
		}

		hItem = TreeView_GetNextSibling (hTree, hItem);
		if (hItem == NULL)
			return FALSE;
	}

      err:
	return FALSE;
}

BOOL
SelectItem (HWND hTree, char nLetter)
{
	HTREEITEM hItem = TreeView_GetRoot (hTree);
	TV_ITEM item;

	if (hItem == NULL)
		goto err;

	for (;;)
	{
		item.mask = TCIF_PARAM;
		item.hItem = hItem;

		if (TreeView_GetItem (hTree, &item) == FALSE)
			return FALSE;
		else
		{
			if (HIWORD (item.lParam) == nLetter)
			{
				TreeView_SelectItem (hTree, item.hItem);
				return TRUE;
			}
		}

		hItem = TreeView_GetNextSibling (hTree, hItem);
		if (hItem == NULL)
			return FALSE;
	}

      err:
	return FALSE;
}


void
LoadDriveLetters (HWND hTree, DWORD dwUsedDrives, BOOL bMounted, MOUNT_LIST_STRUCT * driver)
{
	char *szDriveLetters[]=
	{"A:", "B:", "C:", "D:",
	 "E:", "F:", "G:", "H:", "I:", "J:", "K:",
	 "L:", "M:", "N:", "O:", "P:", "Q:", "R:",
	 "S:", "T:", "U:", "V:", "W:", "X:", "Y:",
	 "Z:"};
	TV_INSERTSTRUCT tvInsert;
	TV_ITEM listitem;
	char i;

	for (i = 0; i < 26; i++)
	{
		if (bMounted == TRUE)
		{
			if ((dwUsedDrives & 1 << i))
			{
				char szTmp[256];

				if (IsInList (hTree, i, &listitem) == TRUE)
				{
					TreeView_DeleteItem (hTree, listitem.hItem);
				}

				tvInsert.hInsertAfter = TVI_SORT;
				tvInsert.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
				tvInsert.hParent = 0;
				tvInsert.item.iImage = 0;
				tvInsert.item.iSelectedImage = 1;

				if (nCurrentOS == WIN_NT)
					ToSBCS ((void *) driver->wszVolume[i]);

				if (memcmp (driver->wszVolume[i], "\\Device", 7) == 0)
					sprintf (szTmp, "%s %s", szDriveLetters[i], ((char *) driver->wszVolume[i]));
				else
				{
					if (nCurrentOS == WIN_NT)
						sprintf (szTmp, "%s %s", szDriveLetters[i], ((char *) driver->wszVolume[i]) + 4);
					else
						sprintf (szTmp, "%s %s", szDriveLetters[i], (char *) driver->wszVolume[i]);
				}

				tvInsert.item.pszText = szTmp;

				tvInsert.item.lParam = MAKELONG (VMOUNTED, i + 'A');

				TreeView_InsertItem (hTree, &tvInsert);
			}
		}
		else
		{
			/* Skip A: & B: */
			if (i <= 2)
				continue;

			if (!(dwUsedDrives & 1 << i) && IsInList (hTree, i, &listitem) == FALSE)
			{
				tvInsert.hInsertAfter = TVI_SORT;
				tvInsert.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
				tvInsert.hParent = 0;
				tvInsert.item.iImage = 0;
				tvInsert.item.iSelectedImage = 1;
				tvInsert.item.pszText = szDriveLetters[i];
				tvInsert.item.lParam = MAKELONG (VFREE, i + 'A');
				TreeView_InsertItem (hTree, &tvInsert);
			}
		}
	}
}

void
GetAvailableDrives (HWND hwndDlg, HWND hTree)
{
	DWORD dwUsedDrives = GetLogicalDrives ();

	if (dwUsedDrives == 0)
	{
		if (bQuiet == FALSE)
			MessageBox (hwndDlg, getstr (IDS_DRIVELETTERS), lpszTitle, ICON_HAND);
	}
	else
	{
		LoadDriveLetters (hTree, dwUsedDrives, FALSE, NULL);
	}
}


void
GetMountedDrives (HWND hwndDlg, HWND hTree)
{
	MOUNT_LIST_STRUCT driver;
	DWORD dwResult;
	BOOL bResult;

	bResult = DeviceIoControl (hDriver, MOUNT_LIST, &driver,
		       sizeof (driver), &driver, sizeof (driver), &dwResult,
				   NULL);

	if (bResult == FALSE)
	{
		handleWin32Error (hwndDlg);
	}
	else
	{
		LoadDriveLetters (hTree, driver.ulMountedDrives, TRUE, &driver);
	}
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
PasswordChangeDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{

	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	if (lParam);		/* remove warning */
	if (hw);			/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			UINT nID[4];

			nID[0] = IDS_PASSWORD_HELP0;
			nID[1] = IDS_PASSWORD_HELP1;
			nID[2] = IDS_PASSWORD_HELP2;
			nID[3] = IDS_PASSWORD_HELP3;

			SendMessage (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), getmultilinestr (nID));
			EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);

			return 1;
		}

	case WM_COMMAND:
		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}
		if (hw == EN_CHANGE)
		{
			/* We use E4M_VOLTYPE2 here but it really does not
			   matter as we don't know the volumes type anyway... */
			VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (hwndDlg, IDOK), GetDlgItem (hwndDlg, IDC_PASSWORD),
						 GetDlgItem (hwndDlg, IDC_VERIFY), NULL, NULL, E4M_VOLTYPE2);
			return 1;
		}
		if (lw == IDOK)
		{
			HWND hParent = GetParent (hwndDlg);
			char szOldPassword[MAX_PASSWORD + 1];
			char szPassword[MAX_PASSWORD + 1];
			int nStatus;

			GetWindowText (GetDlgItem (hParent, IDC_VOLUME), szFileName, sizeof (szFileName));

			GetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), szOldPassword, sizeof (szOldPassword));

			GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szPassword, sizeof (szPassword));

			nStatus = ChangePwd (szFileName, szOldPassword, szPassword);

			burn (szOldPassword, sizeof (szOldPassword));
			burn (szPassword, sizeof (szPassword));

			if (nStatus != 0)
				handleError (hwndDlg, nStatus);
			else
				EndDialog (hwndDlg, IDOK);

			return 1;
		}
		return 0;
	}

	return 0;
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
PasswordDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static char* szXPwd;	

	switch (msg)
	{
	case WM_INITDIALOG:
		{

			szXPwd = (char*) lParam;

			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);

			return 1;
		}

	case WM_COMMAND:
		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}

		if (lw == IDOK)
		{
			GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szXPwd, MAX_PASSWORD + 1);

			EndDialog (hwndDlg, IDOK);

			return 1;
		}
		return 0;
	}

	return 0;
}

void
Show (HWND hwndDlg, int nCtrl)
{
	ShowWindow (GetDlgItem (hwndDlg, nCtrl), SW_SHOWNORMAL);
	
	if (bHistoryCmdLine == TRUE && nCtrl == IDC_NO_HISTORY)
		EnableWindow (GetDlgItem (hwndDlg, nCtrl), FALSE);
	else
		EnableWindow (GetDlgItem (hwndDlg, nCtrl), TRUE);
}

void
Hide (HWND hwndDlg, int nCtrl)
{
	ShowWindow (GetDlgItem (hwndDlg, nCtrl), SW_HIDE);
	EnableWindow (GetDlgItem (hwndDlg, nCtrl), FALSE);
}

void
BuildTree (HWND hwndDlg, HWND hTree)
{
	HIMAGELIST hList;
	HBITMAP hBitmap;

	hBitmap = LoadBitmap (hInst, MAKEINTRESOURCE (IDB_TREE_VIEW_NORMAL));
	if (hBitmap == NULL)
		return;

	hList = ImageList_Create (16, 12, ILC_COLOR, 2, 2);
	if (ImageList_Add (hList, hBitmap, NULL) == -1)
	{
		DeleteObject (hBitmap);
		return;
	}
	else
		DeleteObject (hBitmap);

	TreeView_SetImageList (hTree, hList, TVSIL_NORMAL);

	GetAvailableDrives (hwndDlg, hTree);
	GetMountedDrives (hwndDlg, hTree);

}

LPARAM
GetSelectedLong (HWND hTree)
{
	HTREEITEM hItem = TreeView_GetSelection (hTree);
	TV_ITEM item;

	if (hItem == NULL)
		return -1;

	item.mask = TCIF_PARAM;
	item.hItem = hItem;

	if (TreeView_GetItem (hTree, &item) == FALSE)
		return MAKELONG (0xffff, 0xffff);
	else
		return item.lParam;
}

void
ShowAll (HWND hwndDlg, int nShowType)
{
	int n_main_controls[]=
	{
		IDC_PASSWORD,
		IDC_PASSWORD_STATIC,
		IDC_CHANGE_PASSWORD,
		IDC_WIPE_CACHE,
		IDC_BROWSE_FILES,
		IDC_BROWSE_DEVICES,
		IDC_VOLUME,
		IDC_VOLUME_STATIC,
		IDC_CACHE,
		IDC_NO_HISTORY
	};
	int i;

	if (nShowType == nCurrentShowType)
		return;

	for (i = 0; i < sizeof (n_main_controls) / sizeof (n_main_controls[0]); i++)
	{
		if (nShowType == SHOW_MOUNT)
			Show (hwndDlg, n_main_controls[i]);
		else if (nShowType == SHOW_UNMOUNT || nShowType == SHOW_NOTHING)
			Hide (hwndDlg, n_main_controls[i]);
	}

	if (nShowType != SHOW_NOTHING)
		Hide (hwndDlg, IDC_NO_DRIVES_STATIC);
	else
		Show (hwndDlg, IDC_NO_DRIVES_STATIC);

	if (nShowType != SHOW_NOTHING)
		PostMessage(hwndDlg, WM_USER, 0, 0L);

	nCurrentShowType = nShowType;
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK
MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	if (lParam);		/* remove warning */

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			LoadSettings (hwndDlg);

			/* Call the common dialog init code */
			InitDialog (hwndDlg);

			SendMessage (GetDlgItem (hwndDlg, IDC_VOLUME), CB_LIMITTEXT, E4M_MAX_PATH, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_NO_DRIVES_STATIC), WM_SETFONT, (WPARAM) hBoldFont, (LPARAM) TRUE);
			SetWindowText (hwndDlg, lpszTitle);

			BuildTree (hwndDlg, GetDlgItem (hwndDlg, IDC_TREE));

			ShowAll (hwndDlg, SHOW_NOTHING);

			ExtractCommandLine (hwndDlg, (char *) lParam);

			if (*szDriveLetter != 0)
			{
				SelectItem (GetDlgItem (hwndDlg, IDC_TREE), *szDriveLetter);
			}

			SendMessage (GetDlgItem (hwndDlg, IDC_CACHE), BM_SETCHECK, bCacheInDriver == TRUE
				     ? BST_CHECKED : BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_NO_HISTORY), BM_SETCHECK, bHistory == FALSE
				     ? BST_CHECKED : BST_UNCHECKED, 0);

			EnableDisableButtons (hwndDlg);

			if (bWipe == TRUE)
			{
				SendMessage (GetDlgItem (hwndDlg, IDC_WIPE_CACHE), BM_CLICK, 0, 0);
			}

			if (bAuto == TRUE && IsWindowEnabled (GetDlgItem (hwndDlg, IDOK)))
			{
				SendMessage (GetDlgItem (hwndDlg, IDOK), BM_CLICK, 0, 0);
			}

			if (nCurrentShowType == SHOW_MOUNT)
			{
				if (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_VOLUME)) != 0)
				{
					SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));
				}
				else
				{
					SetFocus (GetDlgItem (hwndDlg, IDC_VOLUME));
				}
			}

			if (nCurrentShowType == SHOW_UNMOUNT)
			{
				SetFocus (GetDlgItem (hwndDlg, IDOK));
			}

			if (nCurrentShowType == SHOW_NOTHING)
			{
				SetFocus (GetDlgItem (hwndDlg, IDC_TREE));
			}


		}
		return 0;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBox (hInst, MAKEINTRESOURCE (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_HELP:
		OpenPageHelp (hwndDlg);
		return 1;

	case WM_NOTIFY:
		if (((LPNMHDR) lParam)->code == TVN_SELCHANGED)
		{
			NM_TREEVIEW *pnmtv = (NM_TREEVIEW *) lParam;
			if (LOWORD (pnmtv->itemNew.lParam) == 0)
			{
				ShowAll (hwndDlg, SHOW_MOUNT);

				SetWindowText (GetDlgItem (hwndDlg, IDOK), getstr (IDS_MOUNT_BUTTON));

			}
			else
			{

				ShowAll (hwndDlg, SHOW_UNMOUNT);

				SetWindowText (GetDlgItem (hwndDlg, IDOK), getstr (IDS_UNMOUNT_BUTTON));
			}

			return 1;
		}

		return 0;

	case WM_ERASEBKGND:
		return 0;

	case WM_COMMAND:
		if (lw == IDHELP)
		{
			OpenPageHelp (hwndDlg);
			return 1;
		}

		if (lw == IDOK && LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_TREE))) == VFREE)
		{
			MOUNT_STRUCT driver;
			DWORD dwResult;
			BOOL bResult, bDevice;
			char dosName[3];
			char szPassword[MAX_PASSWORD + 1];
			HWND hPassword;

			driver.nDosDriveNo = (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_TREE))) -
					      'A');

			dosName[0] = (char) (driver.nDosDriveNo + 'A');
			dosName[1] = ':';
			dosName[2] = *szFileName = 0;

			driver.bCache = IsButtonChecked (GetDlgItem (hwndDlg, IDC_CACHE));

			driver.time = time (NULL);

			burn (szPassword, sizeof (szPassword));
			hPassword = GetDlgItem (hwndDlg, IDC_PASSWORD);
			GetWindowText (hPassword, szPassword, sizeof (szPassword));

			memcpy (driver.szPassword, szPassword, sizeof (szPassword));
			burn (szPassword, sizeof (szPassword));

			driver.nPasswordLen = strlen (driver.szPassword);

			GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName,
				       sizeof (szFileName));

			CreateFullVolumePath ((char *) &driver.wszVolume[0], &szFileName[0], &bDevice);

			if (nCurrentOS == WIN_NT)
				ToUNICODE ((char *) &driver.wszVolume[0]);

			bResult = DeviceIoControl (hDriver, MOUNT, &driver,
						   sizeof (driver), &driver, sizeof (driver), &dwResult, NULL);

			burn (&driver.szPassword, sizeof (driver.szPassword));

			if (bResult == FALSE)
			{
				handleWin32Error (hwndDlg);
			}
			else
			{
				if (driver.nReturnCode == 0)
				{
					if (nCurrentOS == WIN_NT)
					{
						char szDevice[64];
						sprintf (szDevice, "%s%c", NT_MOUNT_PREFIX, dosName[0]);
						bResult = DefineDosDevice (DDD_RAW_TARGET_PATH, dosName, szDevice);
						if (bResult == FALSE)
						{
							if (bQuiet == FALSE)
								MessageBox (hwndDlg, getstr (IDS_SYMLINK), lpszTitle, ICON_HAND);
							return 1;
						}
					}
					else 
					{
						EjectStop ((char)toupper(szFileName[0]), TRUE);
					}

					if (bExplore == TRUE)
						ShellExecute (NULL, "open", dosName, NULL, NULL, SW_SHOWNORMAL);

					if (bBeep == TRUE)
						MessageBeep (MB_OK);

					EndMainDlg (hwndDlg);
				}
				else
				{
					if (bQuiet == FALSE)
						handleError (hwndDlg, driver.nReturnCode);
					else
						EndMainDlg (hwndDlg);
				}
			}
			return 1;
		}

		if (lw == IDOK && LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_TREE))) == VMOUNTED)
		{
			char *lpszPipeName = "\\\\.\\pipe\\e4mservice";
			DWORD bytesRead;
			BOOL bResult;
			int nDosDriveNo;
			char inbuf[80];
			char outbuf[80];

			nDosDriveNo = (char) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_TREE))) -
					      'A');


			if (nCurrentOS == WIN_NT)
			{
				/* Unmount the volume using the e4mservice,
				   this is done to allow non-administrators
				   to unmount volumes */

				sprintf (outbuf, "unmount %d", nDosDriveNo);

				bResult = CallNamedPipe (lpszPipeName,
						    outbuf, sizeof (outbuf),
						      inbuf, sizeof (inbuf),
					  &bytesRead, NMPWAIT_WAIT_FOREVER);

				if (bResult == FALSE)
				{
					handleWin32Error (hwndDlg);
				}
				else
				{
					DWORD os_err = 0;
					int err = 0;

					sscanf (inbuf, "%s %d %lu", outbuf, &err, &os_err);

					if (*inbuf == '-')
					{
						if (err == ERR_OS_ERROR)
						{
							SetLastError (os_err);

							handleWin32Error (hwndDlg);
						}
						else
						{
							handleError (hwndDlg, err);
						}
					}
					else
					{
						if (bBeep == TRUE)
							MessageBeep (MB_OK);

						EndMainDlg (hwndDlg);
					}
				}
			}
			else
			{
				int err = 0;

				bResult = CloseSlot (nDosDriveNo, 0, &err);

				if (bResult == FALSE)
				{
					handleWin32Error (hwndDlg);
				}
				else
				{
					if (err != 0)
					{
						handleError (hwndDlg, err);
					}
					else
					{
						if (bBeep == TRUE)
							MessageBeep (MB_OK);

						EndMainDlg (hwndDlg);
					}
				}
			}

			return 1;
		}

		if (lw == IDCANCEL)
		{
			EndMainDlg (hwndDlg);
			return 1;
		}

		if (lw == IDC_VOLUME && hw == CBN_EDITCHANGE)
		{
			PostMessage (hwndDlg, WM_USER, 0, 0);
			return 1;
		}

		if (lw == IDC_VOLUME && hw == CBN_SELCHANGE)
		{
			UpdateComboOrder (GetDlgItem (hwndDlg, IDC_VOLUME));
			MoveEditToCombo ((HWND) lParam);
			PostMessage (hwndDlg, WM_USER, 0, 0);
			return 1;
		}

		if (lw == IDC_BROWSE_FILES)
		{
			if (BrowseFiles (hwndDlg, IDS_OPEN_TITLE, szFileName) == FALSE)
				return 1;

			AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
			EnableDisableButtons (hwndDlg);
			SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));
			return 1;
		}

		if (lw == IDC_BROWSE_DEVICES)
		{
			int nResult = DialogBoxParam (hInst, MAKEINTRESOURCE (IDD_RAWDEVICES_DLG), hwndDlg,
						      (DLGPROC) RawDevicesDlgProc, (LPARAM) & szFileName[0]);
			if (nResult == IDOK)
			{
				AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
				EnableDisableButtons (hwndDlg);
				SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));
			}
			return 1;
		}

		if (lw == IDC_CHANGE_PASSWORD)
		{
			int result = DialogBox (hInst, MAKEINTRESOURCE (IDD_PASSWORDCHANGE_DLG), hwndDlg,
					   (DLGPROC) PasswordChangeDlgProc);

			if (result == IDOK)
			{
				HWND tmp = GetDlgItem (hwndDlg, IDC_PASSWORD);
				MessageBox (hwndDlg, getstr (IDS_PASSWORD_CHANGED), lpszTitle, ICON_HAND);
				SetFocus (tmp);
			}

			return 1;
		}

		if (lw == IDC_WIPE_CACHE)
		{
			DWORD dwResult;
			BOOL bResult;

			bResult = DeviceIoControl (hDriver, WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);

			if (bResult == FALSE)
				handleWin32Error (hwndDlg);
			else
			{
				if (bQuiet == FALSE)
					MessageBox (hwndDlg, getstr (IDS_WIPE_CACHE), lpszTitle, ICON_HAND);
			}
			return 1;
		}

		return 0;

	case WM_USER:
		EnableDisableButtons (hwndDlg);
		return 1;

	case WM_CLOSE:
		EndMainDlg (hwndDlg);
		return 1;
	}

	return 0;
}

void
ExtractCommandLine (HWND hwndDlg, char *lpszCommandLine)
{
	char **lpszCommandLineArgs;	/* Array of command line arguments */
	int nNoCommandLineArgs;	/* The number of arguments in the array */

	/* Extract command line arguments */
	nNoCommandLineArgs = Win32CommandLine (lpszCommandLine, &lpszCommandLineArgs);
	if (nNoCommandLineArgs > 0)
	{
		int i;

		for (i = 0; i < nNoCommandLineArgs; i++)
		{
			argument args[]=
			{
				{"/volume", "/v"},
				{"/letter", "/l"},
				{"/explore", "/e"},
				{"/beep", "/b"},
				{"/password", "/p"},
				{"/auto", "/a"},
				{"/cache", "/c"},
				{"/history", "/h"},
				{"/wipecache", "/wc"},
				{"/quiet", "/q"},
				{"/help", "/?"}
			};

			argumentspec as;

			int nArgPos;
			int x;

			as.args = args;
			as.arg_cnt = sizeof(args)/ sizeof(args[0]);
			
			x = GetArgumentID (&as, lpszCommandLineArgs[i], &nArgPos);

			switch (x)
			{
			case 'v':
				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i,
								      nNoCommandLineArgs, szFileName, sizeof (szFileName)))
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
				break;

			case 'l':
				GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
				     szDriveLetter, sizeof (szDriveLetter));
				*szDriveLetter = (char) toupper (*szDriveLetter);
				break;

			case 'e':
				bExplore = TRUE;
				break;

			case 'b':
				bBeep = TRUE;
				break;

			case 'p':
				{
					char szTmp[MAX_PASSWORD + 1];
					
					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     szTmp, sizeof (szTmp));

					if (strlen(szTmp) == 1 && *szTmp == '?') 
					{

						int result = DialogBoxParam (hInst, 
									MAKEINTRESOURCE (IDD_PASSWORD_DLG), hwndDlg,
					   				(DLGPROC) PasswordDlgProc, (LPARAM) szTmp);

						if (result != IDOK)
							*szTmp = 0;
					}

					SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szTmp);
					burn (szTmp, sizeof (szTmp));
				}
				break;

			case 'a':
				bAuto = TRUE;
				break;

			case 'c':
				{
					char szTmp[8];
					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     szTmp, sizeof (szTmp));
					if (!stricmp(szTmp,"y") || !stricmp(szTmp,"yes"))
						bCacheInDriver = TRUE;
					if (!stricmp(szTmp,"n") || !stricmp(szTmp,"no"))
						bCacheInDriver = FALSE;
				}
				break;

			case 'h':
				{
					char szTmp[8];
					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     szTmp, sizeof (szTmp));
					if (!stricmp(szTmp,"y") || !stricmp(szTmp,"yes"))
					{
						bHistory = TRUE;
						bHistoryCmdLine = TRUE;
					}

					if (!stricmp(szTmp,"n") || !stricmp(szTmp,"no"))
					{
						bHistory = FALSE;
						bHistoryCmdLine = TRUE;
					}
				}
				break;

			case 'w':
				bWipe = TRUE;
				break;

			case 'q':
				bQuiet = TRUE;
				break;

			case '?':
			default:
				DialogBoxParam (hInst, MAKEINTRESOURCE (IDD_COMMANDHELP_DLG), hwndDlg, (DLGPROC)
						CommandHelpDlgProc, (LPARAM) &as);

				exit(0);
			}
		}
	}

	/* Free up the command line arguments */
	while (--nNoCommandLineArgs >= 0)
	{
		free (lpszCommandLineArgs[nNoCommandLineArgs]);
	}
}

int WINAPI
WINMAIN (HINSTANCE hInstance, HINSTANCE hPrevInstance, char *lpszCommandLine,
	 int nCmdShow)
{
	int status;

	if (nCmdShow && hPrevInstance);	/* Remove unused parameter warning */

	atexit (localcleanup);

	/* Allocate, dup, then store away the application title */
	lpszTitle = err_strdup (getstr (IDS_TITLE));

	/* Call InitApp to initialize the common code */
	InitApp (hInstance);

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR)
			handleWin32Error (NULL);
		else
			handleError (NULL, status);

		AbortProcess (IDS_NODRIVER);
	}

	/* Create the main dialog box */
	DialogBoxParam (hInstance, MAKEINTRESOURCE (IDD_MOUNT_DLG), NULL, (DLGPROC) MainDialogProc,
			(LPARAM) lpszCommandLine);

	/* Terminate */
	return 0;
}
