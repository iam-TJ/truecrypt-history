/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"

#include "dlgcode.h"
#include "combo.h"
#include "../common/resource.h"
#include "crypto.h"
#include "ntioctl.h"

#include "resource.h"
#include "cmdline.h"
#include "volmount.h"
#include "sdvol.h"

#include "dismount.h"

#include "password.h"

#include <time.h>

BOOL bHelpStarted = FALSE;	/* Set if the help system has been started */
BOOL bExplore = FALSE;		/* Donot display explorer window after mount */
BOOL bBeep = FALSE;		/* Donot beep after mount */
char szFileName[E4M_MAX_PATH];	/* Volume to mount */
char szDriveLetter[3];		/* Drive Letter to mount */
BOOL bCacheInDriver = FALSE;	/* Cache any passwords we see */
BOOL bHistory = FALSE;		/* Remember all the settings */

BOOL bWipe = FALSE;		/* Wipe driver passwords */
BOOL bAuto = FALSE;		/* Do everything without user input */

BOOL bNoMountWarning = FALSE;	/* Don't show mount warning */

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
  GetPrivateProfileString ("LastRun", "drive_letter", "", szDriveLetter,
			   sizeof (szDriveLetter), "e4m.ini");

  bCacheInDriver = GetPrivateProfileInt ("LastRun", "cache_in_driver",
					 FALSE, "e4m.ini");

  bHistory = !GetPrivateProfileInt ("LastRun", "never_save_history",
				    FALSE, "e4m.ini");

  LoadCombo (GetDlgItem (hwndDlg, IDC_VOLUME), "LastRun", "last_volume",
	     "e4m.ini");

  bNoMountWarning = GetPrivateProfileInt ("LastRun", "no_mount_warning", FALSE, "e4m.ini");

  /* There are no mount warning's currently defined */
  bNoMountWarning = TRUE;
}

void
SaveSettings (HWND hwndDlg)
{
  char szTmp[32];
  LPARAM lLetter;

  /* This setting is not affected by the no history switch */
  sprintf (szTmp, "%d", bNoMountWarning);
  WritePrivateProfileString ("LastRun", "no_mount_warning", szTmp, "e4m.ini");

  /* History */
  bHistory = !IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY));
  if (bHistory == FALSE)
    {
      /* User wants no settings, stop now, and remove old settings if found */
      remove ("e4m.ini");
      return;
    }
  sprintf (szTmp, "%d", !bHistory);
  WritePrivateProfileString ("LastRun", "never_save_history", szTmp,
			     "e4m.ini");


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
LoadDriveLetters (HWND hTree, DWORD dwUsedDrives, BOOL bMounted, E4M_NT_MOUNT_LIST * driver)
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

	      ToSBCS (driver->wszVolume[i]);
	      if (memcmp (driver->wszVolume[i], "\\Device", 7) == 0)
		sprintf (szTmp, "%s %s", szDriveLetters[i], ((char *) driver->wszVolume[i]));
	      else
		sprintf (szTmp, "%s %s", szDriveLetters[i], ((char *) driver->wszVolume[i]) + 4);
	      tvInsert.item.pszText = szTmp;

	      tvInsert.item.lParam = MAKELONG (VMOUNTED, i + 'A');
	      TreeView_InsertItem (hTree, &tvInsert);
	    }
	}
      else
	{
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
  E4M_NT_MOUNT_LIST driver;
  DWORD dwResult;
  BOOL bResult;

  bResult = DeviceIoControl (hNTDriver, E4M_MOUNT_LIST, &driver,
		       sizeof (driver), &driver, sizeof (driver), &dwResult,
			     NULL);

  if (bResult == FALSE || dwResult != sizeof (driver))
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

  if (lParam);			/* remove warning */

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
	  /* We use E4M_VOLTYPE2 here but it really does not matter as we
	     don't know the volumes type anyway... */
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

void
Show (HWND hwndDlg, int nCtrl)
{
  ShowWindow (GetDlgItem (hwndDlg, nCtrl), SW_SHOWNORMAL);
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

  hBitmap = LoadBitmap (GET_INSTANCE (hTree), MAKEINTRESOURCE (IDB_TREE_VIEW_NORMAL));
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
HidePassword4 (HWND hwndDlg)
{
  Show (hwndDlg, IDC_PASSWORD);
  Show (hwndDlg, IDC_PASSWORD_STATIC);

  Hide (hwndDlg, IDC_PASSWORD2);
  Hide (hwndDlg, IDC_PASSWORD_STATIC2);
  Hide (hwndDlg, IDC_PASSWORD3);
  Hide (hwndDlg, IDC_PASSWORD_STATIC3);
  Hide (hwndDlg, IDC_PASSWORD4);
  Hide (hwndDlg, IDC_PASSWORD_STATIC4);
}

void
ShowPassword4 (HWND hwndDlg)
{
  Show (hwndDlg, IDC_PASSWORD);
  Show (hwndDlg, IDC_PASSWORD_STATIC);

  Show (hwndDlg, IDC_PASSWORD2);
  Show (hwndDlg, IDC_PASSWORD_STATIC2);
  Show (hwndDlg, IDC_PASSWORD3);
  Show (hwndDlg, IDC_PASSWORD_STATIC3);
  Show (hwndDlg, IDC_PASSWORD4);
  Show (hwndDlg, IDC_PASSWORD_STATIC4);
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
    IDC_PASSWORD2,
    IDC_PASSWORD_STATIC2,
    IDC_PASSWORD3,
    IDC_PASSWORD_STATIC3,
    IDC_PASSWORD4,
    IDC_PASSWORD_STATIC4,
    IDC_PASSWORD_TAB,
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


  if (nShowType == SHOW_MOUNT)
    {
      HWND hTab = GetDlgItem (hwndDlg, IDC_PASSWORD_TAB);
      int nCurrentTab = SendMessage (hTab, TCM_GETCURSEL, 0, 0);

      if (nCurrentTab == 0)
	HidePassword4 (hwndDlg);
      else
	ShowPassword4 (hwndDlg);
    }

  nCurrentShowType = nShowType;
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL WINAPI
WarningDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
  WORD lw = LOWORD (wParam);
  if (lParam);			/* remove warning */

  switch (msg)
    {
    case WM_INITDIALOG:
      SetWindowText (GetDlgItem (hwndDlg, IDC_WARNING_TEXT), (LPCSTR) lParam);
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

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK
MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  WORD lw = LOWORD (wParam);
  WORD hw = HIWORD (wParam);
  if (lParam);			/* remove warning */

  switch (uMsg)
    {
    case WM_INITDIALOG:
      {
	TC_ITEM tabItem;

	LoadSettings (hwndDlg);

	/* Call the common dialog init code */
	InitDialog (hwndDlg);

	SendMessage (GetDlgItem (hwndDlg, IDC_VOLUME), CB_LIMITTEXT, E4M_MAX_PATH, 0);

	SendMessage (GetDlgItem (hwndDlg, IDC_NO_DRIVES_STATIC), WM_SETFONT, (WPARAM) hBoldFont, (LPARAM) TRUE);
	SetWindowText (hwndDlg, lpszTitle);

	tabItem.mask = TVIF_TEXT;
	tabItem.pszText = getstr (IDS_PASSWORD);
	TabCtrl_InsertItem (GetDlgItem (hwndDlg, IDC_PASSWORD_TAB), 0, &tabItem);
	tabItem.pszText = getstr (IDS_PASSWORD4);
	TabCtrl_InsertItem (GetDlgItem (hwndDlg, IDC_PASSWORD_TAB), 1, &tabItem);

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
	  DialogBox (GET_INSTANCE (hwndDlg), MAKEINTRESOURCE (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
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
	      HWND hTab = GetDlgItem (hwndDlg, IDC_PASSWORD_TAB);
	      int nCurrentTab = SendMessage (hTab, TCM_GETCURSEL, 0, 0);

	      if (nCurrentTab == 0)
		HidePassword4 (hwndDlg);
	      else
		ShowPassword4 (hwndDlg);

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

      if (((LPNMHDR) lParam)->code == TCN_SELCHANGE)
	{
	  HWND hTab = GetDlgItem (hwndDlg, IDC_PASSWORD_TAB);
	  int nCurrentTab = SendMessage (hTab, TCM_GETCURSEL, 0, 0);
	  if (nCurrentTab == 0)
	    HidePassword4 (hwndDlg);
	  else
	    ShowPassword4 (hwndDlg);
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
	  E4M_NT_MOUNT driver;
	  DWORD dwResult;
	  BOOL bResult, bDevice;
	  char dosName[3];
	  HWND hTab = GetDlgItem (hwndDlg, IDC_PASSWORD_TAB);
	  int nCurrentTab = SendMessage (hTab, TCM_GETCURSEL, 0, 0);
	  HWND hPassword;

	  driver.nDosDriveNo = (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_TREE))) -
				'A');

	  dosName[0] = (char) (driver.nDosDriveNo + 'A');
	  dosName[1] = ':';
	  dosName[2] = *szFileName = 0;

	  driver.bCache = IsButtonChecked (GetDlgItem (hwndDlg, IDC_CACHE));

	  driver.time = time (NULL);

	  if (nCurrentTab != 0)
	    {
	      SHA1_CTX S;
	      char szPassword[40 + 1];
	      char digestptr[SHA_DIGESTSIZE];
	      char sz4Password[160];

	      burn (sz4Password, sizeof (sz4Password));

	      /* 1 */
	      hPassword = GetDlgItem (hwndDlg, IDC_PASSWORD);
	      GetWindowText (hPassword, szPassword, sizeof (szPassword));

	      strcpy (sz4Password, szPassword);


	      /* 2 */
	      hPassword = GetDlgItem (hwndDlg, IDC_PASSWORD2);
	      GetWindowText (hPassword, szPassword, sizeof (szPassword));

	      strcpy (&sz4Password[40], szPassword);


	      /* 3 */
	      hPassword = GetDlgItem (hwndDlg, IDC_PASSWORD3);
	      GetWindowText (hPassword, szPassword, sizeof (szPassword));

	      strcpy (&sz4Password[80], szPassword);

	      hPassword = GetDlgItem (hwndDlg, IDC_PASSWORD4);
	      GetWindowText (hPassword, szPassword, sizeof (szPassword));

	      strcpy (&sz4Password[120], szPassword);

	      shash (&sz4Password[0], 160, &S, digestptr);

	      memcpy (driver.szPassword, digestptr, sizeof (digestptr));

	      burn (digestptr, sizeof (digestptr));
	      burn (sz4Password, sizeof (sz4Password));
	      burn (szPassword, sizeof (szPassword));

	      driver.nPasswordLen = sizeof (digestptr);

	      driver.bSD = TRUE;


	    }
	  else
	    {
	      char szPassword[MAX_PASSWORD + 1];

	      burn (szPassword, sizeof (szPassword));
	      hPassword = GetDlgItem (hwndDlg, IDC_PASSWORD);
	      GetWindowText (hPassword, szPassword, sizeof (szPassword));

	      memcpy (driver.szPassword, szPassword, sizeof (szPassword));
	      burn (szPassword, sizeof (szPassword));


	      driver.nPasswordLen = strlen (driver.szPassword);


	      driver.bSD = FALSE;

	    }

	  GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName,
			 sizeof (szFileName));

	  CreateFullVolumePath ((char *) &driver.wszVolume[0], &szFileName[0], &bDevice);

	  ToUNICODE ((char *) &driver.wszVolume[0]);

	  bResult = DeviceIoControl (hNTDriver, E4M_MOUNT, &driver,
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
		  char szDevice[64];
		  sprintf (szDevice, "%s%c", NT_MOUNT_PREFIX, dosName[0]);
		  bResult = DefineDosDevice (DDD_RAW_TARGET_PATH, dosName, szDevice);
		  if (bResult == FALSE)
		    {
		      MessageBox (hwndDlg, getstr (IDS_SYMLINK), lpszTitle, ICON_HAND);
		    }
		  else
		    {
		      if (bNoMountWarning != TRUE)
			{
			  int x = DialogBoxParam (GET_INSTANCE (hwndDlg), MAKEINTRESOURCE (IDD_WARNING_DLG), hwndDlg,
			   (DLGPROC) WarningDlgProc, (LPARAM) "no warning");

			  if (x == IDOK)
			    bNoMountWarning = TRUE;
			}

		      if (bExplore == TRUE)
			ShellExecute (NULL, "open", dosName, NULL, NULL, SW_SHOWNORMAL);
		      if (bBeep == TRUE)
			MessageBeep (MB_OK);

		      EndMainDlg (hwndDlg);
		    }
		}
	      else
		{
		  handleError (hwndDlg, driver.nReturnCode);
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

	  /* Unmount the volume using the e4mservice, this is done to allow
	     non-administrators to unmount volumes */

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
	  if (BrowseFiles (hwndDlg, IDS_OPEN_TITLE, szFileName, TRUE) == FALSE)
	    return 1;

	  AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
	  EnableDisableButtons (hwndDlg);
	  SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));
	  return 1;
	}

      if (lw == IDC_BROWSE_DEVICES)
	{
	  int nResult = DialogBoxParam (GET_INSTANCE (hwndDlg), MAKEINTRESOURCE (IDD_RAWDEVICES_DLG), hwndDlg,
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
	  int result = DialogBox (GET_INSTANCE (hwndDlg), MAKEINTRESOURCE (IDD_PASSWORDCHANGE_DLG), hwndDlg,
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

	  bResult = DeviceIoControl (hNTDriver, E4M_WIPE_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);

	  if (bResult == FALSE)
	    handleWin32Error (hwndDlg);
	  else
	    MessageBox (hwndDlg, getstr (IDS_WIPE_CACHE), lpszTitle, ICON_HAND);

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
  BOOL bHas4 = FALSE;

  /* Extract command line arguments */
  nNoCommandLineArgs = Win32CommandLine (lpszCommandLine, &lpszCommandLineArgs);
  if (nNoCommandLineArgs > 0)
    {
      int i;

      for (i = 0; i < nNoCommandLineArgs; i++)
	{
	  int nArgPos;
	  int x = GetArgumentID (lpszCommandLineArgs[i], &nArgPos);
	  switch (x)
	    {
	    case VOLUME_ARG:
	      if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i,
		       nNoCommandLineArgs, szFileName, sizeof (szFileName)))
		AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
	      break;

	    case DRIVE_LETTER_ARG:
	      GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
				szDriveLetter, sizeof (szDriveLetter));
	      *szDriveLetter = (char) toupper (*szDriveLetter);
	      break;

	    case EXPLORE_ARG:
	      bExplore = TRUE;
	      break;

	    case BEEP_ARG:
	      bBeep = TRUE;
	      break;

	    case PASSWORD_ARG:
	    case PASSWORD_ARG2:
	    case PASSWORD_ARG3:
	    case PASSWORD_ARG4:
	      {
		char szTmp[MAX_PASSWORD + 1];
		GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
				  szTmp, sizeof (szTmp));
		if (x == PASSWORD_ARG)
		  SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), szTmp);
		else if (x == PASSWORD_ARG2)
		  SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD2), szTmp);
		else if (x == PASSWORD_ARG3)
		  SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD3), szTmp);
		else if (x == PASSWORD_ARG4)
		  SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD4), szTmp);
		if (x != PASSWORD_ARG)
		  bHas4 = TRUE;
	      }
	      break;

	    case AUTO_ARG:
	      bAuto = TRUE;
	      break;

	    case CACHE_ARG:
	      {
		char szTmp[8];
		GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
				  szTmp, sizeof (szTmp));
		if (*szTmp == 'Y')
		  bCacheInDriver = TRUE;
		if (*szTmp == 'N')
		  bCacheInDriver = FALSE;
	      }
	      break;

	    case HISTORY_ARG:
	      {
		char szTmp[8];
		GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
				  szTmp, sizeof (szTmp));
		if (*szTmp == 'Y')
		  bHistory = TRUE;
		if (*szTmp == 'N')
		  bHistory = FALSE;
	      }
	      break;

	    case WIPE_ARG:
	      bWipe = TRUE;
	      break;

	    case SD_ARG:
	      bHas4 = TRUE;
	      break;


	    }
	}
    }

  if (bHas4 == TRUE)
    TabCtrl_SetCurSel (GetDlgItem (hwndDlg, IDC_PASSWORD_TAB), 1);

  /* Free up the command line arguments */
  while (--nNoCommandLineArgs >= 0)
    {
      free (lpszCommandLineArgs[nNoCommandLineArgs]);
    }
}

BOOL
InstallService (SC_HANDLE schSCManager, char *SZSERVICENAME, char *SZSERVICEDISPLAYNAME)
{
  SC_HANDLE schService;
  char szPath[E4M_MAX_PATH];
  char *lpszTmp;

  GetModuleFileName (NULL, szPath, sizeof (szPath));
  lpszTmp = strrchr (szPath, '\\');
  if (lpszTmp)
    {
      strcpy (++lpszTmp, "e4mservice.exe");
    }

  schService = CreateService (
			       schSCManager,	/* SCManager database */
			       SZSERVICENAME,	/* name of service */
			       SZSERVICEDISPLAYNAME,	/* name to display */
			       SERVICE_ALL_ACCESS,	/* desired access */
			       SERVICE_WIN32_OWN_PROCESS,	/* service type */
			       SERVICE_AUTO_START,	/* start type */
			       SERVICE_ERROR_NORMAL,	/* error control type */
			       szPath,	/* service's binary */
			       NULL,	/* no load ordering group */
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

  schSCManager = OpenSCManager (
				 NULL,	/* machine (NULL == local) */
				 NULL,	/* database (NULL == default) */
				 SC_MANAGER_ALL_ACCESS	/* access required */
    );

  if (schSCManager == NULL)
    {
      schSCManager = OpenSCManager (
				     NULL,	/* machine (NULL == local) */
				     NULL,	/* database (NULL == default) */
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
	  AbortProcess (IDS_NOSERVICE);
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

      bOK = QueryServiceStatus (schService, &status);

      if (bOK == FALSE)
	goto error;

      if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING)
	goto success;

      if (bAdmin == FALSE)
	{
	  CloseServiceHandle (schService);
	  CloseServiceHandle (schSCManager);
	  AbortProcess (IDS_SERVICE_NOT_RUNNING);
	}

      bOK = StartService (schService, 0, NULL);

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


int WINAPI
WINMAIN (HINSTANCE hInstance, HINSTANCE hPrevInstance, char *lpszCommandLine,
	 int nCmdShow)
{
  if (nCmdShow && hPrevInstance);	/* Remove unused parameter warning */

  atexit (localcleanup);

  /* Allocate, dup, then store away the application title */
  lpszTitle = err_strdup (getstr (IDS_TITLE));

  /* Call InitApp to initialize the common code */
  InitApp (hInstance);

  if (DriverAttach ()== FALSE)
    AbortProcess (IDS_NODRIVER);

  /* Setup the service if it's not present */
  if (CheckService ()== FALSE)
    AbortProcess (IDS_NOSERVICE);

  /* Create the main dialog box */
  DialogBoxParam (hInstance, MAKEINTRESOURCE (IDD_MOUNT_DLG), NULL, (DLGPROC) MainDialogProc,
		  (LPARAM) lpszCommandLine);

  /* Terminate */
  return 0;
}
