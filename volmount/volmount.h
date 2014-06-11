/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

/* Everything below this line is automatically updated by the -mkproto-tool- */

void localcleanup ( void );
void EndMainDlg ( HWND hwndDlg );
void EnableDisableButtons ( HWND hwndDlg );
void OpenPageHelp ( HWND hwndDlg );
void LoadSettings ( HWND hwndDlg );
void SaveSettings ( HWND hwndDlg );
BOOL IsInList ( HWND hTree , char nLetter , TV_ITEM *item );
BOOL SelectItem ( HWND hTree , char nLetter );
void LoadDriveLetters ( HWND hTree , DWORD dwUsedDrives , BOOL bMounted , E4M_NT_MOUNT_LIST *driver );
void GetAvailableDrives ( HWND hwndDlg , HWND hTree );
void GetMountedDrives ( HWND hwndDlg , HWND hTree );
BOOL WINAPI PasswordChangeDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
void Show ( HWND hwndDlg , int nCtrl );
void Hide ( HWND hwndDlg , int nCtrl );
void BuildTree ( HWND hwndDlg , HWND hTree );
LPARAM GetSelectedLong ( HWND hTree );
void HidePassword4 ( HWND hwndDlg );
void ShowPassword4 ( HWND hwndDlg );
void ShowAll ( HWND hwndDlg , int nShowType );
BOOL WINAPI WarningDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ExtractCommandLine ( HWND hwndDlg , char *lpszCommandLine );
BOOL InstallService ( SC_HANDLE schSCManager , char *SZSERVICENAME , char *SZSERVICEDISPLAYNAME );
BOOL CheckService ( void );
int WINAPI WINMAIN ( HINSTANCE hInstance , HINSTANCE hPrevInstance , char *lpszCommandLine , int nCmdShow );
