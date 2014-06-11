/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#define IDC_ABOUT 0x7fff	/* ID for AboutBox on system menu in wm_user
				   range */

extern char szHelpFile[E4M_MAX_PATH];
extern HFONT hSmallFont;
extern HFONT hBoldFont;
extern HFONT hSmallBoldFont;
extern HFONT hTitleFont;
extern char *lpszTitle;

extern HANDLE hNTDriver;

#define ICON_HAND MB_ICONHAND
#define YES_NO MB_YESNO

#ifdef _UNICODE
#define WINMAIN wWinMain
#else
#define WINMAIN WinMain
#endif

#define GET_INSTANCE(x) ((HINSTANCE)GetWindowLong(x,GWL_HINSTANCE))

/* Everything below this line is automatically updated by the -mkproto-tool- */

void cleanup ( void );
void LowerCaseCopy ( char *lpszDest , char *lpszSource );
void UpperCaseCopy ( char *lpszDest , char *lpszSource );
void CreateFullVolumePath ( char *lpszDiskFile , char *lpszFileName , BOOL *bDevice );
int FakeDosNameForDevice ( char *lpszDiskFile , char *lpszDosDevice , char *lpszCFDevice , BOOL bNameOnly );
int RemoveFakeDosName ( char *lpszDiskFile , char *lpszDosDevice );
char *getstr ( UINT nID );
char *getmultilinestr ( UINT nID [4 ]);
void AbortProcess ( UINT nID );
void *err_malloc ( size_t size );
char *err_strdup ( const char *lpszText );
void handleWin32Error ( HWND hwndDlg );
BOOL translateWin32Error ( char *lpszMsgBuf , int nSizeOfBuf );
BOOL WINAPI AboutDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL IsButtonChecked ( HWND hButton );
void CheckButton ( HWND hButton );
void ToSBCS ( LPWSTR lpszText );
void ToUNICODE ( char *lpszText );
void InitDialog ( HWND hwndDlg );
void CreateMemBitmap ( HINSTANCE hInstance , HWND hwnd , const char *resource );
void PaintBitmap ( HDC pdcMem , int x , int y , int nWidth , int nHeight , HDC hDC );
LRESULT CALLBACK SplashDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
void WaitCursor ( void );
void NormalCursor ( void );
void ArrowWaitCursor ( void );
LRESULT CALLBACK CustomDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
void InitApp ( HINSTANCE hInstance );
BOOL OpenDevice ( char *lpszPath );
int GetAvailableFixedDisks ( HWND hComboBox , char *lpszRootPath );
int GetAvailableRemovables ( HWND hComboBox , char *lpszRootPath );
BOOL WINAPI RawDevicesDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL DriverAttach ( void );
void CloseHelpFile ( HWND hwndDlg , BOOL bHelpStarted );
BOOL BrowseFiles ( HWND hwndDlg , UINT nTitleID , char *lpszFileName , BOOL bIncludeSD );
void handleError ( HWND hwndDlg , int code );
