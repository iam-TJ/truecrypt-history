/* Everything below this line is automatically updated by the -mkproto-tool- */

UINT APIENTRY OFNHookProcOldStyle ( HWND hdlg , UINT uiMsg , WPARAM wParam , LPARAM lParam );
BOOL StatDeleteFile ( char *lpszFile );
BOOL StatRemoveDirectory ( char *lpszDir );
HRESULT CreateLink ( char *lpszPathObj , char *lpszArguments , char *lpszPathLink );
void GetProgramPath ( HWND hwndDlg , char *path );
void StatusMessage ( HWND hwndDlg , char *head , char *txt );
void RegMessage ( HWND hwndDlg , char *txt );
void CopyMessage ( HWND hwndDlg , char *txt );
void RemoveMessage ( HWND hwndDlg , char *txt );
void ServiceMessage ( HWND hwndDlg , char *txt );
void IconMessage ( HWND hwndDlg , char *txt );
BOOL BrowseFiles2 ( HWND hwndDlg , LPCSTR lpszTitle , LPSTR lpszFileName );
void LoadLicense ( HWND hwndDlg );
BOOL DoFilesInstall ( HWND hwndDlg , char *szDestDir , BOOL bUninstallSupport );
BOOL DoRegInstall ( HWND hwndDlg , char *szDestDir , BOOL bInstallType , BOOL bUninstallSupport );
BOOL DoRegUninstall ( HWND hwndDlg );
BOOL DoServiceUninstall ( HWND hwndDlg , char *lpszService );
BOOL DoDriverUnload ( HWND hwndDlg );
BOOL DoServiceInstall ( HWND hwndDlg );
BOOL DoDriverInstall ( HWND hwndDlg );
BOOL DoShortcutsInstall ( HWND hwndDlg , char *szDestDir , BOOL bProgGroup );
