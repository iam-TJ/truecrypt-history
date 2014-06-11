
#define SZSERVICENAME        "e4mservice"
#define SZSERVICEDISPLAYNAME "E4M service"
#define SZDEPENDENCIES       ""

/* Everything below this line is automatically updated by the -mkproto-tool- */

void _CRTAPI1 main ( int argc , char **argv );
void WINAPI service_main ( DWORD dwArgc , LPSTR *lpszArgv );
VOID WINAPI service_ctrl ( DWORD dwCtrlCode );
BOOL ReportStatusToSCMgr ( DWORD dwCurrentState , DWORD dwWin32ExitCode , DWORD dwWaitHint );
VOID AddToMessageLog ( LPSTR lpszMsg );
LPSTR GetLastErrorText ( LPSTR lpszBuf , DWORD dwSize );
VOID ServiceStart ( DWORD dwArgc , LPTSTR *lpszArgv );
VOID ServiceStop ( void );
void handleWin32Error ( HWND dummy);
