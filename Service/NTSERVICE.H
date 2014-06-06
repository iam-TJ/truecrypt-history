/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#define SZSERVICENAME        "e4mservice"
#define SZSERVICEDISPLAYNAME "E4M service"
#define SZDEPENDENCIES       ""

/* Everything below this line is automatically updated by the -mkproto-tool- */

void _CRTAPI1 main ( int argc , char **argv );
void WINAPI service_main ( DWORD dwArgc , LPSTR *lpszArgv );
void WINAPI service_ctrl ( DWORD dwCtrlCode );
BOOL ReportStatusToSCMgr ( DWORD dwCurrentState , DWORD dwWin32ExitCode , DWORD dwWaitHint );
void AddToMessageLog ( LPSTR lpszMsg );
LPSTR GetLastErrorText ( LPSTR lpszBuf , DWORD dwSize );
void ServiceStart ( DWORD dwArgc , LPTSTR *lpszArgv );
void ServiceStop ( void );
void handleWin32Error ( HWND dummy );
