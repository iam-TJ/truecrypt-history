/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

/* Everything below this line is automatically updated by the -mkproto-tool- */

int HookProc ( pIFSFunc fsdproc , int fcn , int drive , int flags , int cp , pioreq pir );
int BroadcastMon ( int msg , int wparam , int lparam , int ref );
void installhook ( void );
void InstallE4MThread ( void );
void wakethread ( void );
void killthread ( void );
void E4MRing0Thread ( void );
