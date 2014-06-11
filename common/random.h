/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

/* Everything below this line is automatically updated by the -mkproto-tool- */

int Randinit ( void );
void Randfree ( void );
void Randmix ( void );
void RandaddBuf ( void *buf , int len );
void RandpeekBytes ( char *buf , int len );
void RandgetBytes ( char *buf , int len );
int CALLBACK MouseProc ( int nCode , WPARAM wParam , LPARAM lParam );
int CALLBACK KeyboardProc ( int nCode , WPARAM wParam , LPARAM lParam );
void ThreadSafeThreadFunction ( void *dummy );
void SlowPollWinNT ( void );
void FastPoll ( void );
