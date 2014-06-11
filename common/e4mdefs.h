/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#define E4M_MAX_PATH			260	/* Includes the null
						   terminator */
#define SECTOR_SIZE			512	/* sector size */

#define E4M_OLD_VOLTYPE			1
#define SFS_VOLTYPE			2
#define SD_VOLTYPE			3
#define E4M_VOLTYPE2			4

#define isE4M(x) (x == E4M_OLD_VOLTYPE || x == E4M_VOLTYPE2)

#define BYTES_PER_KB			1024	/* 1kb = 1024 bytes */
#define BYTES_PER_MB			1024000	/* On disk 1mb = 1kb * 1000
						   not 1kb^2 */
#define ERR_OS_ERROR			0x7000
#define ERR_OUTOFMEMORY			0x700e
#define ERR_PASSWORD_WRONG		0x8001
#define ERR_VOLUME_FORMAT_BAD		0x8002
#define ERR_BAD_DRIVE_LETTER		0x8003
#define ERR_DRIVE_NOT_FOUND		0x8004
#define ERR_FILES_OPEN			0x8005
#define ERR_VOLUME_SIZE_WRONG		0x8006
#define ERR_COMPRESSION_NOT_SUPPORTED	0x8007
#define ERR_PASSWORD_CHANGE_VOL_TYPE	0x8008
#define ERR_PASSWORD_CHANGE_VOL_VERSION	0x8009
#define ERR_VOL_SEEKING			0x800a
#define ERR_VOL_WRITING			0x800b
#define ERR_FILES_OPEN_LOCK		0x800c

#define MAX_VOLUME_SIZE			2146435072
#define MIN_VOLUME_SIZE			19456

#define WIDE(x) (LPWSTR)L##x

#define VERSION_STRING			"V2.0.0"

#define burn(mem,size) \
	memset(mem,0xff,size); \
	memset(mem,0,size);

#ifndef NT4_DRIVER

#define e4malloc malloc
#define e4mfree free

#pragma warning( disable : 4201 )
#pragma warning( disable : 4214 )
#pragma warning( disable : 4115 )
#pragma warning( disable : 4514 )

#include <windows.h>		/* Windows header */
#include <commctrl.h>		/* The common controls */
#include <process.h>		/* Process control */
#include <winioctl.h>
#include <stdio.h>		/* For sprintf */

#pragma warning( default : 4201 )
#pragma warning( default : 4214 )
#pragma warning( default : 4115 )

/* #pragma warning( default : 4514 ) this warning remains disabled */

/* This is needed to fix a bug with VC 5, the TCHAR macro _ttoi64 maps
   incorrectly to atoi64 when it should be _atoi64 */
#define atoi64 _atoi64

#endif				/* !NT4_DRIVER */

#ifdef NT4_DRIVER

#pragma warning( disable : 4201 )
#pragma warning( disable : 4214 )
#pragma warning( disable : 4115 )
#pragma warning( disable : 4100 )
#pragma warning( disable : 4101 )
#pragma warning( disable : 4057 )
#pragma warning( disable : 4244 )
#pragma warning( disable : 4514 )
#pragma warning( disable : 4127 )

#include <ntddk.h>		/* Standard header file for nt drivers */
#include <ntdddisk.h>		/* Standard I/O control codes  */
#include <ntiologc.h>

#pragma warning( default : 4201 )
#pragma warning( default : 4214 )
#pragma warning( default : 4115 )
#pragma warning( default : 4100 )
#pragma warning( default : 4101 )
#pragma warning( default : 4057 )
#pragma warning( default : 4244 )
#pragma warning( default : 4127 )

/* #pragma warning( default : 4514 ) this warning remains disabled */

#ifndef BOOL
typedef int BOOL;
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE !TRUE
#endif

/* Define dummies for the driver */
typedef int HFILE;
typedef unsigned int WPARAM;
typedef unsigned long LPARAM;
#define CALLBACK

#define e4malloc(size) ((void *) ExAllocatePool( NonPagedPool, size ))

#define e4mfree(memblock) ExFreePool( memblock )

#endif				/* NT4_DRIVER */


#pragma hdrstop
