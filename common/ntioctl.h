/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

/* DeviceIoControl values.

*/

#ifndef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#ifndef FILE_DEVICE_DISK
#define FILE_DEVICE_DISK 0x00000007
#endif

#ifndef IOCTL_DISK_BASE
#define IOCTL_DISK_BASE FILE_DEVICE_DISK
#endif

#define E4M_FIRST_PRIVATE CTL_CODE(IOCTL_DISK_BASE, 0x800, METHOD_BUFFERED, \
	FILE_ANY_ACCESS)

#define E4M_MOUNT CTL_CODE(IOCTL_DISK_BASE, 0x800, METHOD_BUFFERED, \
	FILE_ANY_ACCESS)

#define E4M_MOUNT_LIST CTL_CODE(IOCTL_DISK_BASE, 0x801, METHOD_BUFFERED, \
	FILE_ANY_ACCESS)

#define E4M_OPEN_TEST CTL_CODE(IOCTL_DISK_BASE, 0x802, METHOD_BUFFERED, \
	FILE_ANY_ACCESS)

#define E4M_UNMOUNT CTL_CODE(IOCTL_DISK_BASE, 0x803, METHOD_BUFFERED, \
	FILE_ANY_ACCESS)

#define E4M_WIPE_CACHE CTL_CODE(IOCTL_DISK_BASE, 0x804, METHOD_BUFFERED, \
	FILE_ANY_ACCESS)

#ifdef DEBUG
#define E4M_HALT_SYSTEM CTL_CODE(IOCTL_DISK_BASE, 0x805, METHOD_BUFFERED, \
	FILE_ANY_ACCESS)
#endif

#define E4M_UNMOUNT_PENDING CTL_CODE(IOCTL_DISK_BASE, 0xffa, METHOD_BUFFERED, \
	FILE_ANY_ACCESS)

#define E4M_LAST_PRIVATE CTL_CODE(IOCTL_DISK_BASE, 0xffa, METHOD_BUFFERED, \
	FILE_ANY_ACCESS)


/* This last private code allowed by Windows NT is 0xfff */

typedef struct
{
  int nReturnCode;		/* Return code back from driver */
  WCHAR wszVolume[E4M_MAX_PATH];/* Volume to be mounted */
  char szPassword[MAX_PASSWORD + 1];	/* User password or SHA1 hash */
  int nPasswordLen;		/* User password length */
  BOOL bCache;			/* Cache passwords in driver */
  BOOL bSD;
  int nDosDriveNo;		/* Drive number to mount */
  long time;			/* Time when this volume was mounted */
} E4M_NT_MOUNT;

typedef struct
{
  int nReturnCode;
  int nDosDriveNo;		/* Drive letter to unmount */
} E4M_NT_UNMOUNT;

typedef struct
{
  unsigned long ulMountedDrives;/* Bitfield of all mounted drive letters */
  WCHAR wszVolume[26][64];	/* Volume names of mounted volumes */
} E4M_NT_MOUNT_LIST;

typedef struct
{
  WCHAR wszFileName[E4M_MAX_PATH];	/* Volume to be "open tested" */
} E4M_NT_OPEN_TEST;

#ifdef NT4_DRIVER
#define DRIVER_STR WIDE
#else
#define DRIVER_STR
#endif

#define NT_MOUNT_PREFIX DRIVER_STR("\\Device\\E4MV200")
#define NT_ROOT_PREFIX DRIVER_STR("\\Device\\E4MRootV200")
#define DOS_MOUNT_PREFIX DRIVER_STR("\\DosDevices\\")
#define DOS_ROOT_PREFIX DRIVER_STR("\\DosDevices\\E4MRootV200")
#define WIN32_ROOT_PREFIX DRIVER_STR("\\\\.\\E4MRootV200")
