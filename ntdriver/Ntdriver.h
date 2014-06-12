/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

/* This structure is used to start new threads */
typedef struct _THREAD_BLOCK_
{
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS ntCreateStatus;
	WCHAR wszMountVolume[E4M_MAX_PATH];
	MOUNT_STRUCT *mount;
} THREAD_BLOCK, *PTHREAD_BLOCK;

/* This structure is allocated for non-root devices! WARNING: bRootDevice
   must be the first member of the structure! */
typedef struct EXTENSION
{
	BOOL bRootDevice;	/* Is this the root device ? which the
				   user-mode apps talk to */

	ULONG lMagicNumber;	/* To ensure the completion routine is not
				   sending us bad IRP's */

	int nDosDriveNo;	/* Drive number this extension is mounted
				   against */
	BOOL bShuttingDown;	/* Is the driver shutting down ? */
	BOOL bThreadShouldQuit;	/* Instruct per device worker thread to quit */
	PETHREAD peThread;	/* Thread handle */
	KEVENT keCreateEvent;	/* Device creation event */
	KSPIN_LOCK ListSpinLock;/* IRP spinlock */
	LIST_ENTRY ListEntry;	/* IRP listentry */
	KSEMAPHORE RequestSemaphore;	/* IRP list request  Semaphore */

#ifdef USE_KERNEL_MUTEX
	KMUTEX KernelMutex;	/* Sync. mutex for entire thread */
#endif

	HANDLE hDeviceFile;	/* Device handle for this device */
	PFILE_OBJECT pfoDeviceFile;	/* Device fileobject for this device */
	PDEVICE_OBJECT pFsdDevice;	/* lower level device handle */

	CRYPTO_INFO *cryptoInfo;/* Cryptographic information for this device */
	ULONG DiskLength;	/* The length of the disk referred to by this
				   device */
	ULONG NumberOfCylinders;/* Partition info */
	ULONG TracksPerCylinder;/* Partition info */
	ULONG SectorsPerTrack;	/* Partition info */
	ULONG BytesPerSector;	/* Partition info */
	UCHAR PartitionType;	/* Partition info */

	KEVENT keVolumeEvent;	/* Event structure used when setting up a
				   device */

	int nVolType;		/* The type of volume sfs, e4m etc... */
	BOOL bReadOnly;		/* Is this device readonly ? */
	BOOL bRawDevice;	/* Is this a raw-partition or raw-floppy
				   device ? */

	WCHAR wszVolume[64];	/* For the tree view in the user-mode
				   application, here we only store 64
				   characters rather than E4M_MAX_PATH to try
				   to keep this structures size down - DONT
				   change this size without also changing
				   MOUNT_LIST_STRUCT! */

	long mountTime;		/* The time this volume was last mounted, for
				   the user-mode application */

	UCHAR sfs_true_boot_sector[SECTOR_SIZE];	/* sfs real boot sector */
	UCHAR sfs_fake_boot_sector[SECTOR_SIZE];	/* the boot sector NT
							   tried to write to the
							   sfs disk, this is
							   needed because NT
							   seems to want to
							   rewrite the boot
							   sector, for sfs disks
							   there is no boot
							   sector, only an
							   in-memory one created
							   when sfs disks are
							   first mounted! */


} EXTENSION, *PEXTENSION;

/* Helper macro returning x seconds in units of 100 nanoseconds */
#define WAIT_SECONDS(x) (x*10000000)

/* In order to see any debug output you will need to run a checked build of
   NT */
#ifdef DEBUG
#define Dump DbgPrint
#else
#define Dump
#endif

/* Sync. mutex for entire driver */
extern KMUTEX driverMutex;

#ifdef USE_KERNEL_MUTEX
#pragma message ("Compiling " __FILE__ " with USE_KERNEL_MUTEX on")
#endif

/* Everything below this line is automatically updated by the -mkproto-tool- */

NTSTATUS DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS E4MDispatchQueueIRP (PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS E4MCreateRootDeviceObject (PDRIVER_OBJECT DriverObject);
NTSTATUS E4MCreateDeviceObject (PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT * ppDeviceObject, int nDosDriveNo);
NTSTATUS E4MDeviceControl (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp);
NTSTATUS E4MStartThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, MOUNT_STRUCT * mount);
void E4MStopThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension);
VOID E4MThreadIRP (PVOID Context);
void E4MGetNTNameFromNumber (LPWSTR ntname, int nDriveNo);
void E4MGetDosNameFromNumber (LPWSTR dosname, int nDriveNo);
LPWSTR E4MTranslateCode (ULONG ulCode);
PDEVICE_OBJECT E4MDeleteDeviceObject (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension);
VOID E4MUnloadDriver (PDRIVER_OBJECT DriverObject);
