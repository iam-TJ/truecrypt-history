/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"
#include "crypto.h"
#include "fat.h"
#include "volumes1.h"

#include "apidrvr.h"
#include "ntdriver.h"
#include "ntvol.h"
#include "ntrawdv.h"
#include "ntfiledv.h"

#include "cache.h"

#ifdef _DEBUG
#define EXTRA_INFO 1
#endif

#pragma warning( disable : 4127 )

#define FIRST_READ_SIZE SECTOR_SIZE*2

NTSTATUS
E4MOpenVolume (PDEVICE_OBJECT DeviceObject,
	       PEXTENSION Extension,
	       MOUNT_STRUCT * mount,
	       PWSTR pwszMountVolume,
	       BOOL bRawDevice)
{
	struct msdos_boot_sector *boot_sector = NULL;
	FILE_STANDARD_INFORMATION FileStandardInfo;
	FILE_BASIC_INFORMATION FileBasicInfo;
	OBJECT_ATTRIBUTES oaFileAttributes;
	UNICODE_STRING FullFileName;
	IO_STATUS_BLOCK IoStatusBlock;
	LARGE_INTEGER lDiskLength;
	char *readBuffer;
	NTSTATUS ntStatus;

	Extension->pfoDeviceFile = NULL;
	Extension->hDeviceFile = NULL;

	readBuffer = e4malloc (FIRST_READ_SIZE);
	if (readBuffer == NULL)
	{
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	RtlInitUnicodeString (&FullFileName, pwszMountVolume);

	InitializeObjectAttributes (&oaFileAttributes, &FullFileName, OBJ_CASE_INSENSITIVE,
				    NULL, NULL);

	ntStatus = ZwCreateFile (&Extension->hDeviceFile,
				 GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
				 &oaFileAttributes,
				 &IoStatusBlock,
				 NULL,
				 FILE_ATTRIBUTE_NORMAL |
				 FILE_ATTRIBUTE_SYSTEM,
				 0,
				 FILE_OPEN,
				 FILE_WRITE_THROUGH |
				 FILE_NO_INTERMEDIATE_BUFFERING |
				 FILE_SYNCHRONOUS_IO_NONALERT,
				 NULL,
				 0);

	/* 26-4-99 NT for some partitions returns this code, it is really a
	   access denied */
	if (ntStatus == 0xc000001b)
	{
		ntStatus = STATUS_ACCESS_DENIED;
	}

	if (ntStatus == STATUS_ACCESS_DENIED)
	{
		ntStatus = ZwCreateFile (&Extension->hDeviceFile,
					 GENERIC_READ | SYNCHRONIZE,
					 &oaFileAttributes,
					 &IoStatusBlock,
					 NULL,
					 FILE_ATTRIBUTE_NORMAL |
					 FILE_ATTRIBUTE_SYSTEM,
					 0,
					 FILE_OPEN,
					 FILE_WRITE_THROUGH |
					 FILE_NO_INTERMEDIATE_BUFFERING |
					 FILE_SYNCHRONOUS_IO_NONALERT,
					 NULL,
					 0);
		Extension->bReadOnly = TRUE;
	}
	else
		Extension->bReadOnly = FALSE;

	/* 26-4-99 NT for some partitions returns this code, it is really a
	   access denied */
	if (ntStatus == 0xc000001b)
	{
		/* Partitions which return this code can still be opened with
		   FILE_SHARE_READ but this causes NT problems elsewhere in
		   particular if you do FILE_SHARE_READ NT will die later if
		   anyone even tries to open the partition  (or file for that
		   matter...)  */
		ntStatus = STATUS_SHARING_VIOLATION;
	}

	if (!NT_SUCCESS (ntStatus))
	{
		goto error;
	}

	ntStatus = ZwReadFile (Extension->hDeviceFile, NULL, NULL, NULL,
		   &IoStatusBlock, readBuffer, FIRST_READ_SIZE, NULL, NULL);

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("Read failed: NTSTATUS 0x%08x\n", ntStatus);
	}
	else if (IoStatusBlock.Information != FIRST_READ_SIZE)
	{
		Dump ("Read didn't read enough data in: %lu / %lu\n", IoStatusBlock.Information, FIRST_READ_SIZE);
		ntStatus = STATUS_UNSUCCESSFUL;
	}

	if (!NT_SUCCESS (ntStatus))
	{
		goto error;
	}


	KeInitializeEvent (&Extension->keVolumeEvent, NotificationEvent, FALSE);

	if (bRawDevice == FALSE)
	{
		ntStatus = ZwQueryInformationFile (Extension->hDeviceFile,
						   &IoStatusBlock,
						   &FileBasicInfo,
						   sizeof (FileBasicInfo),
						   FileBasicInformation);

		if (NT_SUCCESS (ntStatus))
			ntStatus = ZwQueryInformationFile (Extension->hDeviceFile,
							   &IoStatusBlock,
							   &FileStandardInfo,
						  sizeof (FileStandardInfo),
						   FileStandardInformation);

		if (!NT_SUCCESS (ntStatus))
		{
			Dump ("ZwQueryInformationFile failed while opening file: NTSTATUS 0x%08x\n",
			      ntStatus);
			goto error;
		}
		else
			lDiskLength.QuadPart = FileStandardInfo.EndOfFile.QuadPart;

		if (FileBasicInfo.FileAttributes & FILE_ATTRIBUTE_COMPRESSED)
		{
			Dump ("File \"%ls\" is marked as compressed - not supported!\n", pwszMountVolume);
			mount->nReturnCode = ERR_COMPRESSION_NOT_SUPPORTED;
			ntStatus = STATUS_SUCCESS;
			goto error;
		}

		ntStatus = ObReferenceObjectByHandle (Extension->hDeviceFile,
						      FILE_ALL_ACCESS,
						      *IoFileObjectType,
						      KernelMode,
						  &Extension->pfoDeviceFile,
						      0);

		if (!NT_SUCCESS (ntStatus))
		{
			goto error;
		}

		/* Get the FSD device for the file (probably either NTFS or
		   FAT) */
		Extension->pFsdDevice = IoGetRelatedDeviceObject (Extension->pfoDeviceFile);

		DeviceObject->StackSize = (CCHAR) (Extension->pFsdDevice->StackSize + 1);

	}
	else
	{
		DISK_GEOMETRY dg;

		ZwClose (Extension->hDeviceFile);
		Extension->hDeviceFile = NULL;

		if (Extension->bReadOnly == TRUE)
			ntStatus = IoGetDeviceObjectPointer (&FullFileName,
							     FILE_READ_DATA,
						  &Extension->pfoDeviceFile,
						    &Extension->pFsdDevice);
		else
			ntStatus = IoGetDeviceObjectPointer (&FullFileName,
							     FILE_ALL_ACCESS,
						  &Extension->pfoDeviceFile,
						    &Extension->pFsdDevice);

		if (!NT_SUCCESS (ntStatus))
		{
			goto error;
		}

		DeviceObject->StackSize = (CCHAR) (Extension->pFsdDevice->StackSize + 1);


		if (wcscmp (Extension->pFsdDevice->DriverObject->DriverName.Buffer, WIDE ("\\FileSystem\\RAW")) != 0)
		{
			/* FAT/NTFS  "knows" about this device */
			ntStatus = STATUS_SHARING_VIOLATION;
			goto error;
		}

		ntStatus = E4MSendDeviceIoControlRequest (DeviceObject,
				   Extension, IOCTL_DISK_GET_DRIVE_GEOMETRY,
						 (char *) &dg, sizeof (dg));

		if (!NT_SUCCESS (ntStatus))
		{
			goto error;
		}

		if (dg.MediaType == FixedMedia)
		{
			PARTITION_INFORMATION pi;

			ntStatus = E4MSendDeviceIoControlRequest (DeviceObject,
				   Extension, IOCTL_DISK_GET_PARTITION_INFO,
						 (char *) &pi, sizeof (pi));

			if (!NT_SUCCESS (ntStatus))
			{
				goto error;
			}
			else
				lDiskLength.QuadPart = pi.PartitionLength.QuadPart;

		}
		else
		{
			lDiskLength.QuadPart = dg.Cylinders.QuadPart * dg.SectorsPerTrack *
				dg.TracksPerCylinder * dg.BytesPerSector;
		}


	}

	if (lDiskLength.QuadPart < MIN_VOLUME_SIZE || lDiskLength.QuadPart > MAX_VOLUME_SIZE)
	{
		/* Volume too large or too small for us to handle... */
		mount->nReturnCode = ERR_VOL_SIZE_WRONG;
		ntStatus = STATUS_SUCCESS;
		goto error;
	}
	else
		Extension->DiskLength = lDiskLength.LowPart;

	/* Save away the real boot sector, because if this turns out to be an
	   SFS volume then we need this information later, if this is a E4M
	   volume the info is not needed */
	memcpy (Extension->sfs_true_boot_sector, readBuffer, SECTOR_SIZE);

	/* Attempt to recognize the volume */

	KeWaitForMutexObject (&driverMutex, Executive, KernelMode,
			      FALSE, NULL);

	mount->nReturnCode = VolumeReadHeaderCache (
							   mount->bCache,
							   readBuffer,
						       &Extension->nVolType,
							   mount->szPassword,
						 strlen (mount->szPassword),
						    &Extension->cryptoInfo);

	KeReleaseMutex (&driverMutex, FALSE);

	if (mount->nReturnCode == 0)
	{
		if (Extension->nVolType == SFS_VOLTYPE)
		{
			/* Handle the volume setup for SFS */

			/* The boot sector has been decrypted */
			boot_sector = (struct msdos_boot_sector *) readBuffer;

			memcpy (Extension->sfs_fake_boot_sector, boot_sector, SECTOR_SIZE);

			/* Volume setup end */
		}
		else if (isE4M (Extension->nVolType) == TRUE)
		{
			/* Handle the volume setup for E4M */

			boot_sector = (struct msdos_boot_sector *) (readBuffer + SECTOR_SIZE);

			/* It's in the volume file so we must decrypt it */
			Extension->cryptoInfo->decrypt_sector ((ULONG *) boot_sector, 1, 1,
					      &Extension->cryptoInfo->ks[0],
						  Extension->cryptoInfo->iv,
					     Extension->cryptoInfo->cipher);


			/* There's one extra sector than there should be */
			Extension->DiskLength -= SECTOR_SIZE;

			/* Volume setup end */
		}
		else
		{
			ASSERT (0);
		}

		Extension->TracksPerCylinder = boot_sector->heads;
		Extension->SectorsPerTrack = boot_sector->secs_track;
		Extension->BytesPerSector = *((unsigned short *) boot_sector->sector_size);
		Extension->NumberOfCylinders = Extension->DiskLength / Extension->BytesPerSector /
			Extension->SectorsPerTrack / Extension->TracksPerCylinder;
		Extension->PartitionType = (UCHAR) ((boot_sector->fs_type[4] == '6') ?
				       PARTITION_FAT_16 : PARTITION_FAT_12);

		Extension->bRawDevice = bRawDevice;

		if (wcslen (pwszMountVolume) < 64)
			wcscpy (Extension->wszVolume, pwszMountVolume);
		else
		{
			memcpy (Extension->wszVolume, pwszMountVolume, 60 * 2);
			Extension->wszVolume[60] = (WCHAR) '.';
			Extension->wszVolume[61] = (WCHAR) '.';
			Extension->wszVolume[62] = (WCHAR) '.';
			Extension->wszVolume[63] = (WCHAR) 0;
		}

		Extension->mountTime = mount->time;

		e4mfree (readBuffer);

		return STATUS_SUCCESS;
	}


	/* Failed due to some non-OS reason so we drop through and return NT
	   SUCCESS then nReturnCode is checked later in user-mode */

	if (mount->nReturnCode == ERR_OUTOFMEMORY)
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	else
		ntStatus = STATUS_SUCCESS;

      error:

	/* Close the hDeviceFile */
	if (Extension->hDeviceFile != NULL)
		ZwClose (Extension->hDeviceFile);

	/* The cryptoInfo pointer is deallocated if the readheader routines
	   fail so there is no need to deallocate here  */

	/* Dereference the user-mode file object */
	if (Extension->pfoDeviceFile != NULL)
		ObDereferenceObject (Extension->pfoDeviceFile);

	/* Free the tmp IO buffer */
	if (readBuffer != NULL)
		e4mfree (readBuffer);

	return ntStatus;
}

void
E4MCloseVolume (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension)
{
	if (DeviceObject);	/* Remove compiler warning */

	if (Extension->hDeviceFile != NULL)
		ZwClose (Extension->hDeviceFile);
	ObDereferenceObject (Extension->pfoDeviceFile);
	crypto_close (Extension->cryptoInfo);

}

/* This rountine can be called at any IRQL so we need to tread carefully. Not
   even DbgPrint or KdPrint are called here as the kernel sometimes faults if
   they are called at high IRQL */

NTSTATUS
E4MCompletion (PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID pUserBuffer)
{
	PIO_STACK_LOCATION irpSp;
	PEXTENSION Extension;
	NTSTATUS ntStatus;

	Extension = (PEXTENSION) DeviceObject->DeviceExtension;

	/* Check to make sure the DeviceObject passed in is actually ours! */
	if (Extension->lMagicNumber != 0xabfeacde)
		KeBugCheck ((ULONG) 0xabfeacde);

	ASSERT (Extension->nDosDriveNo >= 0 && Extension->nDosDriveNo <= 0x19);

#ifdef USE_KERNEL_MUTEX
	KeWaitForMutexObject (&Extension->KernelMutex, Executive, KernelMode,
			      FALSE, NULL);
#endif

#if EXTRA_INFO
	Dump ("Completing IRP...BEGIN\n");
	Dump ("COMPLETION USER BUFFER IS 0x%08x MDL ADDRESS IS 0x%08x\n", Irp->UserBuffer, Irp->MdlAddress);
	Dump ("COMPLETION Irp->Tail.Overlay.OriginalFileObject = 0x%08x\n", Irp->Tail.Overlay.OriginalFileObject);
	Dump ("Completing DeviceObject 0x%08x Irp 0x%08x\n", DeviceObject, Irp);
#endif

	/* Note: The Irp stack location we get back here is our one, we setup
	   the next stack location with a copy of this stack data in the send
	   function... here we always get back our own stack location, so
	   it's possible to use Read.Key to store extra pointers if needed. */
	irpSp = IoGetCurrentIrpStackLocation (Irp);

	ntStatus = Irp->IoStatus.Status;

	if (ntStatus == STATUS_TOO_LATE)
		KeBugCheck ((ULONG) 0x50ff);

	if (Irp->PendingReturned)	/* From Windows NT File System
					   Internals */
		IoMarkIrpPending (Irp);

	if (Extension->bRawDevice == FALSE)
	{
		/* Note: For some reason even though we used DIRECT_IO
		   sometimes the Irp's come back to use with MDLs !! if we
		   get an MDL here we need to free it up otherwise later when
		   we call IoFreeIrp the system will trap */

		PMDL pMdl, pNextMdl;

		pMdl = Irp->MdlAddress;

		while (pMdl != NULL)
		{
			pNextMdl = pMdl->Next;

			MmUnmapLockedPages (MmGetSystemAddressForMdl (pMdl), pMdl);
			MmUnlockPages (pMdl);
			IoFreeMdl (pMdl);

			pMdl = pNextMdl;
		}
	}

	if (NT_SUCCESS (Irp->IoStatus.Status) && irpSp->MajorFunction == IRP_MJ_READ)
	{
		ULONG tmpOffset = irpSp->Parameters.Read.ByteOffset.LowPart;
		ULONG tmpLength = irpSp->Parameters.Read.Length;
		PUCHAR CurrentAddress;

		if (Extension->bRawDevice == TRUE)
			CurrentAddress = MmGetSystemAddressForMdl (Irp->MdlAddress);
		else
			CurrentAddress = Irp->UserBuffer;

		if (Extension->nVolType == SFS_VOLTYPE && tmpOffset == 0)
		{
			/* Return the fake boot sector back to Windows NT */
			memcpy (CurrentAddress, Extension->sfs_fake_boot_sector, SECTOR_SIZE);
			tmpOffset += SECTOR_SIZE;
			tmpLength -= SECTOR_SIZE;
			CurrentAddress += SECTOR_SIZE;
		}

		if (tmpLength > 0)
		{
			ULONG secNum;

			secNum = tmpOffset / SECTOR_SIZE;

			/* Decrypt the data on read */
			Extension->cryptoInfo->decrypt_sector ((ULONG *) CurrentAddress,
							       secNum,
						    tmpLength / SECTOR_SIZE,
					      &Extension->cryptoInfo->ks[0],
						  Extension->cryptoInfo->iv,
					     Extension->cryptoInfo->cipher);

		}

		if (Extension->bRawDevice == FALSE)
		{
			PIRP OldIrp = (PIRP) pUserBuffer;
			PUCHAR OriginalAddress;
			CurrentAddress = Irp->UserBuffer;
			OriginalAddress = MmGetSystemAddressForMdl (OldIrp->MdlAddress);
			memcpy (OriginalAddress, CurrentAddress, Irp->IoStatus.Information);
		}

	}

	if (NT_SUCCESS (Irp->IoStatus.Status) && irpSp->MajorFunction == IRP_MJ_WRITE)
	{
		PUCHAR CurrentAddress;
		PUCHAR OriginalAddress;

		if (Extension->bRawDevice == TRUE)
		{
			CurrentAddress = MmGetSystemAddressForMdl (Irp->MdlAddress);
			OriginalAddress = MmGetSystemAddressForMdl ((PMDL) pUserBuffer);
		}
		else
		{
			PIRP OldIrp = (PIRP) pUserBuffer;
			CurrentAddress = Irp->UserBuffer;
			OriginalAddress = MmGetSystemAddressForMdl (OldIrp->MdlAddress);
		}

		if (NT_SUCCESS (Irp->IoStatus.Status))
		{
			ULONG tmpOffset = irpSp->Parameters.Read.ByteOffset.LowPart;

			if (Extension->nVolType == SFS_VOLTYPE && tmpOffset == 0)
			{
				/* Copy the boot sector Windows NT tried to
				   write to begin with into the fake boot
				   sector area, next time Windows NT reads
				   the boot sector it will actually get the
				   fake area updated with whatever it tried
				   to write here! */
				memcpy (Extension->sfs_fake_boot_sector, OriginalAddress, SECTOR_SIZE);
			}
		}
	}

	if (Extension->bRawDevice == TRUE && irpSp->MajorFunction == IRP_MJ_WRITE)
	{
		PUCHAR tmpBuffer = MmGetSystemAddressForMdl (Irp->MdlAddress);
		/* Free the temp buffer we allocated */
		e4mfree (tmpBuffer);
		/* Free the Mdl we allocated */
		IoFreeMdl (Irp->MdlAddress);
		/* Reset the Irp */
		Irp->MdlAddress = pUserBuffer;
	}

	if (Extension->bRawDevice == TRUE && irpSp->MajorFunction == IRP_MJ_READ)
	{
		/* Nothing to do */
	}

#if EXTRA_INFO
	Dump ("COMPLETION OLD USER BUFFER IS 0x%08x MDL ADDRESS IS 0x%08x\n", Irp->UserBuffer, Irp->MdlAddress);
	Dump ("COMPLETION OLD Irp->Tail.Overlay.OriginalFileObject = 0x%08x\n", Irp->Tail.Overlay.OriginalFileObject);
	Dump ("Completing IRP 0x%08x NTSTATUS 0x%08x information %lu END\n", (ULONG) irpSp->MajorFunction,
	      Irp->IoStatus.Status, Irp->IoStatus.Information);
#endif

	if (Extension->bRawDevice == FALSE)
	{
		PIRP OldIrp = (PIRP) pUserBuffer;
		PVOID tmpBuffer = Irp->UserBuffer;
		BOOL bFreeBuffer = irpSp->MajorFunction == IRP_MJ_WRITE || irpSp->MajorFunction == IRP_MJ_READ;

		OldIrp->IoStatus.Status = Irp->IoStatus.Status;
		OldIrp->IoStatus.Information = Irp->IoStatus.Information;

		IoCompleteRequest (OldIrp, IO_DISK_INCREMENT);

#if EXTRA_INFO
		Dump ("About to free allocated IRP\n");
#endif

		Irp->UserBuffer = NULL;

		/* Free the allocated IRP. Note: This must be done before we
		   free tmpBuffer! */
		IoFreeIrp (Irp);

		/* Note: From here on we cannot touch the Irp or irpSp */

#if EXTRA_INFO
		Dump ("Free allocated buffer = %d\n", bFreeBuffer);
#endif

		if (bFreeBuffer == TRUE)
			e4mfree (tmpBuffer);

		ntStatus = STATUS_MORE_PROCESSING_REQUIRED;
	}

#ifdef USE_KERNEL_MUTEX
	KeReleaseMutex (&Extension->KernelMutex, FALSE);
#endif

	return ntStatus;
}

NTSTATUS
E4MReadWrite (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	PUCHAR tmpBuffer = NULL;/* Remove compiler warning */
	NTSTATUS ntStatus;

	Dump ("E4MReadWrite BEGIN\n");

	/* Check for invalid parameters.  It is an error for the starting
	   offset + length to go past the end of the buffer, or for the
	   length to not be a proper multiple of the sector size. Others are
	   possible, but we don't check them since we trust the file system
	   and they aren't deadly.  */
	if (RtlLargeIntegerGreaterThan (RtlLargeIntegerAdd (
								   RtlConvertUlongToLargeInteger (irpSp->Parameters.Read.ByteOffset.LowPart),
	     RtlConvertUlongToLargeInteger (irpSp->Parameters.Read.Length)),
		   RtlConvertUlongToLargeInteger (Extension->DiskLength)) ||
	  (irpSp->Parameters.Read.Length & (Extension->BytesPerSector - 1)))
	{
		return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
	}
	else
	{
		if (irpSp->Parameters.Read.Length == 0)
		{
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_INVALID_PARAMETER, 0);
		}
	}

#if EXTRA_INFO
	Dump ("USER BUFFER IS 0x%08x MDL ADDRESS IS 0x%08x\n", Irp->UserBuffer, Irp->MdlAddress);
	Dump ("Irp->Tail.Overlay.OriginalFileObject = 0x%08x\n", Irp->Tail.Overlay.OriginalFileObject);
	Dump ("irpSp->FileObject = 0x%08x\n", irpSp->FileObject);

	if (Irp->Tail.Overlay.OriginalFileObject != NULL)
	{
		if (Irp->Tail.Overlay.OriginalFileObject->FileName.Length != 0)
			Dump ("Irp->Tail.Overlay.OriginalFileObject = %ls\n", Irp->Tail.Overlay.OriginalFileObject->FileName.Buffer);
		else
			Dump ("Irp->Tail.Overlay.OriginalFileObject = %ls\n", WIDE ("null value"));

	}

	if (irpSp->FileObject != NULL)
	{
		if (irpSp->FileObject->FileName.Length != 0)
			Dump ("irpSp->FileObject = %ls\n", irpSp->FileObject->FileName.Buffer);
		else
			Dump ("irpSp->FileObject = %ls\n", WIDE ("null value"));

	}
#endif

	if (Extension->bReadOnly == TRUE && irpSp->MajorFunction == IRP_MJ_WRITE)
		return COMPLETE_IRP (DeviceObject, Irp, STATUS_MEDIA_WRITE_PROTECTED, 0);

	if (Extension->bRawDevice == FALSE || irpSp->MajorFunction == IRP_MJ_WRITE)
	{
		tmpBuffer = e4malloc (irpSp->Parameters.Read.Length);
		if (tmpBuffer == NULL)
			return COMPLETE_IRP (DeviceObject, Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
	}

	if (irpSp->MajorFunction == IRP_MJ_READ)
	{
		Dump ("Read: 0x%08x for %lu bytes...\n", irpSp->Parameters.Read.ByteOffset.LowPart,
		      irpSp->Parameters.Read.Length);

		/* Fixup the parameters to handle this particular volume type */
		if (isE4M (Extension->nVolType) == TRUE)
			irpSp->Parameters.Read.ByteOffset.LowPart += SECTOR_SIZE;

		if (Extension->bRawDevice == TRUE)
			ntStatus = E4MSendIRP_RawDevice (DeviceObject, Extension,
				     NULL, IRP_READ_OPERATION | IRP_NOCACHE,
						       irpSp->MajorFunction,
							 Irp);
		else
			ntStatus = E4MSendIRP_FileDevice (DeviceObject, Extension,
				tmpBuffer, IRP_READ_OPERATION | IRP_NOCACHE,
						       irpSp->MajorFunction,
							  Irp);
	}
	else
	{
		PUCHAR CurrentAddress;

		Dump ("Write: 0x%08x for %lu bytes...\n", irpSp->Parameters.Read.ByteOffset.LowPart,
		      irpSp->Parameters.Read.Length);

		CurrentAddress = (PUCHAR) MmGetSystemAddressForMdl (Irp->MdlAddress);

		/* Fixup the parameters to handle this particular volume type */
		if (isE4M (Extension->nVolType) == TRUE)
			irpSp->Parameters.Read.ByteOffset.LowPart += SECTOR_SIZE;

		memcpy (tmpBuffer, CurrentAddress, irpSp->Parameters.Read.Length);

		if (Extension->nVolType == SFS_VOLTYPE && irpSp->Parameters.Read.ByteOffset.LowPart == 0)
		{
			memcpy (tmpBuffer, Extension->sfs_true_boot_sector, SECTOR_SIZE);

			if (irpSp->Parameters.Read.Length > SECTOR_SIZE)
			{
				/* Encrypt the data */
				Extension->cryptoInfo->encrypt_sector ((ULONG *) (tmpBuffer + SECTOR_SIZE),
								       (irpSp->Parameters.Read.ByteOffset.LowPart + SECTOR_SIZE) / SECTOR_SIZE,
								       (irpSp->Parameters.Read.Length - SECTOR_SIZE) / SECTOR_SIZE,
					      &Extension->cryptoInfo->ks[0],
						  Extension->cryptoInfo->iv,
					     Extension->cryptoInfo->cipher);
			}
		}
		else
		{
			ULONG secNum;

			secNum = irpSp->Parameters.Read.ByteOffset.LowPart / SECTOR_SIZE;

			/* Encrypt the data */
			Extension->cryptoInfo->encrypt_sector ((ULONG *) tmpBuffer,
			secNum, irpSp->Parameters.Read.Length / SECTOR_SIZE,
					      &Extension->cryptoInfo->ks[0],
						  Extension->cryptoInfo->iv,
					     Extension->cryptoInfo->cipher);

		}

		if (Extension->bRawDevice == TRUE)
		{
			PMDL tmpBufferMdl = IoAllocateMdl (tmpBuffer, irpSp->Parameters.Read.Length, FALSE, FALSE, NULL);
			PMDL pTrueMdl = Irp->MdlAddress;

			if (tmpBufferMdl == NULL)
			{
				e4mfree (tmpBuffer);
				return COMPLETE_IRP (DeviceObject, Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
			}

			MmBuildMdlForNonPagedPool (tmpBufferMdl);

			Irp->MdlAddress = tmpBufferMdl;

#if EXTRA_INFO
			Dump ("NEW MDL ADDRESS IS 0x%08x UserBuffer = 0x%08x\n", Irp->MdlAddress, Irp->UserBuffer);
#endif

			ntStatus = E4MSendIRP_RawDevice (DeviceObject, Extension,
				pTrueMdl, IRP_WRITE_OPERATION | IRP_NOCACHE,
						       irpSp->MajorFunction,
							 Irp);
		}
		else
		{
			ntStatus = E4MSendIRP_FileDevice (DeviceObject, Extension,
			       tmpBuffer, IRP_WRITE_OPERATION | IRP_NOCACHE,
						       irpSp->MajorFunction,
							  Irp);
		}

	}

	Dump ("E4MReadWrite END\n");
	return ntStatus;
}

NTSTATUS
E4MSendDeviceIoControlRequest (PDEVICE_OBJECT DeviceObject,
			       PEXTENSION Extension,
			       ULONG IoControlCode,
			       char *OutputBuffer,
			       int OutputBufferSize)
{
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS ntStatus;
	PIRP Irp;

	if (DeviceObject);	/* Remove compiler warning */

	KeClearEvent (&Extension->keVolumeEvent);

	Irp = IoBuildDeviceIoControlRequest (IoControlCode,
					     Extension->pFsdDevice,
					     NULL, 0,
					     OutputBuffer, OutputBufferSize,
					     FALSE,
					     &Extension->keVolumeEvent,
					     &IoStatusBlock);

	if (Irp == NULL)
	{
		Dump ("IRP allocation failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = IoCallDriver (Extension->pFsdDevice, Irp);
	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject (&Extension->keVolumeEvent, UserRequest, UserMode, FALSE, NULL);
		ntStatus = IoStatusBlock.Status;
	}

	return ntStatus;
}

NTSTATUS
COMPLETE_IRP (PDEVICE_OBJECT DeviceObject,
	      PIRP Irp,
	      NTSTATUS IrpStatus,
	      ULONG IrpInformation)
{
	Irp->IoStatus.Status = IrpStatus;
	Irp->IoStatus.Information = IrpInformation;

	if (DeviceObject);	/* Remove compiler warning */

#ifdef _DEBUG
	if (!NT_SUCCESS (IrpStatus))
	{
		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
		Dump ("COMPLETE_IRP FAILING IRP %ls Flags 0x%08x vpb 0x%08x NTSTATUS 0x%08x\n", E4MTranslateCode (irpSp->MajorFunction),
		      (ULONG) DeviceObject->Flags, (ULONG) DeviceObject->Vpb->Flags, IrpStatus);
	}
	else
	{
		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
		Dump ("COMPLETE_IRP SUCCESS IRP %ls Flags 0x%08x vpb 0x%08x NTSTATUS 0x%08x\n", E4MTranslateCode (irpSp->MajorFunction),
		      (ULONG) DeviceObject->Flags, (ULONG) DeviceObject->Vpb->Flags, IrpStatus);
	}
#endif
	IoCompleteRequest (Irp, IO_NO_INCREMENT);
	return IrpStatus;
}
