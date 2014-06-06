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

#pragma warning( disable : 4127 )

NTSTATUS
E4MSendIRP_RawDevice (PDEVICE_OBJECT DeviceObject,
		      PEXTENSION Extension,
		      PVOID pUserBuffer,
		      ULONG uFlags,
		      UCHAR uMajorFunction,
		      PIRP Irp)
{
	PIO_STACK_LOCATION irpSp;
	PIO_STACK_LOCATION irpNextSp;
	NTSTATUS ntStatus;

	if (uFlags);		/* Remove compiler warning */

	Dump ("Sending IRP...\n");

	irpSp = IoGetCurrentIrpStackLocation (Irp);
	irpNextSp = IoGetNextIrpStackLocation (Irp);

	irpSp->MajorFunction = uMajorFunction;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = Extension->pfoDeviceFile;

	/* Copy our flags down one level, this is to get the proper
	   removable-media handling */
	irpNextSp->Flags = irpSp->Flags;

	/* Setup the lower drivers stack location */
	irpNextSp->MajorFunction = irpSp->MajorFunction;
	irpNextSp->MinorFunction = irpSp->MinorFunction;
	irpNextSp->DeviceObject = irpSp->DeviceObject;
	irpNextSp->FileObject = irpSp->FileObject;
	/* Copy over io parameters, this is a union, so it handles
	   deviceiocontrol & read/write */
	irpNextSp->Parameters.Read.Length = irpSp->Parameters.Read.Length;
	irpNextSp->Parameters.Read.ByteOffset = irpSp->Parameters.Read.ByteOffset;
	irpNextSp->Parameters.Read.Key = irpSp->Parameters.Read.Key;

	IoSetCompletionRoutine (Irp, E4MCompletion, pUserBuffer, TRUE, TRUE, TRUE);
	ntStatus = IoCallDriver (Extension->pFsdDevice, Irp);

	Dump ("IRP Sent!\n");
	return ntStatus;
}
