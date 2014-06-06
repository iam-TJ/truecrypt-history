/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

/* Everything below this line is automatically updated by the -mkproto-tool- */

NTSTATUS E4MOpenVolume ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension , MOUNT_STRUCT *mount , PWSTR pwszMountVolume , BOOL bRawDevice );
void E4MCloseVolume ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension );
NTSTATUS E4MCompletion ( PDEVICE_OBJECT DeviceObject , PIRP Irp , PVOID pUserBuffer );
NTSTATUS E4MReadWrite ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension , PIRP Irp );
NTSTATUS E4MSendDeviceIoControlRequest ( PDEVICE_OBJECT DeviceObject , PEXTENSION Extension , ULONG IoControlCode , char *OutputBuffer , int OutputBufferSize );
NTSTATUS COMPLETE_IRP ( PDEVICE_OBJECT DeviceObject , PIRP Irp , NTSTATUS IrpStatus , ULONG IrpInformation );
