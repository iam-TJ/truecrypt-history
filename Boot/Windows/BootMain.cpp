/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Crc.h"
#include "Crypto.h"
#include "Password.h"
#include "Volumes.h"

#include "Platform.h"
#include "Bios.h"
#include "BootConfig.h"
#include "BootMain.h"
#include "BootDefs.h"
#include "BootCommon.h"
#include "BootConsoleIo.h"
#include "BootDebug.h"
#include "BootDiskIo.h"
#include "BootEncryptedIo.h"
#include "BootMemory.h"
#include "IntFilter.h"


static void InitScreen ()
{
	ClearScreen();

	Print (" TrueCrypt Boot Loader " VERSION_STRING "             Copyright (C) 2008 TrueCrypt Foundation\r\n");
	PrintRepeatedChar ('\xDC', TC_BIOS_MAX_CHARS_PER_LINE);

	PrintEndl (2);
}


static void PrintMainMenu ()
{
	Print ("    Keyboard Controls:\r\n");
	Print ("    [Esc]  Skip Authentication (Boot Manager)\r\n");
	Print ("    [F8]   "); Print ("Repair Options");

	PrintEndl (3);
}


static bool IsMenuKey (byte scanCode)
{
	return scanCode == TC_MENU_KEY_REPAIR;
}


static bool AskYesNo (const char *message)
{
	Print (message);
	Print ("? (y/n): ");
	while (true)
	{
		switch (GetKeyboardChar())
		{
		case 'y':
		case 'Y':
		case 'z':
			PrintEndl();
			return true;

		case 'n':
		case 'N':
			PrintEndl();
			return false;

		default:
			Beep();
		}
	}
}


static int AskSelection (const char *options[], size_t optionCount)
{
	for (int i = 0; i < optionCount; ++i)
	{
		Print ("["); Print (i + 1); Print ("]    ");
		Print (options[i]);
		PrintEndl();
	}
	Print ("[Esc]  Cancel\r\n\r\n");

	Print ("To select, press 1-9: ");

	char str;

	while (true)
	{
		if (GetString (&str, 1) == 0)
			return 0;

		if (str >= '1' && str <= optionCount + '0')
			return str - '0';

		Beep();
		PrintBackspace();
	}
}


static byte AskPassword (Password &password)
{
	size_t pos = 0;
	byte scanCode;
	byte asciiCode;

	Print ("Enter password: ");

	while (true)
	{
		asciiCode = GetKeyboardChar (&scanCode);

		switch (scanCode)
		{
		case TC_BIOS_KEY_ENTER:
			ClearBiosKeystrokeBuffer();
			PrintEndl();

			password.Length = pos;
			return scanCode;

		case TC_BIOS_KEY_BACKSPACE:
			if (pos > 0)
			{
				if (pos < MAX_PASSWORD)
					PrintBackspace();
				else
					PrintCharAtCusor (' ');

				--pos;
			}
			continue;

		default:
			if (scanCode == TC_BIOS_KEY_ESC || IsMenuKey (scanCode))
			{
				burn (password.Text, sizeof (password.Text));
				ClearBiosKeystrokeBuffer();

				PrintEndl();
				return scanCode;
			}
		}

		if (!IsPrintable (asciiCode) || pos == MAX_PASSWORD)
		{
			Beep();
			continue;
		}

		password.Text[pos++] = asciiCode;
		if (pos < MAX_PASSWORD)
			PrintChar ('*');
		else
			PrintCharAtCusor ('*');
	}
}


static void ExecuteBootSector (byte drive, byte *sectorBuffer)
{
	Print ("Booting...\r\n");
	CopyMemory (sectorBuffer, 0x0000, 0x7c00, TC_LB_SIZE);

	uint32 addr = 0x7c00;
	__asm
	{
		cli
		mov dl, drive
		xor ax, ax
		mov ds, ax
		mov es, ax
		mov ss, ax
		mov sp, 0xffff
		sti
		jmp cs:addr
	}
}


static bool OpenVolume (byte drive, Password &password, CRYPTO_INFO **cryptoInfo, uint32 *headSaltCrc32)
{
	bool status = false;
	uint64 headerSec;
	headerSec.HighPart = 0;
	headerSec.LowPart = TC_BOOT_VOLUME_HEADER_SECTOR;

	AcquireSectorBuffer();
	if (ReadSectors (SectorBuffer, drive, headerSec, 1) != BiosResultSuccess)
		goto ret;

	if (VolumeReadHeader (TRUE, (char *) SectorBuffer, &password, cryptoInfo, nullptr) == 0)
	{
		if (headSaltCrc32)
			*headSaltCrc32 = GetCrc32 (SectorBuffer, PKCS5_SALT_SIZE);
		status = true;
	}

ret:
	ReleaseSectorBuffer();
	return status;
}


static bool CheckMemoryRequirements ()
{
	uint16 codeSeg;
	__asm mov codeSeg, cs
	if (codeSeg == TC_BOOT_LOADER_LOWMEM_SEGMENT)
	{
		PrintError ("Insufficient base memory: ", true, false);

		uint16 memFree;
		__asm
		{
			push es
			xor ax, ax
			mov es, ax
			mov ax, es:[0x413]
			mov memFree, ax
			pop es
		}

		Print (memFree); Print (" KB\r\n");

		return false;
	}

	return true;
}


static bool MountVolume (byte drive, byte &exitKey)
{
	BootArguments *bootArguments = (BootArguments *) TC_BOOT_LOADER_ARGS_OFFSET;
	int incorrectPasswordCount = 0;

	// Open volume header
	while (true)
	{
		exitKey = AskPassword (bootArguments->BootPassword);

		if (exitKey != TC_BIOS_KEY_ENTER)
			return false;

		if (OpenVolume (BootDrive, bootArguments->BootPassword, &BootCryptoInfo, &bootArguments->HeaderSaltCrc32))
			break;

		Print ("Incorrect password.\r\n\r\n");

		if (++incorrectPasswordCount == 5)
		{
			Print ("If you are sure the password is correct, the key data may be damaged. Boot your\r\n"
				   "TrueCrypt Rescue Disk and select 'Repair Options' > 'Restore key data'.\r\n\r\n");
		}
	}

	// Setup boot arguments
	bootArguments->CryptoInfoOffset = (uint16) BootCryptoInfo;
	bootArguments->CryptoInfoLength = sizeof (*BootCryptoInfo);
	bootArguments->BootLoaderVersion = VERSION_NUM;
	TC_SET_BOOT_ARGUMENTS_SIGNATURE	(bootArguments->Signature);

	if (BootCryptoInfo->EncryptedAreaLength.HighPart != 0 || BootCryptoInfo->EncryptedAreaLength.LowPart != 0)
	{
		// Setup virtual encrypted partition
		EncryptedVirtualPartition.Drive = BootDrive;

		EncryptedVirtualPartition.StartSector.HighPart = BootCryptoInfo->EncryptedAreaStart.HighPart;
		EncryptedVirtualPartition.StartSector.LowPart = BootCryptoInfo->EncryptedAreaStart.LowPart;
		EncryptedVirtualPartition.StartSector = EncryptedVirtualPartition.StartSector >> TC_LB_SIZE_BIT_SHIFT_DIVISOR;

		EncryptedVirtualPartition.EndSector.HighPart = BootCryptoInfo->EncryptedAreaLength.HighPart;
		EncryptedVirtualPartition.EndSector.LowPart = BootCryptoInfo->EncryptedAreaLength.LowPart;
		EncryptedVirtualPartition.EndSector = (EncryptedVirtualPartition.EndSector - 1) >> TC_LB_SIZE_BIT_SHIFT_DIVISOR;
		EncryptedVirtualPartition.EndSector = EncryptedVirtualPartition.EndSector + EncryptedVirtualPartition.StartSector;
	}
	else
	{
		// Drive not encrypted
		EncryptedVirtualPartition.Drive = TC_FIRST_BIOS_DRIVE - 1;
	}

	return true;
}


static byte BootEncryptedDrive ()
{
	Partition partition;
	size_t partCount;
	BootCryptoInfo = NULL;

	// Find active partition
	if (GetActivePartition (BootDrive, partition, partCount, false) != BiosResultSuccess || partCount < 1)
	{
		PrintError ("No bootable partition found");
		goto err;
	}

	byte exitKey;
	if (!MountVolume (BootDrive, exitKey))
		return exitKey;
	
	if (!CheckMemoryRequirements ())
	{
		Print ("Try disabling unneeded components (RAID, AHCI, integrated audio card, etc.) in\r\n"
				"BIOS setup menu (invoked by pressing Del or F2 after turning on your computer).\r\n");
#ifndef TC_WINDOWS_BOOT_AES
		Print ("If it does not help, try using the AES encryption algorithm to reduce memory\r\nrequirements.\r\n");
#endif
		goto err;
	}

	if (!InstallInterruptFilters())
		goto err;

	while (true)
	{
		// Execute boot sector of the active partition
		if (ReadSectors (SectorBuffer, partition.Drive, partition.StartSector, 1) == BiosResultSuccess)
		{
			ExecuteBootSector (partition.Drive, SectorBuffer);
		}

		GetKeyboardChar();
	}

err:
	if (BootCryptoInfo)
	{
		crypto_close (BootCryptoInfo);
		BootCryptoInfo = NULL;
	}

	EncryptedVirtualPartition.Drive = TC_FIRST_BIOS_DRIVE - 1;
	memset ((void *) TC_BOOT_LOADER_ARGS_OFFSET, 0, sizeof (BootArguments));

	byte scanCode;
	GetKeyboardChar (&scanCode);
	return scanCode;
}


static void BootMenu ()
{
	BiosResult result;
	Partition partitions[16];
	Partition bootablePartitions[9];
	size_t partitionCount;
	size_t bootablePartitionCount = 0;

	for (byte drive = TC_FIRST_BIOS_DRIVE; drive <= TC_LAST_BIOS_DRIVE; ++drive)
	{
		if (GetDrivePartitions (drive, partitions, array_capacity (partitions), partitionCount, false, true) == BiosResultSuccess)
		{
			for (size_t i = 0; i < partitionCount; ++i)
			{
				const Partition &partition = partitions[i];
				result = ReadSectors (SectorBuffer, drive, partition.StartSector, 1);

				if (result == BiosResultSuccess && *(uint16 *) (SectorBuffer + TC_LB_SIZE - 2) == 0xaa55)
				{
					// Windows writes boot loader on all NTFS/FAT filesytems it creates and, therefore,
					// NTFS/FAT partitions must have the boot indicator set to be considered bootable.
					if (!partition.Active
						&& (*(uint32 *) (SectorBuffer + 3) == 0x5346544e  // 'NTFS'
							|| *(uint16 *) (SectorBuffer + 54) == 0x4146 && SectorBuffer[56] == 'T' // 'FAT'
							|| *(uint16 *) (SectorBuffer + 82) == 0x4146 && SectorBuffer[84] == 'T'))
					{
						continue;
					}

					// Bootable sector found
					if (bootablePartitionCount < array_capacity (bootablePartitions))
						bootablePartitions[bootablePartitionCount++] = partition;
				}
			}
		}
	}

	if (bootablePartitionCount < 1)
	{
		PrintError ("No bootable partition found");
		GetKeyboardChar();
		return;
	}

	char partChar;
	while (true)
	{
		InitScreen();
		Print ("Bootable Partitions:\r\n");
		PrintRepeatedChar ('\xC4', 20);
		Print ("\r\n");

		for (size_t i = 0; i < bootablePartitionCount; ++i)
		{
			const Partition &partition = bootablePartitions[i];
			Print ("["); Print (i + 1); Print ("]    ");
			Print ("Drive: "); Print (partition.Drive - TC_FIRST_BIOS_DRIVE);
			Print (", Partition: "); Print (partition.Number + 1);
			Print (", Size: "); Print (partition.SectorCount >> 11); Print (" MB\r\n");
		}

		if (bootablePartitionCount == 1)
		{
			// There's only one bootable partition so we'll boot it directly instead of showing boot manager
			partChar = '1';
		}
		else
		{
			Print ("[Esc]  Cancel\r\n\r\n");
			Print ("Press 1-9 to select partition: ");

			if (GetString (&partChar, 1) == 0)
				return;

			PrintEndl();

			if (partChar < '1' || partChar > '0' + bootablePartitionCount)
			{
				Beep();
				continue;
			}
		}

		const Partition &partition = bootablePartitions[partChar - '0' - 1];

		if (ReadSectors (SectorBuffer, partition.Drive, partition.StartSector, 1) == BiosResultSuccess)
		{
			ExecuteBootSector (partition.Drive, SectorBuffer);
		}
	}
}


static void DecryptDrive (byte drive)
{
	byte exitKey;
	if (!MountVolume (drive, exitKey))
		return;

	const int sectorsPerIoBlock = 0x7f; // Maximum safe value supported by BIOS

	bool headerUpdateRequired = false;
	uint64 sectorsRemaining = EncryptedVirtualPartition.EndSector + 1 - EncryptedVirtualPartition.StartSector;
	uint64 sector = EncryptedVirtualPartition.EndSector + 1;

	int fragmentSectorCount = sectorsPerIoBlock;
	int statCount;

	if (EncryptedVirtualPartition.Drive == TC_FIRST_BIOS_DRIVE - 1)
	{
		// Drive already decrypted
		sectorsRemaining.HighPart = 0;
		sectorsRemaining.LowPart = 0;
	}
	else
	{
		Print ("\r\nTo safely interrupt and defer decryption, press Esc.\r\n"
			"WARNING: You can turn off power only after you press Esc.\r\n\r\n");
	}

	while (sectorsRemaining.HighPart != 0 || sectorsRemaining.LowPart != 0)
	{
		if (IsKeyboardCharAvailable ())
		{
			byte keyScanCode;
			GetKeyboardChar (&keyScanCode);
			if (keyScanCode == TC_BIOS_KEY_ESC)
				break;
		}

		if (sectorsRemaining.HighPart == 0 && sectorsRemaining.LowPart < fragmentSectorCount)
			fragmentSectorCount = sectorsRemaining.LowPart;

		sector = sector - fragmentSectorCount;

		if (!(statCount++ & 0xf))
		{
			Print ("\rRemaining: ");
			Print (sectorsRemaining >> 11); Print (" MB ");
		}

		if (ReadWriteSectors (false, TC_BOOT_LOADER_BUFFER_SEGMENT, 0, drive, sector, fragmentSectorCount, false) != BiosResultSuccess)
			break;

		AcquireSectorBuffer();

		for (int i = 0; i < fragmentSectorCount; ++i)
		{
			CopyMemory (TC_BOOT_LOADER_BUFFER_SEGMENT, i * TC_LB_SIZE, SectorBuffer, TC_LB_SIZE);

			uint64 s = sector + i;
			DecryptDataUnits (SectorBuffer, &s, 1, BootCryptoInfo);

			CopyMemory (SectorBuffer, TC_BOOT_LOADER_BUFFER_SEGMENT, i * TC_LB_SIZE, TC_LB_SIZE);
		} 

		ReleaseSectorBuffer();

		if (ReadWriteSectors (true, TC_BOOT_LOADER_BUFFER_SEGMENT, 0, drive, sector, fragmentSectorCount, false) != BiosResultSuccess)
			break;

		sectorsRemaining = sectorsRemaining - fragmentSectorCount;
		headerUpdateRequired = true;
	}

	crypto_close (BootCryptoInfo);
	BootArguments *bootArguments = (BootArguments *) TC_BOOT_LOADER_ARGS_OFFSET;

	if (headerUpdateRequired)
	{
		AcquireSectorBuffer();
		uint64 headerSector;
		headerSector.HighPart = 0;
		headerSector.LowPart = TC_BOOT_VOLUME_HEADER_SECTOR;

		// Update encrypted area size in volume header

		CRYPTO_INFO *headerCryptoInfo = crypto_open();
		ReadSectors (SectorBuffer, drive, headerSector, 1);

		if (VolumeReadHeader (TRUE, (char *) SectorBuffer, &bootArguments->BootPassword, NULL, headerCryptoInfo) == 0)
		{
			DecryptBuffer (SectorBuffer + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, headerCryptoInfo);

			byte *sizeField = SectorBuffer + TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH;
			uint64 encryptedAreaLength = sectorsRemaining << TC_LB_SIZE_BIT_SHIFT_DIVISOR;

			for (int i = 7; i >= 0; --i)
			{
				sizeField[i] = (byte) encryptedAreaLength.LowPart;
				encryptedAreaLength = encryptedAreaLength >> 8;
			}

			EncryptBuffer (SectorBuffer + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, headerCryptoInfo);
		}

		crypto_close (headerCryptoInfo);

		WriteSectors (SectorBuffer, drive, headerSector, 1);
		ReleaseSectorBuffer();
	}

	if (sectorsRemaining.HighPart == 0 && sectorsRemaining.LowPart == 0)
		Print ("\rDrive decrypted.\r\n");
	else
		Print ("\r\nDecryption deferred.\r\n");

err:
	memset (bootArguments, 0, sizeof (*bootArguments));
	GetKeyboardChar();
}


static void RepairMenu ()
{
	DriveGeometry bootLoaderDriveGeometry;
	if (GetDriveGeometry (BootLoaderDrive, bootLoaderDriveGeometry) != BiosResultSuccess)
	{
		GetKeyboardChar();
		return;
	}

	while (true)
	{
		InitScreen();
		Print ("Available "); Print ("Repair Options"); Print (":\r\n");
		PrintRepeatedChar ('\xC4', 25);
		Print ("\r\n");

		enum
		{
			RestoreNone = 0,
			DecryptVolume,
			RestoreTrueCryptLoader,
			RestoreVolumeHeader,
			RestoreOriginalSystemLoader
		};

		static const char *options[] = { "Permanently decrypt system partition/drive", "Restore TrueCrypt Boot Loader", "Restore key data (volume header)", "Restore original system loader" };

		int optionCount = 1;
		if (BootSectorFlags & TC_BOOT_CFG_FLAG_RESCUE_DISK_ORIG_SYS_LOADER)
			optionCount = array_capacity (options);
		else if (BootSectorFlags & TC_BOOT_CFG_FLAG_RESCUE_DISK)
			optionCount = array_capacity (options) - 1;

		int selection = AskSelection (options, optionCount);
		PrintEndl();

		switch (selection)
		{
			case RestoreNone:
				return;

			case DecryptVolume:
				Print ("\r\nIMPORTANT: Use this only if Windows cannot start. Decryption under Windows is\r\n"
					   "much faster. To decrypt under Windows, run TrueCrypt and select 'System' >\r\n"
					   "'Permanently Decrypt'.\r\n\r\n");

				if (AskYesNo ("Decrypt now"))
				{
					PrintEndl();
					DecryptDrive (BootDrive);
				}
				continue;

			case RestoreOriginalSystemLoader:
				if (!AskYesNo ("Is the drive decrypted"))
				{
					Print ("Please decrypt it first.\r\n");
					GetKeyboardChar();
					continue;
				}
				break;
		}

		bool writeConfirmed = false;
		BiosResult result;

		uint64 sector;
		sector.HighPart = 0;
		ChsAddress chs;

		byte mbrPartTable[TC_LB_SIZE - TC_MAX_MBR_BOOT_CODE_SIZE];
		AcquireSectorBuffer();

		for (int i = (selection == RestoreVolumeHeader ? TC_BOOT_VOLUME_HEADER_SECTOR : TC_MBR_SECTOR);
			i < TC_BOOT_LOADER_AREA_SECTOR_COUNT; ++i)
		{
			sector.LowPart = (selection == RestoreOriginalSystemLoader ? TC_ORIG_BOOT_LOADER_BACKUP_SECTOR : 0) + i;

			// The backup medium may be a floppy-emulated bootable CD. The emulation may fail if LBA addressing is used.
			// Therefore, only CHS addressing can be used.
			LbaToChs (bootLoaderDriveGeometry, sector, chs);
			sector.LowPart = i;

			if (i == TC_MBR_SECTOR)
			{
				// Read current partition table
				result = ReadSectors (SectorBuffer, TC_FIRST_BIOS_DRIVE, sector, 1);
				if (result != BiosResultSuccess)
					goto err;

				memcpy (mbrPartTable, SectorBuffer + TC_MAX_MBR_BOOT_CODE_SIZE, sizeof (mbrPartTable));
			}

			result = ReadSectors (SectorBuffer, BootLoaderDrive, chs, 1);
			if (result != BiosResultSuccess)
				goto err;

			if (i == TC_MBR_SECTOR)
			{
				// Preserve current partition table
				memcpy (SectorBuffer + TC_MAX_MBR_BOOT_CODE_SIZE, mbrPartTable, sizeof (mbrPartTable));

				// Clear rescue disk flags
				if (selection == RestoreTrueCryptLoader)
					SectorBuffer[TC_BOOT_SECTOR_CONFIG_OFFSET] &= ~(TC_BOOT_CFG_FLAG_RESCUE_DISK | TC_BOOT_CFG_FLAG_RESCUE_DISK_ORIG_SYS_LOADER);
			}

			// Volume header
			if (i == TC_BOOT_VOLUME_HEADER_SECTOR)
			{
				if (selection == RestoreTrueCryptLoader)
					continue;

				if (selection == RestoreVolumeHeader)
				{
					while (true)
					{
						Password password;
						byte exitKey = AskPassword (password);

						if (exitKey != TC_BIOS_KEY_ENTER)
							goto abort;

						CRYPTO_INFO *cryptoInfo;

						CopyMemory (SectorBuffer, TC_BOOT_LOADER_BUFFER_SEGMENT, 0, TC_LB_SIZE);
						ReleaseSectorBuffer();

						// Restore volume header only if the current one cannot be used
						if (OpenVolume (TC_FIRST_BIOS_DRIVE, password, &cryptoInfo))
						{
							Print ("Original header preserved.\r\n");
							crypto_close (cryptoInfo);
							goto err;
						}

						AcquireSectorBuffer();
						CopyMemory (TC_BOOT_LOADER_BUFFER_SEGMENT, 0, SectorBuffer, TC_LB_SIZE);

						if (VolumeReadHeader (TRUE, (char *) SectorBuffer, &password, &cryptoInfo, nullptr) == 0)
						{
							crypto_close (cryptoInfo);
							break;
						}

						Print ("Incorrect password.\r\n\r\n");
					}
				}
			}

			if (!writeConfirmed && !AskYesNo ("Modify drive 0"))
				goto abort;
			writeConfirmed = true;

			if (WriteSectors (SectorBuffer, TC_FIRST_BIOS_DRIVE, sector, 1) != BiosResultSuccess)
				goto err;
		}
done:
		switch (selection)
		{
		case RestoreTrueCryptLoader:
			Print ("TrueCrypt Boot Loader");
			break;

		case RestoreVolumeHeader:
			Print ("Header");
			break;

		case RestoreOriginalSystemLoader:
			Print ("System loader");
			break;
		}
		Print (" restored.\r\n");

err:	GetKeyboardChar();
abort:	ReleaseSectorBuffer();
	}
}


#ifndef DEBUG
extern "C" void _acrtused () { }  // Required by linker
#endif


void main ()
{
	__asm mov BootLoaderDrive, dl
	__asm mov BootSectorFlags, dh

#ifdef TC_BOOT_TRACING_ENABLED
	InitDebugPort();
#endif

#ifdef TC_BOOT_STACK_CHECKING_ENABLED
	InitStackChecker();
#endif

	BootDrive = BootLoaderDrive;
	if (BootDrive < TC_FIRST_BIOS_DRIVE)
		BootDrive = TC_FIRST_BIOS_DRIVE;

	if (GetDriveGeometry (BootDrive, BootDriveGeometry, true) != BiosResultSuccess)
	{
		BootDrive = TC_FIRST_BIOS_DRIVE;
		if (GetDriveGeometry (BootDrive, BootDriveGeometry) == BiosResultSuccess)
			BootDriveGeometryValid = TRUE;
	}
	else
		BootDriveGeometryValid = TRUE;

	while (true)
	{
		InitScreen();
		PrintMainMenu();

		byte exitKey = BootEncryptedDrive();
		
		if (exitKey == TC_MENU_KEY_REPAIR)
		{
			RepairMenu();
			continue;
		}

		BootMenu();
	}
}
