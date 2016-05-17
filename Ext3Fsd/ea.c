/*
* COPYRIGHT:        See COPYRIGHT.TXT
* PROJECT:          Ext2 File System Driver for Windows >= NT
* FILE:             ea.c
* PROGRAMMER:       Matt Wu <mattwu@163.com>  Kaho Ng <ngkaho1234@gmail.com>
* HOMEPAGE:         http://www.ext2fsd.com
* UPDATE HISTORY:
*/

/* INCLUDES *****************************************************************/

#include "ext2fs.h"
#include <linux/ext4_xattr.h>

NTSTATUS
Ext2QueryEa (
	IN PEXT2_IRP_CONTEXT    IrpContext
)
{
	// TODO: Properly setting value according to caller's request.
	PIRP                Irp = NULL;
	PIO_STACK_LOCATION  IrpSp;

	PDEVICE_OBJECT      DeviceObject;

	PEXT2_VCB           Vcb = NULL;
	PEXT2_FCB           Fcb = NULL;
	PEXT2_CCB           Ccb = NULL;
	PEXT2_MCB           Mcb = NULL;

	BOOLEAN             MainResourceAcquired = FALSE;
	BOOLEAN             XattrRefAcquired = FALSE;

	NTSTATUS            Status = STATUS_UNSUCCESSFUL;

	struct ext4_xattr_ref xattr_ref;

	__try {

		Ccb = IrpContext->Ccb;
		ASSERT(Ccb != NULL);
		ASSERT((Ccb->Identifier.Type == EXT2CCB) &&
			(Ccb->Identifier.Size == sizeof(EXT2_CCB)));
		DeviceObject = IrpContext->DeviceObject;
		Vcb = (PEXT2_VCB)DeviceObject->DeviceExtension;
		Fcb = IrpContext->Fcb;
		Mcb = Fcb->Mcb;
		Irp = IrpContext->Irp;
		IrpSp = IoGetCurrentIrpStackLocation(Irp);

		if (!Mcb)
			__leave;

		if (!ExAcquireResourceExclusiveLite(
			&Fcb->MainResource,
			IsFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT))) {
			Status = STATUS_PENDING;
			__leave;
		}
		MainResourceAcquired = TRUE;

		Status = Ext2WinntError(ext4_fs_get_xattr_ref(IrpContext, Vcb, Fcb->Mcb, &xattr_ref));
		if (!NT_SUCCESS(Status)) {
			DbgPrint("ext4_fs_get_xattr_ref() failed!\n");
			__leave;
		} else {
			// TODO: Properly setting value according to caller's request.
			char test_data2[24];
			memset(test_data2, 'S', sizeof(test_data2));
			ext4_fs_set_xattr(&xattr_ref, EXT4_XATTR_INDEX_USER, "Testing-small",
				strlen("Testing-small"), test_data2, sizeof(test_data2), FALSE);
		}
	}
	__finally {

		if (XattrRefAcquired) {
			if (!NT_SUCCESS(Status)) {
				xattr_ref.dirty = FALSE;
				ext4_fs_put_xattr_ref(&xattr_ref);
			}
			else
				Status = Ext2WinntError(ext4_fs_put_xattr_ref(&xattr_ref));
		}

		if (MainResourceAcquired) {
			ExReleaseResourceLite(&Fcb->MainResource);
		}

		if (NT_SUCCESS(Status)) {
			Ext2NotifyReportChange(
				IrpContext,
				Vcb,
				Mcb,
				FILE_NOTIFY_CHANGE_EA,
				FILE_ACTION_MODIFIED);
		}

		if (!AbnormalTermination()) {
			if (Status == STATUS_PENDING || Status == STATUS_CANT_WAIT) {
				Status = Ext2QueueRequest(IrpContext);
			}
			else {
				Ext2CompleteIrpContext(IrpContext, Status);
			}
		}
	}
	return STATUS_SUCCESS;
}

BOOLEAN
Ext2IsEaNameValid(
	IN OEM_STRING Name
)
{
	ULONG Index;
	UCHAR Char;

	//
	//  Empty names are not valid
	//

	if (Name.Length == 0)
		return FALSE;

	//
	// Do not allow EA name longer than 255 bytes
	//
	if (Name.Length > 255)
		return FALSE;

	for (Index = 0; Index < (ULONG)Name.Length; Index += 1) {

		Char = Name.Buffer[Index];

		//
		//  Skip over and Dbcs chacters
		//
		if (FsRtlIsLeadDbcsCharacter(Char)) {

			ASSERT(Index != (ULONG)(Name.Length - 1));
			Index += 1;
			continue;
		}

		//
		//  Make sure this character is legal, and if a wild card, that
		//  wild cards are permissible.
		//
		if (!FsRtlIsAnsiCharacterLegalFat(Char, FALSE))
			return FALSE;

	}

	return TRUE;
}

NTSTATUS
Ext2SetEa (
	IN PEXT2_IRP_CONTEXT    IrpContext
)
{
	PIRP                Irp = NULL;
	PIO_STACK_LOCATION  IrpSp;

	PDEVICE_OBJECT      DeviceObject;

	PEXT2_VCB           Vcb = NULL;
	PEXT2_FCB           Fcb = NULL;
	PEXT2_CCB           Ccb = NULL;
	PEXT2_MCB           Mcb = NULL;

	BOOLEAN             MainResourceAcquired = FALSE;
	BOOLEAN             XattrRefAcquired = FALSE;

	NTSTATUS            Status = STATUS_UNSUCCESSFUL;

	struct ext4_xattr_ref xattr_ref;
	PCHAR UserBuffer;
	LONG UserBufferLength;

	__try {

		Ccb = IrpContext->Ccb;
		ASSERT(Ccb != NULL);
		ASSERT((Ccb->Identifier.Type == EXT2CCB) &&
			(Ccb->Identifier.Size == sizeof(EXT2_CCB)));
		DeviceObject = IrpContext->DeviceObject;
		Vcb = (PEXT2_VCB)DeviceObject->DeviceExtension;
		Fcb = IrpContext->Fcb;
		Mcb = Fcb->Mcb;
		Irp = IrpContext->Irp;
		IrpSp = IoGetCurrentIrpStackLocation(Irp);

		//
		// Receive input parameter from caller
		//
		UserBufferLength = IrpSp->Parameters.SetEa.Length;
		UserBuffer = Irp->UserBuffer;

		// Check if the EA buffer provided is valid
		Status = IoCheckEaBufferValidity((PFILE_FULL_EA_INFORMATION)UserBuffer,
			UserBufferLength,
			(PULONG)&Irp->IoStatus.Information);
		if (!NT_SUCCESS(Status))
			__leave;

		if (!Mcb)
			__leave;

		//
		// We do not allow multiple instance gaining EA access to the same file
		//
		if (!ExAcquireResourceExclusiveLite(
			&Fcb->MainResource,
			IsFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT))) {
			Status = STATUS_PENDING;
			__leave;
		}
		MainResourceAcquired = TRUE;

		Status = Ext2WinntError(ext4_fs_get_xattr_ref(IrpContext, Vcb, Fcb->Mcb, &xattr_ref));
		if (!NT_SUCCESS(Status)) {
			DbgPrint("ext4_fs_get_xattr_ref() failed!\n");
			__leave;
		} else {
			PFILE_FULL_EA_INFORMATION FullEa;

			// Iterate the whole EA buffer to do inspection
			for (FullEa = (PFILE_FULL_EA_INFORMATION)UserBuffer;
				FullEa < (PFILE_FULL_EA_INFORMATION)&UserBuffer[UserBufferLength];
				FullEa = (PFILE_FULL_EA_INFORMATION)(FullEa->NextEntryOffset == 0 ?
					&UserBuffer[UserBufferLength] :
					(PCHAR)FullEa + FullEa->NextEntryOffset)) {

				OEM_STRING EaName;

				EaName.MaximumLength = EaName.Length = FullEa->EaNameLength;
				EaName.Buffer = &FullEa->EaName[0];

				// Check if EA's name is valid
				if (!Ext2IsEaNameValid(EaName)) {
					Irp->IoStatus.Information = (PCHAR)FullEa - UserBuffer;
					Status = STATUS_INVALID_EA_NAME;
					__leave;
				}
			}

			// Now add EA entries to the inode
			for (FullEa = (PFILE_FULL_EA_INFORMATION)UserBuffer;
				FullEa < (PFILE_FULL_EA_INFORMATION)&UserBuffer[UserBufferLength];
				FullEa = (PFILE_FULL_EA_INFORMATION)(FullEa->NextEntryOffset == 0 ?
					&UserBuffer[UserBufferLength] :
					(PCHAR)FullEa + FullEa->NextEntryOffset)) {

					OEM_STRING EaName;

					EaName.MaximumLength = EaName.Length = FullEa->EaNameLength;
					EaName.Buffer = &FullEa->EaName[0];

					ext4_fs_set_xattr(&xattr_ref,
						EXT4_XATTR_INDEX_USER,
						EaName.Buffer,
						EaName.Length,
						&FullEa->EaName[0] + FullEa->EaNameLength + 1 ,
						FullEa->EaValueLength,
						TRUE);
			}
		}
	} __finally {

		if (XattrRefAcquired) {
			if (!NT_SUCCESS(Status)) {
				xattr_ref.dirty = FALSE;
				ext4_fs_put_xattr_ref(&xattr_ref);
			} else
				Status = Ext2WinntError(ext4_fs_put_xattr_ref(&xattr_ref));
		}

		if (MainResourceAcquired) {
			ExReleaseResourceLite(&Fcb->MainResource);
		}

		if (NT_SUCCESS(Status)) {
			Ext2NotifyReportChange(
				IrpContext,
				Vcb,
				Mcb,
				FILE_NOTIFY_CHANGE_EA,
				FILE_ACTION_MODIFIED);
		}

		if (!AbnormalTermination()) {
			if (Status == STATUS_PENDING || Status == STATUS_CANT_WAIT) {
				Status = Ext2QueueRequest(IrpContext);
			}
			else {
				Ext2CompleteIrpContext(IrpContext, Status);
			}
		}
	}
	return STATUS_SUCCESS;
}
