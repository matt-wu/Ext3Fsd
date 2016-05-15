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
	return STATUS_EAS_NOT_SUPPORTED;
}

NTSTATUS
Ext2SetEa (
	IN PEXT2_IRP_CONTEXT    IrpContext
)
{
#if 1
	return STATUS_EAS_NOT_SUPPORTED;
#else
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
	return STATUS_EAS_NOT_SUPPORTED;
#endif
}
