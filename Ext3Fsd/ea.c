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

NTSTATUS
Ext2QueryEa(
	IN PEXT2_IRP_CONTEXT    IrpContext
)
{
	return STATUS_EAS_NOT_SUPPORTED;
}

NTSTATUS
Ext2SetEa(
	IN PEXT2_IRP_CONTEXT    IrpContext
)
{
	return STATUS_EAS_NOT_SUPPORTED;
}