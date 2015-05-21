/*
 * COPYRIGHT:        See COPYRIGHT.TXT
 * PROJECT:          Ext2 File System Driver for WinNT/2K/XP
 * FILE:             extents.c
 * PROGRAMMER:       Matt Wu <mattwu@163.com>
 * HOMEPAGE:         http://www.ext2fsd.com
 * UPDATE HISTORY:
 */

/* INCLUDES *****************************************************************/

#include "ext2fs.h"

/* GLOBALS *****************************************************************/

extern PEXT2_GLOBAL Ext2Global;

/* DEFINITIONS *************************************************************/

#ifdef ALLOC_PRAGMA
#endif


NTSTATUS
Ext2MapExtent(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN PEXT2_MCB            Mcb,
    IN ULONG                Index,
    IN BOOLEAN              Alloc,
    OUT PULONG              Block,
    OUT PULONG              Number
)
{
    int continuous;
    struct buffer_head bh_got;
    EXT4_EXTENT_HEADER *eh;

    memset(&bh_got, 0, sizeof(struct buffer_head));
    eh = get_ext4_header(&Mcb->Inode);

    if (eh->eh_magic != EXT4_EXT_MAGIC) {
        if (Alloc) {
            ext4_ext_tree_init(IrpContext, NULL, &Mcb->Inode);
        } else {
            return STATUS_INVALID_PARAMETER;
        }
    }
    
    if((continuous = ext4_ext_get_blocks(IrpContext,
                            NULL,
                            &Mcb->Inode,
                            Index,
                            EXT_INIT_MAX_LEN, &bh_got, Alloc, 0)) < 0) {
        DbgPrint("Block insufficient resources, err: %d\n", continuous);
        return Ext2WinntError(continuous);
    }
    if (Alloc)
        Ext2SaveInode(IrpContext, Vcb, &Mcb->Inode);
    if (Number)
        *Number = (continuous)?continuous:1;
    if (Block)
        *Block = (ULONG)bh_got.b_blocknr;

    return STATUS_SUCCESS;
}


NTSTATUS
Ext2ExtentExpandOnce(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN PEXT2_MCB            Mcb,
    IN ULONG                Index,
    IN OUT PULONG           Block,
    IN OUT PULONG           Number
)
{
    int continuous;
    struct buffer_head bh_got;
    EXT4_EXTENT_HEADER *eh;

    memset(&bh_got, 0, sizeof(struct buffer_head));
    eh = get_ext4_header(&Mcb->Inode);

    if (eh->eh_magic != EXT4_EXT_MAGIC) {
        ext4_ext_tree_init(IrpContext, NULL, &Mcb->Inode);
    }

    if((continuous = ext4_ext_get_blocks(IrpContext,
                    NULL,
                    &Mcb->Inode,
                    Index,
                    *Number, &bh_got, 1, 0)) < 0) {
        DbgPrint("Expand Block insufficient resources, Number: %u, err: %d\n",
                  *Number, continuous);
        DbgBreak();
        return Ext2WinntError(continuous);
    }
    if (Number)
        *Number = (continuous)?continuous:1;
    if (Block)
        *Block = (ULONG)bh_got.b_blocknr;
        
    if (!Ext2AddBlockExtent(Vcb, Mcb, Index, (*Block), *Number)) {
        DbgBreak();
        ClearFlag(Mcb->Flags, MCB_ZONE_INITED);
        Ext2ClearAllExtents(&Mcb->Extents);
    }

    Ext2SaveInode(IrpContext, Vcb, &Mcb->Inode);

    return STATUS_SUCCESS;
}


NTSTATUS
Ext2ExpandExtent(
    PEXT2_IRP_CONTEXT IrpContext,
    PEXT2_VCB         Vcb,
    PEXT2_MCB         Mcb,
    ULONG             Start,
    ULONG             End,
    PLARGE_INTEGER    Size
    )
{
    ULONG Count = 0, Number = 0, Block = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    if (End <= Start)
        return Status;

    while (End > Start + Count) {

        Number = End - Start - Count;
        Status = Ext2ExtentExpandOnce(IrpContext, Vcb, Mcb, Start + Count, &Block, &Number);
        if (!NT_SUCCESS(Status)) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        if (Number == 0) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Count += Number;
    }

    Size->QuadPart = ((LONGLONG)(Start + Count)) << BLOCK_BITS;

    /* save inode whatever it succeeds to expand or not */
    Ext2SaveInode(IrpContext, Vcb, &Mcb->Inode);

    return Status;
}


NTSTATUS
Ext2TruncateExtent(
    PEXT2_IRP_CONTEXT IrpContext,
    PEXT2_VCB         Vcb,
    PEXT2_MCB         Mcb,
    PLARGE_INTEGER    Size
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    ULONG    Extra = 0;
    ULONG    Wanted = 0;
    ULONG    End;
    ULONG    Removed;
    int      err;

    /* translate file size to block */
    End = Vcb->max_data_blocks;
    Wanted = (ULONG)((Size->QuadPart + BLOCK_SIZE - 1) >> BLOCK_BITS);

    /* calculate blocks to be freed */
    Extra = End - Wanted;

	err = ext4_ext_remove_space(IrpContext, &Mcb->Inode, Wanted);
    if (err == 0) {
        if (!Ext2RemoveBlockExtent(Vcb, Mcb, Wanted, Extra)) {
            ClearFlag(Mcb->Flags, MCB_ZONE_INITED);
            Ext2ClearAllExtents(&Mcb->Extents);
        }
        Extra = 0;
    } else {
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!NT_SUCCESS(Status)) {
        Size->QuadPart += ((ULONGLONG)Extra << BLOCK_BITS);
    }

    /* save inode */
    if (Mcb->Inode.i_size > (loff_t)(Size->QuadPart))
        Mcb->Inode.i_size = (loff_t)(Size->QuadPart);
    Ext2SaveInode(IrpContext, Vcb, &Mcb->Inode);

    return Status;
}
