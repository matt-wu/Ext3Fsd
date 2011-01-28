/*
 * COPYRIGHT:        See COPYRIGHT.TXT
 * PROJECT:          Ext2 File System Driver for WinNT/2K/XP
 * FILE:             generic.c
 * PROGRAMMER:       Matt Wu <mattwu@163.com>
 * HOMEPAGE:         http://ext2.yeah.net
 * UPDATE HISTORY:
 */

/* INCLUDES *****************************************************************/

#include "ext2fs.h"
#include "linux\ext4_ext.h"

/* GLOBALS ***************************************************************/

extern PEXT2_GLOBAL Ext2Global;

/* DEFINITIONS *************************************************************/

BOOLEAN
Ext2IsBlockEmpty(PULONG BlockArray, ULONG SizeArray);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Ext2LoadSuper)
#pragma alloc_text(PAGE, Ext2SaveSuper)
#pragma alloc_text(PAGE, Ext2RefreshSuper)

#pragma alloc_text(PAGE, Ext2LoadGroup)
#pragma alloc_text(PAGE, Ext2SaveGroup)
#pragma alloc_text(PAGE, Ext2RefreshGroup)

#pragma alloc_text(PAGE, Ext2GetInodeLba)
#pragma alloc_text(PAGE, Ext2LoadInode)
#pragma alloc_text(PAGE, Ext2SaveInode)

#pragma alloc_text(PAGE, Ext2LoadBlock)
#pragma alloc_text(PAGE, Ext2SaveBlock)

#pragma alloc_text(PAGE, Ext2SaveBuffer)

#pragma alloc_text(PAGE, Ext2GetBlock)
#pragma alloc_text(PAGE, Ext2BlockMap)
#pragma alloc_text(PAGE, Ext2ExtentMap)
#pragma alloc_text(PAGE, Ext2ExtentSearch)

#pragma alloc_text(PAGE, Ext2UpdateVcbStat)
#pragma alloc_text(PAGE, Ext2NewBlock)
#pragma alloc_text(PAGE, Ext2FreeBlock)
#pragma alloc_text(PAGE, Ext2ExpandLast)
#pragma alloc_text(PAGE, Ext2ExpandBlock)

#pragma alloc_text(PAGE, Ext2IsBlockEmpty)
#pragma alloc_text(PAGE, Ext2TruncateBlock)

#pragma alloc_text(PAGE, Ext2NewInode)
#pragma alloc_text(PAGE, Ext2FreeInode)

#pragma alloc_text(PAGE, Ext2AddEntry)
#pragma alloc_text(PAGE, Ext2RemoveEntry)
#pragma alloc_text(PAGE, Ext2SetParentEntry)

#endif

/* FUNCTIONS ***************************************************************/

NTSTATUS
Ext2LoadSuper(IN PEXT2_VCB      Vcb,
              IN BOOLEAN        bVerify,
              OUT PEXT2_SUPER_BLOCK * Sb)
{
    NTSTATUS          Status;
    PEXT2_SUPER_BLOCK Ext2Sb = NULL;

    Ext2Sb = (PEXT2_SUPER_BLOCK)
             Ext2AllocatePool(
                 PagedPool,
                 SUPER_BLOCK_SIZE,
                 EXT2_SB_MAGIC
             );
    if (!Ext2Sb) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    Status = Ext2ReadDisk(
                 Vcb,
                 (ULONGLONG) SUPER_BLOCK_OFFSET,
                 SUPER_BLOCK_SIZE,
                 (PVOID) Ext2Sb,
                 bVerify );

    if (!NT_SUCCESS(Status)) {

        DEBUG(DL_ERR, ( "Ext2ReadDisk: disk device error.\n"));

        Ext2FreePool(Ext2Sb, EXT2_SB_MAGIC);
        Ext2Sb = NULL;
    }

errorout:

    *Sb = Ext2Sb;
    return Status;
}


BOOLEAN
Ext2SaveSuper(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb
)
{
    LONGLONG    offset;
    BOOLEAN     rc;

    offset = (LONGLONG) SUPER_BLOCK_OFFSET;
    rc = Ext2SaveBuffer( IrpContext,
                         Vcb,
                         offset,
                         SUPER_BLOCK_SIZE,
                         Vcb->SuperBlock
                       );

    if (IsFlagOn(Vcb->Flags, VCB_FLOPPY_DISK)) {
        Ext2StartFloppyFlushDpc(Vcb, NULL, NULL);
    }

    return rc;
}


BOOLEAN
Ext2RefreshSuper (
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb
)
{
    LONGLONG        offset;
    IO_STATUS_BLOCK iosb;

    offset = (LONGLONG) SUPER_BLOCK_OFFSET;
    if (!CcCopyRead(
                Vcb->Volume,
                (PLARGE_INTEGER)&offset,
                SUPER_BLOCK_SIZE,
                TRUE,
                (PVOID)Vcb->SuperBlock,
                &iosb )) {
        return FALSE;
    }

    if (!NT_SUCCESS(iosb.Status)) {
        return FALSE;
    }

    /* reload root inode */
    if (Vcb->McbTree) {

        if (!Ext2LoadInode(Vcb, &Vcb->McbTree->Inode))
            return FALSE;

        /* initializeroot node */
        Vcb->McbTree->CreationTime = Ext2NtTime(Vcb->McbTree->Inode.i_ctime);
        Vcb->McbTree->LastAccessTime = Ext2NtTime(Vcb->McbTree->Inode.i_atime);
        Vcb->McbTree->LastWriteTime = Ext2NtTime(Vcb->McbTree->Inode.i_mtime);
        Vcb->McbTree->ChangeTime = Ext2NtTime(Vcb->McbTree->Inode.i_mtime);
    }

    return TRUE;
}

BOOLEAN
Ext2LoadGroup(IN PEXT2_VCB Vcb)
{
    struct super_block  *sb = &Vcb->sb;
    struct ext3_sb_info *sbi = &Vcb->sbi;
    unsigned long i;
    ext3_fsblk_t block, sb_block = 1;

    if (BLOCK_SIZE != EXT3_MIN_BLOCK_SIZE) {
        sb_block = EXT4_MIN_BLOCK_SIZE / BLOCK_SIZE;
    }

    if (NULL == sbi->s_group_desc) {
        sbi->s_group_desc = kzalloc(sbi->s_gdb_count * sizeof(void *),
                                    GFP_KERNEL);
    }
    if (sbi->s_group_desc == NULL) {
        DEBUG(DL_ERR, ("Ext2LoadGroup: not enough memory.\n"));
        return FALSE;
    }

    for (i = 0; i < sbi->s_gdb_count; i++) {
        block = descriptor_loc(sb, sb_block, i);
        if (sbi->s_group_desc[i])
            continue;
        sbi->s_group_desc[i] = sb_bread(sb, block);
        if (!sbi->s_group_desc[i]) {
            DEBUG(DL_ERR, ("Ext2LoadGroup: can't read group descriptor %d\n", i));
            return FALSE;
        }
    }

    if (!ext4_check_descriptors(sb)) {
        DEBUG(DL_ERR, ("Ext2LoadGroup: group descriptors corrupted!\n"));
        return FALSE;
    }

    return TRUE;
}

VOID
Ext2PutGroup(IN PEXT2_VCB Vcb)
{
    struct ext3_sb_info *sbi = &Vcb->sbi;
    unsigned long i;

    ExAcquireResourceExclusiveLite(&Vcb->MetaLock, TRUE);
    if (NULL == sbi->s_group_desc) {
        ExReleaseResourceLite(&Vcb->MetaLock);
        return;
    }

    for (i = 0; i < sbi->s_gdb_count; i++) {
        if (sbi->s_group_desc[i]) {
            brelse(sbi->s_group_desc[i]);
            sbi->s_group_desc[i] = NULL;
        }
    }

    kfree(sbi->s_group_desc);
    sbi->s_group_desc = NULL;
    ExReleaseResourceLite(&Vcb->MetaLock);
}

BOOLEAN
Ext2SaveGroup(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN ULONG                Group
)
{
    struct ext4_group_desc *desc;
    struct buffer_head  *bh = NULL;
    unsigned long i;

    ExAcquireResourceExclusiveLite(&Vcb->MetaLock, TRUE);
    desc = ext4_get_group_desc(&Vcb->sb, Group, &bh);
    if (bh)
        get_bh(bh);
    ExReleaseResourceLite(&Vcb->MetaLock);

    if (!bh)
        return 0;

    desc->bg_checksum = ext4_group_desc_csum(&Vcb->sbi, Group, desc);
    mark_buffer_dirty(bh);
    __brelse(bh);

    return TRUE;
}


BOOLEAN
Ext2RefreshGroup(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb
)
{
    return TRUE;
}

BOOLEAN
Ext2GetInodeLba (
    IN PEXT2_VCB    Vcb,
    IN  ULONG       inode,
    OUT PLONGLONG   offset
)
{
    PEXT2_GROUP_DESC gd;
    ext4_fsblk_t loc;
    int group;

    if (inode < 1 || inode > INODES_COUNT)  {
        DEBUG(DL_ERR, ( "Ext2GetInodeLba: Inode value %xh is invalid.\n",inode));
        *offset = 0;
        return FALSE;
    }

    group = (inode - 1) / INODES_PER_GROUP ;
    gd = ext4_get_group_desc(&Vcb->sb, group, NULL);
    if (!gd) {
        *offset = 0;
        DbgBreak();
        return FALSE;
    }
    loc = (LONGLONG)ext4_inode_table(&Vcb->sb, gd);
    loc = loc << BLOCK_BITS;
    loc = loc + ((inode - 1) % INODES_PER_GROUP) * Vcb->InodeSize;

    *offset = loc;

    return TRUE;
}

void Ext2DecodeInode(struct inode *dst, struct ext3_inode *src)
{
    dst->i_mode = src->i_mode;
    dst->i_flags = src->i_flags;
    dst->i_uid = src->i_uid;
    dst->i_gid = src->i_gid;
    dst->i_nlink = src->i_links_count;
    dst->i_generation = src->i_generation;
    dst->i_size = src->i_size;
    if (S_ISREG(src->i_mode)) {
        dst->i_size |= (loff_t)src->i_size_high << 32;
    }
    dst->i_atime = src->i_atime;
    dst->i_ctime = src->i_ctime;
    dst->i_mtime = src->i_mtime;
    dst->i_dtime = src->i_dtime;
    dst->i_blocks = ext3_inode_blocks(src, dst);
    memcpy(&dst->i_block[0], &src->i_block[0], sizeof(__u32) * 15);
}

void Ext2EncodeInode(struct ext3_inode *dst,  struct inode *src)
{
    dst->i_mode = src->i_mode;
    dst->i_flags = src->i_flags;
    dst->i_uid = src->i_uid;
    dst->i_gid = src->i_gid;
    dst->i_links_count = src->i_nlink;
    dst->i_generation = src->i_generation;
    dst->i_size = (__u32)src->i_size;
    if (S_ISREG(src->i_mode)) {
        dst->i_size_high = (__u32)(src->i_size >> 32);
    }
    dst->i_atime = src->i_atime;
    dst->i_ctime = src->i_ctime;
    dst->i_mtime = src->i_mtime;
    dst->i_dtime = src->i_dtime;
    ASSERT(src->i_sb);
    ext3_inode_blocks_set(dst, src);
    memcpy(&dst->i_block[0], &src->i_block[0], sizeof(__u32) * 15);
}


BOOLEAN
Ext2LoadInode (IN PEXT2_VCB Vcb,
               IN struct inode *Inode)
{
    struct ext3_inode   ext3i;

    IO_STATUS_BLOCK     IoStatus;
    LONGLONG            Offset;

    if (!Ext2GetInodeLba(Vcb, Inode->i_ino, &Offset))  {
        DEBUG(DL_ERR, ( "Ext2LoadInode: error get inode(%xh)'s addr.\n", Inode->i_ino));
        return FALSE;
    }

    if (!CcCopyRead(
                Vcb->Volume,
                (PLARGE_INTEGER)&Offset,
                sizeof(struct ext3_inode),
                PIN_WAIT,
                (PVOID)&ext3i,
                &IoStatus )) {
        return FALSE;
    }

    if (!NT_SUCCESS(IoStatus.Status)) {
        return FALSE;
    }

    Ext2DecodeInode(Inode, &ext3i);

    return TRUE;
}


BOOLEAN
Ext2ClearInode (
    IN PEXT2_IRP_CONTEXT IrpContext,
    IN PEXT2_VCB Vcb,
    IN ULONG Inode)
{
    LONGLONG            Offset = 0;
    BOOLEAN             rc;

    rc = Ext2GetInodeLba(Vcb, Inode, &Offset);
    if (!rc)  {
        DEBUG(DL_ERR, ( "Ext2SaveInode: error get inode(%xh)'s addr.\n", Inode));
        goto errorout;
    }

    rc = Ext2ZeroBuffer(IrpContext, Vcb, Offset, Vcb->InodeSize);

errorout:

    return rc;
}

BOOLEAN
Ext2SaveInode ( IN PEXT2_IRP_CONTEXT IrpContext,
                IN PEXT2_VCB Vcb,
                IN struct inode *Inode)
{
    struct ext3_inode   ext3i;

    IO_STATUS_BLOCK     IoStatus;
    LONGLONG            Offset = 0;
    BOOLEAN             rc = 0;

    DEBUG(DL_INF, ( "Ext2SaveInode: Saving Inode %xh: Mode=%xh Size=%xh\n",
                    Inode->i_ino, Inode->i_mode, Inode->i_size));
    rc = Ext2GetInodeLba(Vcb,  Inode->i_ino, &Offset);
    if (!rc)  {
        DEBUG(DL_ERR, ( "Ext2SaveInode: error get inode(%xh)'s addr.\n", Inode->i_ino));
        goto errorout;
    }

    if (!CcCopyRead(
                Vcb->Volume,
                (PLARGE_INTEGER)&Offset,
                sizeof(struct ext3_inode),
                PIN_WAIT,
                (PVOID)&ext3i,
                &IoStatus )) {
        rc = FALSE;
        goto errorout;
    }

    if (!NT_SUCCESS(IoStatus.Status)) {
        rc = FALSE;
        goto errorout;
    }

    Ext2EncodeInode(&ext3i, Inode);
    rc = Ext2SaveBuffer(IrpContext, Vcb, Offset, sizeof(struct ext3_inode), &ext3i);

    if (rc && IsFlagOn(Vcb->Flags, VCB_FLOPPY_DISK)) {
        Ext2StartFloppyFlushDpc(Vcb, NULL, NULL);
    }

errorout:
    return rc;
}


BOOLEAN
Ext2LoadBlock (IN PEXT2_VCB Vcb,
               IN ULONG     Index,
               IN PVOID     Buffer )
{
    IO_STATUS_BLOCK     IoStatus;
    LONGLONG            Offset;

    Offset = (LONGLONG) Index;
    Offset = Offset * Vcb->BlockSize;

    if (!CcCopyRead(
                Vcb->Volume,
                (PLARGE_INTEGER)&Offset,
                Vcb->BlockSize,
                PIN_WAIT,
                Buffer,
                &IoStatus ));

    if (!NT_SUCCESS(IoStatus.Status)) {
        return FALSE;
    }

    return TRUE;
}


BOOLEAN
Ext2SaveBlock ( IN PEXT2_IRP_CONTEXT    IrpContext,
                IN PEXT2_VCB            Vcb,
                IN ULONG                Index,
                IN PVOID                Buf )
{
    LONGLONG Offset;
    BOOLEAN  rc;

    Offset = (LONGLONG) Index;
    Offset = Offset * Vcb->BlockSize;

    rc = Ext2SaveBuffer(IrpContext, Vcb, Offset, Vcb->BlockSize, Buf);

    if (IsFlagOn(Vcb->Flags, VCB_FLOPPY_DISK)) {
        Ext2StartFloppyFlushDpc(Vcb, NULL, NULL);
    }

    return rc;
}

BOOLEAN
Ext2ZeroBuffer( IN PEXT2_IRP_CONTEXT    IrpContext,
                IN PEXT2_VCB            Vcb,
                IN LONGLONG             Offset,
                IN ULONG                Size )
{
    PBCB        Bcb;
    PVOID       Buffer;
    BOOLEAN     rc;

    if ( !CcPreparePinWrite(
                Vcb->Volume,
                (PLARGE_INTEGER) (&Offset),
                Size,
                FALSE,
                PIN_WAIT,
                &Bcb,
                &Buffer )) {

        DEBUG(DL_ERR, ( "Ext2SaveBuffer: failed to PinLock offset %I64xh ...\n", Offset));
        return FALSE;
    }

    __try {

        RtlZeroMemory(Buffer, Size);
        CcSetDirtyPinnedData(Bcb, NULL );
        SetFlag(Vcb->Volume->Flags, FO_FILE_MODIFIED);

        rc = Ext2AddVcbExtent(Vcb, Offset, (LONGLONG)Size);
        if (!rc) {
            DbgBreak();
            Ext2Sleep(100);
            rc = Ext2AddVcbExtent(Vcb, Offset, (LONGLONG)Size);
        }

    } __finally {
        CcUnpinData(Bcb);
    }


    return rc;
}

BOOLEAN
Ext2SaveBuffer( IN PEXT2_IRP_CONTEXT    IrpContext,
                IN PEXT2_VCB            Vcb,
                IN LONGLONG             Offset,
                IN ULONG                Size,
                IN PVOID                Buf )
{
    PBCB        Bcb;
    PVOID       Buffer;
    BOOLEAN     rc;

    if ( !CcPreparePinWrite(
                Vcb->Volume,
                (PLARGE_INTEGER) (&Offset),
                Size,
                FALSE,
                PIN_WAIT,
                &Bcb,
                &Buffer )) {

        DEBUG(DL_ERR, ( "Ext2SaveBuffer: failed to PinLock offset %I64xh ...\n", Offset));
        return FALSE;
    }

    __try {

        RtlCopyMemory(Buffer, Buf, Size);
        CcSetDirtyPinnedData(Bcb, NULL );
        SetFlag(Vcb->Volume->Flags, FO_FILE_MODIFIED);

        rc = Ext2AddVcbExtent(Vcb, Offset, (LONGLONG)Size);
        if (!rc) {
            DbgBreak();
            Ext2Sleep(100);
            rc = Ext2AddVcbExtent(Vcb, Offset, (LONGLONG)Size);
        }

    } __finally {
        CcUnpinData(Bcb);
    }


    return rc;
}

NTSTATUS
Ext2GetBlock(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN PEXT2_MCB            Mcb,
    IN ULONG                Base,
    IN ULONG                Layer,
    IN ULONG                Start,
    IN ULONG                SizeArray,
    IN PULONG               BlockArray,
    IN BOOLEAN              bAlloc,
    IN OUT PULONG           Hint,
    OUT PULONG              Block,
    OUT PULONG              Number
)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    PBCB        Bcb = NULL;
    PULONG      pData = NULL;
    ULONG       Slot = 0, i = 0;
    ULONG       Unit = 1;

    LARGE_INTEGER Offset;

    if (Layer == 0) {

        *Number = 1;
        if (BlockArray[0] == 0 && bAlloc) {

            /* now allocate new block */
            Status = Ext2ExpandLast(
                         IrpContext,
                         Vcb,
                         Mcb,
                         Base,
                         Layer,
                         NULL,
                         Hint,
                         &BlockArray[0],
                         Number
                     );

            if (!NT_SUCCESS(Status)) {
                goto errorout;
            }
        }

        *Block = BlockArray[0];
        for (i=1; i < SizeArray; i++) {
            if (BlockArray[i] == BlockArray[i-1] + 1) {
                *Number = *Number + 1;
            } else {
                break;
            }
        }
        *Hint = BlockArray[*Number - 1];

    } else if (Layer <= 3) {

        /* check the block is valid or not */
        if (BlockArray[0] >= TOTAL_BLOCKS) {
            DbgBreak();
            Status = STATUS_DISK_CORRUPT_ERROR;
            goto errorout;
        }

        /* map memory in cache for the index block */
        Offset.QuadPart = ((LONGLONG)BlockArray[0]) << BLOCK_BITS;
        if ( !CcPinRead( Vcb->Volume,
                         (PLARGE_INTEGER) (&Offset),
                         BLOCK_SIZE,
                         PIN_WAIT,
                         &Bcb,
                         &pData )) {

            DEBUG(DL_ERR, ( "Ext2GetBlock: Failed to PinLock block: %xh ...\n",
                            BlockArray[0] ));
            Status = STATUS_CANT_WAIT;
            goto errorout;
        }


        if (Layer > 1) {
            Unit = Vcb->max_blocks_per_layer[Layer - 1];
        } else {
            Unit = 1;
        }

        Slot  = Start / Unit;
        Start = Start % Unit;

        if (pData[Slot] == 0) {

            if (bAlloc) {

                /* we need allocate new block and zero all data in case
                   it's an in-direct block. Index stores the new block no. */
                ULONG   Count = 1;
                Status = Ext2ExpandLast(
                             IrpContext,
                             Vcb,
                             Mcb,
                             Base,
                             Layer,
                             NULL,
                             Hint,
                             &pData[Slot],
                             &Count
                         );

                if (!NT_SUCCESS(Status)) {
                    goto errorout;
                }

                /* refresh hint block */
                *Hint = pData[Slot];

                /* set dirty bit to notify system to flush */
                CcSetDirtyPinnedData(Bcb, NULL );
                SetFlag(Vcb->Volume->Flags, FO_FILE_MODIFIED);
                if (!Ext2AddVcbExtent(Vcb, Offset.QuadPart,
                                      (LONGLONG)BLOCK_SIZE)) {
                    DbgBreak();
                    Ext2Sleep(100);
                    if (!Ext2AddVcbExtent(Vcb, Offset.QuadPart,
                                          (LONGLONG)BLOCK_SIZE)) {
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        goto errorout;
                    }
                }

                /* save inode information here */
                Ext2SaveInode(IrpContext, Vcb, &Mcb->Inode);

            } else {

                *Number = 1;

                if (Layer == 1) {
                    for (i = Slot + 1; i < BLOCK_SIZE/4; i++) {
                        if (pData[i] == 0) {
                            *Number = *Number + 1;
                        } else {
                            break;
                        }
                    }
                } else if (Layer == 2) {
                    *Number = BLOCK_SIZE/4 - Start;
                } else {
                    *Number = BLOCK_SIZE/4;
                }

                goto errorout;
            }
        }

        /* transfer to next recursion call */
        Status = Ext2GetBlock(
                     IrpContext,
                     Vcb,
                     Mcb,
                     Base,
                     Layer - 1,
                     Start,
                     BLOCK_SIZE/4 - Slot,
                     &pData[Slot],
                     bAlloc,
                     Hint,
                     Block,
                     Number
                 );

        if (!NT_SUCCESS(Status)) {
            goto errorout;
        }
    }

errorout:

    /* free the memory of pData */
    if (Bcb) {
        CcUnpinData(Bcb);
    }

    if (!NT_SUCCESS(Status)) {
        *Block = 0;
    }

    return Status;
}

NTSTATUS
Ext2BlockMap(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN PEXT2_MCB            Mcb,
    IN ULONG                Index,
    IN BOOLEAN              bAlloc,
    OUT PULONG              pBlock,
    OUT PULONG              Number
)
{
    ULONG   Layer;
    ULONG   Slot;

    ULONG   Base = Index;

    NTSTATUS Status = STATUS_SUCCESS;

    *pBlock = 0;
    *Number = 0;

    for (Layer = 0; Layer < EXT2_BLOCK_TYPES; Layer++) {

        if (Index < Vcb->max_blocks_per_layer[Layer]) {

            ULONG   dwRet = 0;
            ULONG   dwBlk = 0;
            ULONG   dwHint = 0;

            Slot = (Layer==0) ? (Index):(Layer + EXT2_NDIR_BLOCKS - 1);
            dwBlk = Mcb->Inode.i_block[Slot];

            if (dwBlk == 0) {

                if (!bAlloc) {

                    *Number = 1;
                    goto errorout;

                } else {

                    if (Slot) {
                        dwHint = Mcb->Inode.i_block[Slot - 1];
                    }

                    /* allocate and zero block if necessary */
                    *Number = 1;
                    Status = Ext2ExpandLast(
                                 IrpContext,
                                 Vcb,
                                 Mcb,
                                 Base,
                                 Layer,
                                 NULL,
                                 &dwHint,
                                 &dwBlk,
                                 Number
                             );

                    if (!NT_SUCCESS(Status)) {
                        goto errorout;
                    }

                    /* save the it into inode*/
                    Mcb->Inode.i_block[Slot] = dwBlk;

                    /* save the inode */
                    if (!Ext2SaveInode(IrpContext, Vcb, &Mcb->Inode)) {

                        Status = STATUS_UNSUCCESSFUL;
                        Ext2FreeBlock(IrpContext, Vcb, dwBlk, 1);

                        goto errorout;
                    }
                }
            }

            /* querying block number of the index-th file block */
            Status = Ext2GetBlock(
                         IrpContext,
                         Vcb,
                         Mcb,
                         Base,
                         Layer,
                         Index,
                         (Layer == 0) ? (Vcb->max_blocks_per_layer[Layer] - Index) : 1,
                         &Mcb->Inode.i_block[Slot],
                         bAlloc,
                         &dwHint,
                         &dwRet,
                         Number
                     );

            if (NT_SUCCESS(Status)) {
                *pBlock = dwRet;
            }

            break;
        }

        Index -= Vcb->max_blocks_per_layer[Layer];
    }

errorout:

    return Status;
}

NTSTATUS
Ext2ExtentMap(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN PEXT2_MCB            Mcb,
    IN ULONG                Index,
    IN BOOLEAN              Alloc,
    OUT PULONG              Block,
    OUT PULONG              Number
)
{
    EXT4_EXTENT_HEADER *eh;

    eh = get_ext4_header(&Mcb->Inode);

    return Ext2ExtentSearch(
               IrpContext,
               Vcb,
               Mcb,
               Index,
               Alloc,
               eh,
               FALSE,
               NULL,
               Block,
               Number
           );
}

NTSTATUS
Ext2ExtentSearch(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN PEXT2_MCB            Mcb,
    IN ULONG                Index,
    IN BOOLEAN              Alloc,
    IN PVOID                ExtentHeader,
    IN BOOLEAN              UnpinBcb,
    IN PBCB                 BcbToUnpin,
    OUT PULONG              Block,
    OUT PULONG              Number
)
{
    EXT4_EXTENT_HEADER *eh;
    EXT4_EXTENT_IDX *ei;
    EXT4_EXTENT *ex;
    LARGE_INTEGER offset;
    PBCB bcb;
    PVOID ib;
    int i;
    NTSTATUS status;

    *Block = 0;
    *Number = 0;

    eh = (EXT4_EXTENT_HEADER *) ExtentHeader;

    if (eh != NULL && eh->eh_magic == EXT4_EXT_MAGIC) {
        DEBUG(DL_INF, ("eh_magic=%x eh_entries=%u eh_max=%u eh_depth=%u eh_generation=%u\n", (ULONG)eh->eh_magic, (ULONG)eh->eh_entries, (ULONG)eh->eh_max, (ULONG)eh->eh_depth, eh->eh_generation ));
        if (eh->eh_depth == 0) {
            ex = EXT_FIRST_EXTENT(eh);
            for (i = 0; i < eh->eh_entries; i++, ex++) {
                DEBUG(DL_INF, ("ee_block=%u ee_len=%u ee_start_hi=%u ee_start_lo=%u ext_to_block(extent)=%u\n", ex->ee_block, (ULONG)ex->ee_len, (ULONG)ex->ee_start_hi, ex->ee_start_lo, ext_to_block(ex) ));
                if (Index >= ex->ee_block && Index < ex->ee_block + ex->ee_len) {
                    *Block = (ULONG) (ext_to_block(ex) + (Index - ex->ee_block));
                    *Number = ex->ee_block + ex->ee_len - Index;
                    DEBUG(DL_INF, ("Index=%u Block=%u Number=%u\n", Index, *Block, *Number ));
                    if (UnpinBcb) {
                        CcUnpinData(BcbToUnpin);
                    }
                    return STATUS_SUCCESS;
                }
            }
            DEBUG(DL_ERR, ("Ext2ExtentSearch: search for extent entry failed on file or directory %wZ\n", &Mcb->FullName ));
            if (Alloc) {
                DEBUG(DL_ERR, ("possible because extending a file or directory that is stored using ext4 exents is not supported yet\n" ));
            }
            DEBUG(DL_ERR, ("eh_magic=%x eh_entries=%u eh_max=%u eh_depth=%u eh_generation=%u lbn=%u\n", (ULONG)eh->eh_magic, (ULONG)eh->eh_entries, (ULONG)eh->eh_max, (ULONG)eh->eh_depth, eh->eh_generation, Index ));
            DEBUG(DL_ERR, ("ee_block=%u ee_len=%u ee_start_hi=%u ee_start_lo=%u ext_to_block(extent)=%u\n", ex->ee_block, (ULONG)ex->ee_len, (ULONG)ex->ee_start_hi, ex->ee_start_lo, ext_to_block(ex) ));
        } else {
            ei = EXT_FIRST_INDEX(eh);
            DEBUG(DL_INF, ("Index=%u ei_block=%u eh_entries=%u\n", Index, ei->ei_block, eh->eh_entries ));
            for (i = 0; i < eh->eh_entries; i++, ei++) {
                if (i == eh->eh_entries - 1 || Index < (ei+1)->ei_block) {
                    DEBUG(DL_INF, ("idx_to_block(index)=%u\n", idx_to_block(ei) ));
                    offset.QuadPart = idx_to_block(ei) * Vcb->BlockSize;
                    status = STATUS_SUCCESS;
                    __try {
                        if ( !CcPinRead (
                            Vcb->Volume,
                            &offset,
                            Vcb->BlockSize,
                            PIN_WAIT,
                            &bcb,
                            &ib )) {
                            status = STATUS_CANT_WAIT;
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        status = GetExceptionCode();
                    }
                    if (!NT_SUCCESS(status)) {
                        DEBUG(DL_ERR, ("Ext2ExtentSearch: CcPinRead failed with status %x\n", status ));
                        return status;
                    }
                    return Ext2ExtentSearch(
                               IrpContext,
                               Vcb,
                               Mcb,
                               Index,
                               Alloc,
                               ib,
                               TRUE,
                               bcb,
                               Block,
                               Number
                           );
                }
            }
        }
    }

    if (UnpinBcb) {
        CcUnpinData(BcbToUnpin);
    }

    return STATUS_DISK_CORRUPT_ERROR;
}


VOID
Ext2UpdateVcbStat(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb
)
{
    Vcb->SuperBlock->s_free_inodes_count = ext4_count_free_inodes(&Vcb->sb);
    ext3_free_blocks_count_set(SUPER_BLOCK, ext4_count_free_blocks(&Vcb->sb));
    Ext2SaveSuper(IrpContext, Vcb);
}

NTSTATUS
Ext2NewBlock(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN ULONG                GroupHint,
    IN ULONG                BlockHint,
    OUT PULONG              Block,
    IN OUT PULONG           Number
)
{
    struct super_block      *sb = &Vcb->sb;
    PEXT2_GROUP_DESC        group_desc;
    struct buffer_head*     bh = NULL;
    ext4_fsblk_t            bitmap_blk;

    RTL_BITMAP              BlockBitmap;

    ULONG                   Group = 0;
    ULONG                   Index = 0xFFFFFFFF;
    ULONG                   dwHint = 0;
    ULONG                   Count = 0;
    ULONG                   Length = 0;

    NTSTATUS                Status = STATUS_DISK_FULL;

    *Block = 0;

    ExAcquireResourceExclusiveLite(&Vcb->MetaLock, TRUE);

    /* validate the hint group and hint block */
    if (GroupHint >= Vcb->sbi.s_groups_count) {
        DbgBreak();
        GroupHint = Vcb->sbi.s_groups_count - 1;
    }

    if (BlockHint != 0) {
        GroupHint = (BlockHint - EXT2_FIRST_DATA_BLOCK) / BLOCKS_PER_GROUP;
        dwHint = (BlockHint - EXT2_FIRST_DATA_BLOCK) % BLOCKS_PER_GROUP;
    }

    Group = GroupHint;

Again:

    if (bh) {
        __brelse(bh);
        bh = NULL;
    }

    group_desc = ext4_get_group_desc(sb, Group, NULL);
    if (!group_desc) {
        DbgBreak();
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    bitmap_blk = ext4_block_bitmap(sb, group_desc);
    bh = sb_getblk(sb, bitmap_blk);
    if (!bh) {
        DbgBreak();
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    if (group_desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
        ext4_init_block_bitmap(sb, bh, Group, group_desc);
        set_buffer_uptodate(bh);
    }

    if (ext4_free_blks_count(sb, group_desc)) {

        if (Group == Vcb->sbi.s_groups_count - 1) {

            Length = (ULONG)(TOTAL_BLOCKS % BLOCKS_PER_GROUP);

            /* s_blocks_count is integer multiple of s_blocks_per_group */
            if (Length == 0) {
                Length = BLOCKS_PER_GROUP;
            }
        } else {
            Length = BLOCKS_PER_GROUP;
        }

        /* initialize bitmap buffer */
        RtlInitializeBitMap(&BlockBitmap, (PULONG)bh->b_data, Length);

        /* try to find a clear bit range */
        Index = RtlFindClearBits(&BlockBitmap, *Number, dwHint);

        /* We could not get new block in the prefered group */
        if (Index == 0xFFFFFFFF) {

            /* search clear bits from the hint block */
            Count = RtlFindNextForwardRunClear(&BlockBitmap, dwHint, &Index);
            if (dwHint != 0 && Count == 0) {
                /* search clear bits from the very beginning */
                Count = RtlFindNextForwardRunClear(&BlockBitmap, 0, &Index);
            }

            if (Count == 0) {

                RtlZeroMemory(&BlockBitmap, sizeof(RTL_BITMAP));

                /* no blocks found: set bg_free_blocks_count to 0 */
                ext4_free_blks_set(sb, group_desc, 0);
                Ext2SaveGroup(IrpContext, Vcb, Group);

                /* will try next group */
                goto Again;

            } else {

                /* we got free blocks */
                if (Count <= *Number) {
                    *Number = Count;
                }
            }
        }

    } else {

        /* try next group */
        dwHint = 0;
        Group = (Group + 1) % Vcb->sbi.s_groups_count;
        if (Group != GroupHint) {
            goto Again;
        }

        Index = 0xFFFFFFFF;
    }

    if (Index < Length) {

        /* mark block bits as allocated */
        RtlSetBits(&BlockBitmap, Index, *Number);

        /* set block bitmap dirty in cache */
        mark_buffer_dirty(bh);

        if (group_desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT))
            group_desc->bg_flags &= cpu_to_le16(~EXT4_BG_BLOCK_UNINIT);

        /* update group description */
        ext4_free_blks_set(sb, group_desc, RtlNumberOfClearBits(&BlockBitmap));
        Ext2SaveGroup(IrpContext, Vcb, Group);

        /* update Vcb free blocks */
        Ext2UpdateVcbStat(IrpContext, Vcb);

        /* validate the new allocated block number */
        *Block = Index + EXT2_FIRST_DATA_BLOCK + Group * BLOCKS_PER_GROUP;
        if (*Block >= TOTAL_BLOCKS || *Block + *Number > TOTAL_BLOCKS) {
            DbgBreak();
            dwHint = 0;
            goto Again;
        }

        if (ext4_block_bitmap(sb, group_desc) == *Block ||
                ext4_inode_bitmap(sb, group_desc) == *Block ||
                ext4_inode_table(sb, group_desc)  == *Block ) {
            DbgBreak();
            dwHint = 0;
            goto Again;
        }

        DEBUG(DL_INF, ("Ext2NewBlock:  Block %xh - %x allocated.\n",
                       *Block, *Block + *Number));
        Status = STATUS_SUCCESS;
    }

errorout:

    ExReleaseResourceLite(&Vcb->MetaLock);

    if (bh)
        __brelse(bh);

    return Status;
}

NTSTATUS
Ext2FreeBlock(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN ULONG                Block,
    IN ULONG                Number
)
{
    struct super_block     *sb = &Vcb->sb;
    PEXT2_GROUP_DESC        group_desc;
    ext4_fsblk_t            bitmap_blk;

    RTL_BITMAP      BlockBitmap;
    LARGE_INTEGER   Offset;

    PBCB            BitmapBcb;
    PVOID           BitmapCache;

    ULONG           Group;
    ULONG           Index;
    ULONG           Length;
    ULONG           Count;

    NTSTATUS        Status = STATUS_UNSUCCESSFUL;

    ExAcquireResourceExclusiveLite(&Vcb->MetaLock, TRUE);

    DEBUG(DL_INF, ("Ext2FreeBlock: Block %xh - %x to be freed.\n",
                   Block, Block + Number));

    Group = (Block - EXT2_FIRST_DATA_BLOCK) / BLOCKS_PER_GROUP;
    Index = (Block - EXT2_FIRST_DATA_BLOCK) % BLOCKS_PER_GROUP;

Again:

    if ( Block < EXT2_FIRST_DATA_BLOCK ||
            Block >= TOTAL_BLOCKS ||
            Group >= Vcb->sbi.s_groups_count) {

        DbgBreak();
        Status = STATUS_SUCCESS;

    } else  {

        group_desc = ext4_get_group_desc(sb, Group, NULL);
        if (!group_desc) {
            DbgBreak();
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto errorout;
        }
        bitmap_blk = ext4_block_bitmap(sb, group_desc);

        /* check the block is valid or not */
        if (bitmap_blk >= TOTAL_BLOCKS) {
            DbgBreak();
            Status = STATUS_DISK_CORRUPT_ERROR;
            goto errorout;
        }

        /* get bitmap block offset and length */
        Offset.QuadPart = bitmap_blk;
        Offset.QuadPart = Offset.QuadPart << BLOCK_BITS;

        if (Group == Vcb->sbi.s_groups_count - 1) {

            Length = (ULONG)(TOTAL_BLOCKS % BLOCKS_PER_GROUP);

            /* s_blocks_count is integer multiple of s_blocks_per_group */
            if (Length == 0) {
                Length = BLOCKS_PER_GROUP;
            }

        } else {
            Length = BLOCKS_PER_GROUP;
        }

        /* read and initialize bitmap */
        if (!CcPinRead( Vcb->Volume,
                        &Offset,
                        Vcb->BlockSize,
                        PIN_WAIT,
                        &BitmapBcb,
                        &BitmapCache ) ) {

            DEBUG(DL_ERR, ("Ext2FreeBlock: failed to PinLock bitmap block %xh.\n",
                           bitmap_blk));
            Status = STATUS_CANT_WAIT;
            DbgBreak();
            goto errorout;
        }

        /* clear usused bits */
        RtlInitializeBitMap(&BlockBitmap, BitmapCache, Length);
        Count = min(Length - Index, Number);
        RtlClearBits(&BlockBitmap, Index, Count);

        /* update group description table */
        ext4_free_blks_set(sb, group_desc, RtlNumberOfClearBits(&BlockBitmap));

        /* indict the cache range is dirty */
        CcSetDirtyPinnedData(BitmapBcb, NULL );
        CcUnpinData(BitmapBcb);
        BitmapBcb = NULL;
        BitmapCache = NULL;
        Ext2AddVcbExtent(Vcb, Offset.QuadPart, (LONGLONG)Vcb->BlockSize);
        Ext2SaveGroup(IrpContext, Vcb, Group);

        /* save super block (used/unused blocks statics) */
        Ext2UpdateVcbStat(IrpContext, Vcb);

        /* try next group to clear all remaining */
        Number -= Count;
        if (Number) {
            Group += 1;
            if (Group < Vcb->sbi.s_groups_count) {
                Index = 0;
                Block += Count;
                goto Again;
            } else {
                DEBUG(DL_ERR, ("Ext2FreeBlock: block number beyonds max group.\n"));
                goto errorout;
            }
        }
    }

    Status = STATUS_SUCCESS;

errorout:

    ExReleaseResourceLite(&Vcb->MetaLock);

    return Status;
}

NTSTATUS
Ext2ExpandLast(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN PEXT2_MCB            Mcb,
    IN ULONG                Base,
    IN ULONG                Layer,
    IN PULONG *             Data,
    IN PULONG               Hint,
    IN PULONG               Block,
    IN OUT PULONG           Number
)
{
    PULONG      pData = NULL;
    ULONG       i;
    NTSTATUS    Status = STATUS_SUCCESS;

    if (Layer > 0 || IsMcbDirectory(Mcb)) {

        /* allocate buffer for new block */
        pData = (ULONG *) Ext2AllocatePool(
                    PagedPool,
                    BLOCK_SIZE,
                    EXT2_DATA_MAGIC
                );
        if (!pData) {
            DEBUG(DL_ERR, ( "Ex2ExpandBlock: failed to allocate memory for Data.\n"));
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto errorout;
        }
        RtlZeroMemory(pData, BLOCK_SIZE);
        INC_MEM_COUNT(PS_BLOCK_DATA, pData, BLOCK_SIZE);
    }

    /* allocate block from disk */
    Status = Ext2NewBlock(
                 IrpContext,
                 Vcb,
                 (Mcb->Inode.i_ino - 1) / BLOCKS_PER_GROUP,
                 *Hint,
                 Block,
                 Number
             );

    if (!NT_SUCCESS(Status)) {
        goto errorout;
    }

    /* increase inode i_blocks */
    Mcb->Inode.i_blocks += (*Number * (BLOCK_SIZE >> 9));

    if (Layer == 0) {

        if (IsMcbDirectory(Mcb)) {

            /* for directory we need initialize it's entry structure */
            PEXT2_DIR_ENTRY2 pEntry;
            pEntry = (PEXT2_DIR_ENTRY2) pData;
            pEntry->rec_len = (USHORT)(BLOCK_SIZE);
            ASSERT(*Number == 1);
            Ext2SaveBlock(IrpContext, Vcb, *Block, (PVOID)pData);

        } else {

            /* for file we need remove dirty MCB to prevent Volume's writing */
            if (!Ext2RemoveBlockExtent(Vcb, NULL, (*Block), *Number)) {
                DbgBreak();
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto errorout;
            }
        }

        /* add new Extent into Mcb */
        if (!Ext2AddBlockExtent(Vcb, Mcb, Base, (*Block), *Number)) {
            DbgBreak();
            ClearFlag(Mcb->Flags, MCB_ZONE_INIT);
            Ext2ClearAllExtents(&Mcb->Extents);
        }

    } else {

        /* zero the content of all meta blocks */
        for (i = 0; i < *Number; i++) {
            Ext2SaveBlock(IrpContext, Vcb, *Block + i, (PVOID)pData);
        }
    }

errorout:

    if (NT_SUCCESS(Status)) {
        *Hint = *Block + *Number;
        if (Data) {
            *Data = pData;
            ASSERT(*Number == 1);
        } else {
            if (pData) {
                Ext2FreePool(pData, EXT2_DATA_MAGIC);
                DEC_MEM_COUNT(PS_BLOCK_DATA, pData, BLOCK_SIZE);
            }
        }
    } else {
        if (pData) {
            Ext2FreePool(pData, EXT2_DATA_MAGIC);
            DEC_MEM_COUNT(PS_BLOCK_DATA, pData, BLOCK_SIZE);
        }
        if (*Block) {
            Ext2FreeBlock(IrpContext, Vcb, *Block, *Number);
            *Block = 0;
        }
    }

    return Status;
}

NTSTATUS
Ext2ExpandBlock(
    IN PEXT2_IRP_CONTEXT IrpContext,
    IN PEXT2_VCB         Vcb,
    IN PEXT2_MCB         Mcb,
    IN ULONG             Base,
    IN ULONG             Layer,
    IN ULONG             Start,
    IN ULONG             SizeArray,
    IN PULONG            BlockArray,
    IN PULONG            Hint,
    IN PULONG            Extra
)
{
    ULONG       i = 0;
    ULONG       j;
    ULONG       Slot;
    ULONG       Block = 0;
    LARGE_INTEGER Offset;

    PBCB        Bcb = NULL;
    PULONG      pData = NULL;
    ULONG       Skip = 0;

    ULONG       Number;
    ULONG       Wanted;

    NTSTATUS    Status = STATUS_SUCCESS;

    if (Layer == 1) {

        /* try to make all leaf block continuous to avoid fragments */
        Number = min(SizeArray, ((*Extra + (Start & (BLOCK_SIZE/4 - 1))) * 4 / BLOCK_SIZE));
        Wanted = 0;
        DEBUG(DL_BLK, ("Ext2ExpandBlock: SizeArray=%xh Extra=%xh Start=%xh %xh\n",
                       SizeArray, *Extra, Start, Number ));

        for (i=0; i < Number; i++) {
            if (BlockArray[i] == 0) {
                Wanted += 1;
            }
        }

        i = 0;
        while (Wanted > 0) {

            Number = Wanted;
            Status = Ext2ExpandLast(
                         IrpContext,
                         Vcb,
                         Mcb,
                         Base,
                         Layer,
                         NULL,
                         Hint,
                         &Block,
                         &Number
                     );
            if (!NT_SUCCESS(Status)) {
                goto errorout;
            }

            ASSERT(Number > 0);
            Wanted -= Number;
            while (Number) {
                if (BlockArray[i] == 0) {
                    BlockArray[i] = Block++;
                    Number--;
                }
                i++;
            }
        }

    } else if (Layer == 0) {

        /* bulk allocation for inode data blocks */

        i = 0;

        while (*Extra && i < SizeArray) {

            Wanted = 0;
            Number = 1;

            for (j = i; j < SizeArray && j < i + *Extra; j++) {

                if (BlockArray[j] >= TOTAL_BLOCKS) {
                    DbgBreak();
                    BlockArray[j] = 0;
                }

                if (BlockArray[j] == 0) {
                    Wanted += 1;
                } else {
                    break;
                }
            }

            if (Wanted == 0) {

                /* add block extent into Mcb */
                ASSERT(BlockArray[i] != 0);
                if (!Ext2AddBlockExtent(Vcb, Mcb, Base + i, BlockArray[i], 1)) {
                    DbgBreak();
                    ClearFlag(Mcb->Flags, MCB_ZONE_INIT);
                    Ext2ClearAllExtents(&Mcb->Extents);
                }

            } else {

                Number = Wanted;
                Status = Ext2ExpandLast(
                             IrpContext,
                             Vcb,
                             Mcb,
                             Base + i,
                             0,
                             NULL,
                             Hint,
                             &Block,
                             &Number
                         );
                if (!NT_SUCCESS(Status)) {
                    goto errorout;
                }

                ASSERT(Number > 0);
                for (j = 0; j < Number; j++) {
                    BlockArray[i + j] = Block++;
                }
            }

            *Extra -= Number;
            i += Number;
        }

        goto errorout;
    }

    for (i = 0; *Extra && i < SizeArray; i++) {

        if (Layer <= 3) {

            if (BlockArray[i] >= TOTAL_BLOCKS) {
                DbgBreak();
                BlockArray[i] = 0;
            }

            if (BlockArray[i] == 0) {
                Number = 1;
                Status = Ext2ExpandLast(
                             IrpContext,
                             Vcb,
                             Mcb,
                             Base,
                             Layer,
                             &pData,
                             Hint,
                             &BlockArray[i],
                             &Number
                         );
                if (!NT_SUCCESS(Status)) {
                    goto errorout;
                }

            } else {

                Offset.QuadPart = (((LONGLONG)BlockArray[i]) << BLOCK_BITS);
                if (!CcPinRead(
                            Vcb->Volume,
                            &Offset,
                            BLOCK_SIZE,
                            PIN_WAIT,
                            &Bcb,
                            &pData )) {

                    DEBUG(DL_ERR, ( "Ext2ExpandInode: failed to PinLock offset :%I64xh...\n",
                                    Offset.QuadPart));
                    Status = STATUS_CANT_WAIT;
                    DbgBreak();
                    goto errorout;
                }
            }

            Skip = Vcb->max_blocks_per_layer[Layer] * i;

            if (i == 0) {
                if (Layer > 1) {
                    Slot  = Start / Vcb->max_blocks_per_layer[Layer - 1];
                    Start = Start % Vcb->max_blocks_per_layer[Layer - 1];
                    Skip += Slot * Vcb->max_blocks_per_layer[Layer - 1];
                } else {
                    Slot  = Start;
                    Start = 0;
                    Skip += Slot;
                }
            } else {
                Start = 0;
                Slot  = 0;
            }

            Status = Ext2ExpandBlock(
                         IrpContext,
                         Vcb,
                         Mcb,
                         Base + Skip,
                         Layer - 1,
                         Start,
                         BLOCK_SIZE/4 - Slot,
                         &pData[Slot],
                         Hint,
                         Extra
                     );

            if (Bcb) {
                CcSetDirtyPinnedData(Bcb, NULL);
                if (!Ext2AddBlockExtent(Vcb, NULL,
                                        BlockArray[i],
                                        BlockArray[i], 1)) {
                    DbgBreak();
                    Ext2Sleep(500);
                    if (!Ext2AddBlockExtent(Vcb, NULL,
                                            BlockArray[i],
                                            BlockArray[i], 1)) {
                    }
                }
            } else {
                Ext2SaveBlock(IrpContext, Vcb, BlockArray[i], (PVOID)pData);
            }

            if (pData) {
                if (Bcb) {
                    CcUnpinData(Bcb);
                    Bcb = NULL;
                } else {
                    Ext2FreePool(pData, EXT2_DATA_MAGIC);
                    DEC_MEM_COUNT(PS_BLOCK_DATA, pData, BLOCK_SIZE);
                }
                pData = NULL;
            }

            if (!NT_SUCCESS(Status)) {
                DbgBreak();
                break;
            }
        }
    }

errorout:

    return Status;
}

BOOLEAN
Ext2IsBlockEmpty(PULONG BlockArray, ULONG SizeArray)
{
    ULONG i = 0;
    for (i=0; i < SizeArray; i++) {
        if (BlockArray[i]) {
            break;
        }
    }
    return (i == SizeArray);
}


NTSTATUS
Ext2TruncateBlock(
    IN PEXT2_IRP_CONTEXT IrpContext,
    IN PEXT2_VCB         Vcb,
    IN PEXT2_MCB         Mcb,
    IN ULONG             Base,
    IN ULONG             Start,
    IN ULONG             Layer,
    IN ULONG             SizeArray,
    IN PULONG            BlockArray,
    IN PULONG            Extra
)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    ULONG       i = 0;
    ULONG       Slot = 0;
    ULONG       Skip = 0;

    LONGLONG    Offset;
    PBCB        Bcb = NULL;
    PULONG      pData = NULL;

    ASSERT(Mcb != NULL);

    for (i = 0; i < SizeArray; i++) {

        if (Layer == 0) {

            ULONG   Number = 1;

            while (Extra &&  SizeArray > i + 1 && Number < *Extra) {

                if (BlockArray[SizeArray - i - 1] ==
                        BlockArray[SizeArray - i - 2] + 1) {

                    BlockArray[SizeArray - i - 1] = 0;
                    Number++;
                    SizeArray--;

                } else {
                    break;
                }
            }

            if (BlockArray[SizeArray - i - 1]) {

                Status = Ext2FreeBlock(IrpContext, Vcb, BlockArray[SizeArray - i - 1], Number);
                if (NT_SUCCESS(Status)) {
#if EXT2_DEBUG
                    if (i == 0 || i == SizeArray - 1 || *Extra == Number) {
                        DEBUG(DL_BLK, ("Ext2TruncateBlock: Vbn: %xh Lbn: %xh Num: %xh\n",
                                       Base + SizeArray - 1 - i, BlockArray[SizeArray - i - 1], Number));
                    }
#endif
                    ASSERT(Mcb->Inode.i_blocks >= Number * (BLOCK_SIZE >> 9));
                    if (Mcb->Inode.i_blocks < Number * (BLOCK_SIZE >> 9)) {
                        Mcb->Inode.i_blocks = 0;
                        DbgBreak();
                    } else {
                        Mcb->Inode.i_blocks -= Number * (BLOCK_SIZE >> 9);
                    }
                    BlockArray[SizeArray - i - 1] = 0;
                }
            }

            if (Extra) {

                /* dec blocks count */
                ASSERT(*Extra >= Number);
                *Extra = *Extra - Number;

                /* remove block mapping frm Mcb Extents */
                if (!Ext2RemoveBlockExtent(Vcb, Mcb, Base + SizeArray - 1 - i, Number)) {
                    DbgBreak();
                    ClearFlag(Mcb->Flags, MCB_ZONE_INIT);
                    Ext2ClearAllExtents(&Mcb->Extents);
                }
            }

        } else {

            ASSERT(Layer <= 3);

            if (BlockArray[SizeArray - i - 1] >= TOTAL_BLOCKS) {
                DbgBreak();
                BlockArray[SizeArray - i - 1] = 0;
            }

            if (i == 0) {
                if (Layer > 1) {
                    Slot  = Start / Vcb->max_blocks_per_layer[Layer - 1];
                    Start = Start % Vcb->max_blocks_per_layer[Layer - 1];
                } else {
                    Slot  = Start;
                    Start = (BLOCK_SIZE / 4) - 1;
                }
            } else {
                Slot = Start = (BLOCK_SIZE / 4) - 1;
            }

            Skip = (SizeArray - i - 1) * Vcb->max_blocks_per_layer[Layer];

            if (BlockArray[SizeArray - i - 1]) {

                Offset = (LONGLONG) (BlockArray[SizeArray - i - 1]);
                Offset = Offset << BLOCK_BITS;

                if (!CcPinRead( Vcb->Volume,
                                (PLARGE_INTEGER) (&Offset),
                                BLOCK_SIZE,
                                PIN_WAIT,
                                &Bcb,
                                &pData )) {

                    DEBUG(DL_ERR, ( "Ext2TruncateBlock: PinLock failed on block %xh ...\n",
                                    BlockArray[SizeArray - i - 1]));
                    Status = STATUS_CANT_WAIT;
                    DbgBreak();
                    goto errorout;
                }

                Status = Ext2TruncateBlock(
                             IrpContext,
                             Vcb,
                             Mcb,
                             Base + Skip,
                             Start,
                             Layer - 1,
                             Slot + 1,
                             &pData[0],
                             Extra
                         );

                if (!NT_SUCCESS(Status)) {
                    break;
                }

                CcSetDirtyPinnedData(Bcb, NULL);
                Ext2AddVcbExtent(Vcb, Offset, (LONGLONG)BLOCK_SIZE);

                if (*Extra || Ext2IsBlockEmpty(pData, BLOCK_SIZE/4)) {

                    Status = Ext2TruncateBlock(
                                 IrpContext,
                                 Vcb,
                                 Mcb,
                                 Base + Skip,    /* base */
                                 0,              /* start */
                                 0,              /* layer */
                                 1,
                                 &BlockArray[SizeArray - i - 1],
                                 NULL
                             );
                }

                if (pData) {
                    CcUnpinData(Bcb);
                    Bcb = NULL;
                    pData = NULL;
                }

            } else {

                if (Layer > 1) {
                    if (*Extra > Slot * Vcb->max_blocks_per_layer[Layer - 1] + Start + 1) {
                        *Extra -= (Slot * Vcb->max_blocks_per_layer[Layer - 1] + Start + 1);
                    } else {
                        *Extra  = 0;
                    }
                } else {
                    if (*Extra > Slot + 1) {
                        *Extra -= (Slot + 1);
                    } else {
                        *Extra  = 0;
                    }
                }

                if (!Ext2RemoveBlockExtent(Vcb, Mcb, Base + Skip, (Start + 1))) {
                    DbgBreak();
                    ClearFlag(Mcb->Flags, MCB_ZONE_INIT);
                    Ext2ClearAllExtents(&Mcb->Extents);
                }
            }
        }

        if (Extra && *Extra == 0) {
            break;
        }
    }

errorout:

    if (pData) {
        CcUnpinData(Bcb);
    }

    return Status;
}

NTSTATUS
Ext2NewInode(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN ULONG                GroupHint,
    IN ULONG                Type,
    OUT PULONG              Inode
)
{
    struct super_block     *sb = &Vcb->sb;
    PEXT2_GROUP_DESC        group_desc;
    struct buffer_head     *bh = NULL;
    ext4_fsblk_t            bitmap_blk;

    RTL_BITMAP      InodeBitmap;

    ULONG           Group, i, j;
    ULONG           Average, Length;

    ULONG           dwInode;

    NTSTATUS        Status = STATUS_DISK_FULL;

    *Inode = dwInode = 0XFFFFFFFF;

    ExAcquireResourceExclusiveLite(&Vcb->MetaLock, TRUE);

repeat:

    if (bh) {
        __brelse(bh);
        bh = NULL;
    }

    Group = i = 0;
    group_desc = NULL;

    if (Type == EXT2_FT_DIR) {

        Average = Vcb->SuperBlock->s_free_inodes_count / Vcb->sbi.s_groups_count;

        for (j = 0; j < Vcb->sbi.s_groups_count; j++) {

            i = (j + GroupHint) % (Vcb->sbi.s_groups_count);
            group_desc = ext4_get_group_desc(sb, i, NULL);
            if (!group_desc) {
                DbgBreak();
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto errorout;
            }

            if (group_desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT) ||
                    (ext4_used_dirs_count(sb, group_desc) << 8 <
                     ext4_free_inodes_count(sb, group_desc)) ) {
                Group = i + 1;
                break;
            }
        }

        if (!Group) {

            PEXT2_GROUP_DESC  desc = NULL;

            /* get the group with the biggest vacancy */
            for (j = 0; j < Vcb->sbi.s_groups_count; j++) {

                desc = ext4_get_group_desc(sb, j, NULL);
                if (!desc) {
                    DbgBreak();
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto errorout;
                }

                /* return the group if it's not initialized yet */
                if (desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)) {
                    Group = j + 1;
                    group_desc = desc;
                    break;
                }

                if (!group_desc) {
                    if (ext4_free_inodes_count(sb, desc) > 0) {
                        Group = j + 1;
                        group_desc = desc;
                    }
                } else {
                    if ( ext4_free_inodes_count(sb, desc) >
                            ext4_free_inodes_count(sb, group_desc)) {
                        Group = j + 1;
                        group_desc = desc;
                    }
                }
            }
        }

    } else {

        /*
         * Try to place the inode in its parent directory (GroupHint)
         */

        group_desc = ext4_get_group_desc(sb, GroupHint, NULL);
        if (!group_desc) {
            DbgBreak();
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto errorout;
        }

        if (group_desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT) ||
                ext4_free_inodes_count(sb, group_desc)) {

            Group = GroupHint + 1;

        } else {

            i = GroupHint;

            /*
             * Use a quadratic hash to find a group with a free inode
             */

            for (j = 1; j < Vcb->sbi.s_groups_count; j <<= 1) {

                i = (i + j) % Vcb->sbi.s_groups_count;
                group_desc = ext4_get_group_desc(sb, i, NULL);
                if (!group_desc) {
                    DbgBreak();
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto errorout;
                }

                if (group_desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT) ||
                        ext4_free_inodes_count(sb, group_desc)) {
                    Group = i + 1;
                    break;
                }
            }
        }

        if (!Group) {
            /*
             * That failed: try linear search for a free inode
             */
            i = GroupHint;
            for (j = 2; j < Vcb->sbi.s_groups_count; j++) {

                i = (i + 1) % Vcb->sbi.s_groups_count;
                group_desc = ext4_get_group_desc(sb, i, NULL);
                if (!group_desc) {
                    DbgBreak();
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto errorout;
                }

                if (group_desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT) ||
                        ext4_free_inodes_count(sb, group_desc)) {
                    Group = i + 1;
                    break;
                }
            }
        }
    }

    if (group_desc == NULL || Group == 0) {
        goto errorout;
    }

    /* finally we got the group, but is it valid ? */
    if (Group > Vcb->sbi.s_groups_count) {
        DbgBreak();
        goto errorout;
    }

    /* valid group number starts from 1, not 0 */
    Group -= 1;

    ASSERT(group_desc);
    bitmap_blk = ext4_inode_bitmap(sb, group_desc);
    /* check the block is valid or not */
    if (bitmap_blk == 0 || bitmap_blk >= TOTAL_BLOCKS) {
        DbgBreak();
        Status = STATUS_DISK_CORRUPT_ERROR;
        goto errorout;
    }

    bh = sb_getblk(sb, bitmap_blk);
    if (!bh) {
        DbgBreak();
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    if (group_desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)) {
        ext4_init_inode_bitmap(sb, bh, Group, group_desc);
        set_buffer_uptodate(bh);
    }

    if (Vcb->sbi.s_groups_count == 1) {
        Length = INODES_COUNT;
    } else {
        if (Group + 1 == Vcb->sbi.s_groups_count) {
            Length = INODES_COUNT % INODES_PER_GROUP;
            if (!Length) {
                /* INODES_COUNT is integer multiple of INODES_PER_GROUP */
                Length = INODES_PER_GROUP;
            }
        } else  {
            Length = INODES_PER_GROUP;
        }
    }

    RtlInitializeBitMap(&InodeBitmap, (PULONG)bh->b_data, Length);
    dwInode = RtlFindClearBits(&InodeBitmap, 1, 0);

    if (dwInode == 0xFFFFFFFF || dwInode >= Length) {

        RtlZeroMemory(&InodeBitmap, sizeof(RTL_BITMAP));
        if (ext4_free_inodes_count(sb, group_desc) > 0) {
            ext4_free_inodes_set(sb, group_desc, 0);
            Ext2SaveGroup(IrpContext, Vcb, Group);
        }
        goto repeat;

    } else {

        __u32 count = 0;

        /* update unused inodes count */
        count = ext4_free_inodes_count(sb, group_desc) - 1;
        ext4_free_inodes_set(sb, group_desc, count);

        RtlSetBits(&InodeBitmap, dwInode, 1);

        /* set block bitmap dirty in cache */
        mark_buffer_dirty(bh);

        /* If we didn't allocate from within the initialized part of the inode
         * table then we need to initialize up to this inode. */
        if (EXT3_HAS_RO_COMPAT_FEATURE(sb, EXT4_FEATURE_RO_COMPAT_GDT_CSUM)) {

            __u32 free;

            if (group_desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)) {
                group_desc->bg_flags &= cpu_to_le16(~EXT4_BG_INODE_UNINIT);
                /* When marking the block group with
                 * ~EXT4_BG_INODE_UNINIT we don't want to depend
                 * on the value of bg_itable_unused even though
                 * mke2fs could have initialized the same for us.
                 * Instead we calculated the value below
                 */

                free = 0;
            } else {
                free = EXT3_INODES_PER_GROUP(sb) - ext4_itable_unused_count(sb, group_desc);
            }

            /*
             * Check the relative inode number against the last used
             * relative inode number in this group. if it is greater
             * we need to  update the bg_itable_unused count
             *
             */
            if (dwInode + 1 > free) {
                ext4_itable_unused_set(sb, group_desc,
                                       (EXT3_INODES_PER_GROUP(sb) - 1 - dwInode));
            }

            /* We may have to initialize the block bitmap if it isn't already */
            if (group_desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {

                struct buffer_head *block_bitmap_bh;

                /* recheck and clear flag under lock if we still need to */
                block_bitmap_bh = sb_getblk(sb, ext4_block_bitmap(sb, group_desc));
                if (block_bitmap_bh && group_desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
                    group_desc->bg_checksum = ext4_group_desc_csum(EXT3_SB(sb), Group, group_desc);
                    free = ext4_init_block_bitmap(sb, block_bitmap_bh, Group, group_desc);
                    group_desc->bg_flags &= cpu_to_le16(~EXT4_BG_BLOCK_UNINIT);
                    ext4_free_blks_set(sb, group_desc, free);
                }
                if (block_bitmap_bh)
                    brelse(block_bitmap_bh);
            }

        }

        *Inode = dwInode + 1 + Group * INODES_PER_GROUP;

        /* update group_desc / super_block */
        if (Type == EXT2_FT_DIR) {
            ext4_used_dirs_set(sb, group_desc, ext4_used_dirs_count(sb, group_desc) + 1);
        }
        Ext2SaveGroup(IrpContext, Vcb, Group);
        Ext2UpdateVcbStat(IrpContext, Vcb);
        Status = STATUS_SUCCESS;
    }

errorout:

    ExReleaseResourceLite(&Vcb->MetaLock);

    if (bh) {
        brelse(bh);
    }

    return Status;
}

NTSTATUS
Ext2FreeInode(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN ULONG                Inode,
    IN ULONG                Type
)
{
    struct super_block     *sb = &Vcb->sb;
    PEXT2_GROUP_DESC        group_desc;
    struct buffer_head     *bh = NULL;
    ext4_fsblk_t            bitmap_blk;

    RTL_BITMAP      InodeBitmap;
    ULONG           Group;
    ULONG           Length;
    LARGE_INTEGER   Offset;

    ULONG           dwIno;
    BOOLEAN         bModified = FALSE;

    NTSTATUS        Status = STATUS_UNSUCCESSFUL;

    ExAcquireResourceExclusiveLite(&Vcb->MetaLock, TRUE);

    Group = (Inode - 1) / INODES_PER_GROUP;
    dwIno = (Inode - 1) % INODES_PER_GROUP;

    DEBUG(DL_INF, ( "Ext2FreeInode: Inode: %xh (Group/Off = %xh/%xh)\n",
                    Inode, Group, dwIno));

    if (Group >= Vcb->sbi.s_groups_count)  {
        DbgBreak();
        goto errorout;
    }

    group_desc = ext4_get_group_desc(sb, Group, NULL);
    if (!group_desc) {
        DbgBreak();
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    bitmap_blk = ext4_inode_bitmap(sb, group_desc);
    bh = sb_getblk(sb, bitmap_blk);
    if (!bh) {
        DbgBreak();
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    if (Group == Vcb->sbi.s_groups_count - 1) {

        Length = INODES_COUNT % INODES_PER_GROUP;
        if (!Length) {
            /* s_inodes_count is integer multiple of s_inodes_per_group */
            Length = INODES_PER_GROUP;
        }
    } else {
        Length = INODES_PER_GROUP;
    }

    RtlInitializeBitMap(&InodeBitmap, (PULONG)bh->b_data, Length);

    if (RtlCheckBit(&InodeBitmap, dwIno) == 0) {
        DbgBreak();
        Status = STATUS_SUCCESS;
    } else {
        RtlClearBits(&InodeBitmap, dwIno, 1);
        bModified = TRUE;
    }

    if (bModified) {
        /* update group free inodes */
        ext4_free_inodes_set(sb, group_desc,
                             RtlNumberOfClearBits(&InodeBitmap));

        /* set inode block dirty and add to vcb dirty range */
        mark_buffer_dirty(bh);

        /* update group_desc and super_block */
        if (Type == EXT2_FT_DIR) {
            ext4_used_dirs_set(sb, group_desc,
                               ext4_used_dirs_count(sb, group_desc) - 1);
        }
        Ext2SaveGroup(IrpContext, Vcb, Group);
        Ext2UpdateVcbStat(IrpContext, Vcb);
        Status = STATUS_SUCCESS;
    }

errorout:

    ExReleaseResourceLite(&Vcb->MetaLock);

    if (bh) {
        brelse(bh);
    }
    return Status;
}


NTSTATUS
Ext2AddEntry (
    IN PEXT2_IRP_CONTEXT   IrpContext,
    IN PEXT2_VCB           Vcb,
    IN PEXT2_FCB           Dcb,
    IN struct inode       *Inode,
    IN PUNICODE_STRING     FileName,
    struct dentry        **Dentry
)
{
    struct dentry          *de = NULL;

    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    OEM_STRING              oem;
    int                     rc;

    BOOLEAN                 MainResourceAcquired = FALSE;

    if (!IsDirectory(Dcb)) {
        DbgBreak();
        return STATUS_NOT_A_DIRECTORY;
    }

    ExAcquireResourceExclusiveLite(&Dcb->MainResource, TRUE);
    MainResourceAcquired = TRUE;

    __try {

        Ext2ReferXcb(&Dcb->ReferenceCount);
        de = Ext2BuildEntry(Vcb, Dcb->Mcb, FileName);
        if (!de) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        de->d_inode = Inode;

        rc = ext3_add_entry(IrpContext, de, Inode);
        status = Ext2WinntError(rc);
        if (NT_SUCCESS(status)) {

            /* increase dir inode's nlink for .. */
            if (S_ISDIR(Inode->i_mode)) {
                ext3_inc_count(Dcb->Inode);
                ext3_mark_inode_dirty(IrpContext, Dcb->Inode);
            }

            /* increase inode nlink reference */
            ext3_inc_count(Inode);
            ext3_mark_inode_dirty(IrpContext, Inode);

            *Dentry = de;
            de = NULL;
        }

    } __finally {

        Ext2DerefXcb(&Dcb->ReferenceCount);

        if (MainResourceAcquired)    {
            ExReleaseResourceLite(&Dcb->MainResource);
        }

        if (de)
            Ext2FreeEntry(de);
    }

    return status;
}


NTSTATUS
Ext2RemoveEntry (
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN PEXT2_FCB            Dcb,
    IN PEXT2_MCB            Mcb
)
{
    struct inode *dir = Dcb->Inode;
    struct buffer_head *bh = NULL;
    struct ext3_dir_entry_2 *de;
    struct inode *inode;
    int rc = -ENOENT;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    BOOLEAN  MainResourceAcquired = FALSE;

    if (!IsDirectory(Dcb)) {
        return STATUS_NOT_A_DIRECTORY;
    }

    ExAcquireResourceExclusiveLite(&Dcb->MainResource, TRUE);
    MainResourceAcquired = TRUE;

    __try {

        Ext2ReferXcb(&Dcb->ReferenceCount);

        bh = ext3_find_entry(IrpContext, Mcb->de, &de);
        if (!bh)
            __leave;

        inode = &Mcb->Inode;
        if (le32_to_cpu(de->inode) != inode->i_ino)
            __leave;

        if (!inode->i_nlink) {
            ext3_warning (inode->i_sb, "ext3_unlink",
                          "Deleting nonexistent file (%lu), %d",
                          inode->i_ino, inode->i_nlink);
            inode->i_nlink = 1;
        }
        rc = ext3_delete_entry(IrpContext, dir, de, bh);
        if (rc) {
            Status = Ext2WinntError(rc);
            __leave;
        }
        /*
        	    if (!inode->i_nlink)
        		    ext3_orphan_add(handle, inode);
        */
        inode->i_ctime = dir->i_ctime = dir->i_mtime = ext3_current_time(dir);
        ext3_dec_count(inode);
        ext3_mark_inode_dirty(IrpContext, inode);

        /* decrease dir inode's nlink for .. */
        if (S_ISDIR(inode->i_mode)) {
            ext3_update_dx_flag(dir);
            ext3_dec_count(dir);
            ext3_mark_inode_dirty(IrpContext, dir);
        }

        Status = STATUS_SUCCESS;

    } __finally {

        Ext2DerefXcb(&Dcb->ReferenceCount);

        if (MainResourceAcquired)
            ExReleaseResourceLite(&Dcb->MainResource);

        if (bh)
            brelse(bh);
    }

    return Status;
}

NTSTATUS
Ext2SetParentEntry (
    IN PEXT2_IRP_CONTEXT   IrpContext,
    IN PEXT2_VCB           Vcb,
    IN PEXT2_FCB           Dcb,
    IN ULONG               OldParent,
    IN ULONG               NewParent )
{
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;

    PEXT2_DIR_ENTRY2        pSelf   = NULL;
    PEXT2_DIR_ENTRY2        pParent = NULL;

    ULONG                   dwBytes = 0;

    BOOLEAN                 MainResourceAcquired = FALSE;

    ULONG                   Offset = 0;

    if (!IsDirectory(Dcb)) {
        return STATUS_NOT_A_DIRECTORY;
    }

    MainResourceAcquired =
        ExAcquireResourceExclusiveLite(&Dcb->MainResource, TRUE);

    __try {

        Ext2ReferXcb(&Dcb->ReferenceCount);

        pSelf = (PEXT2_DIR_ENTRY2)
                Ext2AllocatePool(
                    PagedPool,
                    EXT2_DIR_REC_LEN(1) + EXT2_DIR_REC_LEN(2),
                    EXT2_DENTRY_MAGIC
                );
        if (!pSelf) {
            DEBUG(DL_ERR, ( "Ex2SetParentEntry: failed to allocate pSelf.\n"));
            Status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        dwBytes = 0;

        //
        // Reading the DCB contents
        //

        Status = Ext2ReadInode(
                     IrpContext,
                     Vcb,
                     Dcb->Mcb,
                     (ULONGLONG)Offset,
                     (PVOID)pSelf,
                     EXT2_DIR_REC_LEN(1) + EXT2_DIR_REC_LEN(2),
                     FALSE,
                     &dwBytes );

        if (!NT_SUCCESS(Status)) {
            DEBUG(DL_ERR, ( "Ext2SetParentEntry: failed to read directory.\n"));
            __leave;
        }

        ASSERT(dwBytes == EXT2_DIR_REC_LEN(1) + EXT2_DIR_REC_LEN(2));

        pParent = (PEXT2_DIR_ENTRY2)((PUCHAR)pSelf + pSelf->rec_len);

        if (pSelf->name_len == 1 && pSelf->name[0] == '.' &&
                pParent->name_len == 2 && pParent->name[0] == '.' &&
                pParent->name[1] == '.') {

            if (pParent->inode != OldParent) {
                DbgBreak();
            }
            pParent->inode = NewParent;

            Status = Ext2WriteInode(
                         IrpContext,
                         Vcb,
                         Dcb->Mcb,
                         (ULONGLONG)Offset,
                         pSelf,
                         dwBytes,
                         FALSE,
                         &dwBytes );
        } else {
            DbgBreak();
        }

    } __finally {


        if (Ext2DerefXcb(&Dcb->ReferenceCount) == 0) {
            DEBUG(DL_ERR, ( "Ext2SetParentEntry: Dcb reference goes to ZERO.\n"));
        }

        if (MainResourceAcquired)    {
            ExReleaseResourceLite(&Dcb->MainResource);
        }

        if (pSelf) {
            Ext2FreePool(pSelf, EXT2_DENTRY_MAGIC);
        }
    }

    return Status;
}

int ext3_check_dir_entry (const char * function, struct inode * dir,
                          struct ext3_dir_entry_2 * de,
                          struct buffer_head * bh,
                          unsigned long offset)
{
    const char * error_msg = NULL;
    const int rlen = ext3_rec_len_from_disk(de->rec_len);

    if (rlen < EXT3_DIR_REC_LEN(1))
        error_msg = "rec_len is smaller than minimal";
    else if (rlen % 4 != 0)
        error_msg = "rec_len % 4 != 0";
    else if (rlen < EXT3_DIR_REC_LEN(de->name_len))
        error_msg = "rec_len is too small for name_len";
    else if ((char *) de + rlen > bh->b_data + dir->i_sb->s_blocksize)
        error_msg = "directory entry across blocks";
    else if (le32_to_cpu(de->inode) >
             le32_to_cpu(EXT3_SB(dir->i_sb)->s_es->s_inodes_count))
        error_msg = "inode out of bounds";

    if (error_msg != NULL) {
        DEBUG(DL_ERR, ("%s: bad entry in directory %u: %s - "
                       "offset=%u, inode=%u, rec_len=%d, name_len=%d\n",
                       function, dir->i_ino, error_msg, offset,
                       (unsigned long) le32_to_cpu(de->inode),
                       rlen, de->name_len));
    }
    return error_msg == NULL ? 1 : 0;
}


/*
 * p is at least 6 bytes before the end of page
 */
struct ext3_dir_entry_2 *
            ext3_next_entry(struct ext3_dir_entry_2 *p)
{
    return (struct ext3_dir_entry_2 *)((char *)p +
                                       ext3_rec_len_from_disk(p->rec_len));
}

#define MAX_LFS_FILESIZE 	0x7fffffffffffffff

/*
 * Maximal extent format file size.
 * Resulting logical blkno at s_maxbytes must fit in our on-disk
 * extent format containers, within a sector_t, and within i_blocks
 * in the vfs.  ext4 inode has 48 bits of i_block in fsblock units,
 * so that won't be a limiting factor.
 *
 * Note, this does *not* consider any metadata overhead for vfs i_blocks.
 */
static loff_t ext4_max_size(int blkbits, int has_huge_files)
{
    loff_t res;
    loff_t upper_limit = MAX_LFS_FILESIZE;

    /* small i_blocks in vfs inode? */
    if (!has_huge_files || sizeof(blkcnt_t) < sizeof(u64)) {
        /*
         * CONFIG_LBD is not enabled implies the inode
         * i_block represent total blocks in 512 bytes
         * 32 == size of vfs inode i_blocks * 8
         */
        upper_limit = (1LL << 32) - 1;

        /* total blocks in file system block size */
        upper_limit >>= (blkbits - 9);
        upper_limit <<= blkbits;
    }

    /* 32-bit extent-start container, ee_block */
    res = 1LL << 32;
    res <<= blkbits;
    res -= 1;

    /* Sanity check against vm- & vfs- imposed limits */
    if (res > upper_limit)
        res = upper_limit;

    return res;
}

/*
 * Maximal extent format file size.
 * Resulting logical blkno at s_maxbytes must fit in our on-disk
 * extent format containers, within a sector_t, and within i_blocks
 * in the vfs.  ext4 inode has 48 bits of i_block in fsblock units,
 * so that won't be a limiting factor.
 *
 * Note, this does *not* consider any metadata overhead for vfs i_blocks.
 */
loff_t ext3_max_size(int blkbits, int has_huge_files)
{
    loff_t res;
    loff_t upper_limit = MAX_LFS_FILESIZE;

    /* small i_blocks in vfs inode? */
    if (!has_huge_files) {
        /*
         * CONFIG_LBD is not enabled implies the inode
         * i_block represent total blocks in 512 bytes
         * 32 == size of vfs inode i_blocks * 8
         */
        upper_limit = ((loff_t)1 << 32) - 1;

        /* total blocks in file system block size */
        upper_limit >>= (blkbits - 9);
        upper_limit <<= blkbits;
    }

    /* 32-bit extent-start container, ee_block */
    res = (loff_t)1 << 32;
    res <<= blkbits;
    res -= 1;

    /* Sanity check against vm- & vfs- imposed limits */
    if (res > upper_limit)
        res = upper_limit;

    return res;
}

/*
 * Maximal bitmap file size.  There is a direct, and {,double-,triple-}indirect
 * block limit, and also a limit of (2^48 - 1) 512-byte sectors in i_blocks.
 * We need to be 1 filesystem block less than the 2^48 sector limit.
 */
loff_t ext3_max_bitmap_size(int bits, int has_huge_files)
{
    loff_t res = EXT3_NDIR_BLOCKS;
    int meta_blocks;
    loff_t upper_limit;
    /* This is calculated to be the largest file size for a
     * dense, bitmapped file such that the total number of
     * sectors in the file, including data and all indirect blocks,
     * does not exceed 2^48 -1
     * __u32 i_blocks_lo and _u16 i_blocks_high representing the
     * total number of  512 bytes blocks of the file
     */

    if (!has_huge_files) {
        /*
         * !has_huge_files or CONFIG_LBD is not enabled
         * implies the inode i_block represent total blocks in
         * 512 bytes 32 == size of vfs inode i_blocks * 8
         */
        upper_limit = ((loff_t)1 << 32) - 1;

        /* total blocks in file system block size */
        upper_limit >>= (bits - 9);

    } else {
        /*
         * We use 48 bit ext4_inode i_blocks
         * With EXT4_HUGE_FILE_FL set the i_blocks
         * represent total number of blocks in
         * file system block size
         */
        upper_limit = ((loff_t)1 << 48) - 1;

    }

    /* indirect blocks */
    meta_blocks = 1;
    /* double indirect blocks */
    meta_blocks += 1 + ((loff_t)1 << (bits-2));
    /* tripple indirect blocks */
    meta_blocks += 1 + ((loff_t)1 << (bits-2)) + ((loff_t)1 << (2*(bits-2)));

    upper_limit -= meta_blocks;
    upper_limit <<= bits;

    res += (loff_t)1 << (bits-2);
    res += (loff_t)1 << (2*(bits-2));
    res += (loff_t)1 << (3*(bits-2));
    res <<= bits;
    if (res > upper_limit)
        res = upper_limit;

    if (res > MAX_LFS_FILESIZE)
        res = MAX_LFS_FILESIZE;

    return res;
}

blkcnt_t ext3_inode_blocks(struct ext3_inode *raw_inode,
                           struct inode *inode)
{
    blkcnt_t i_blocks ;
    struct super_block *sb = inode->i_sb;
    PEXT2_VCB Vcb = (PEXT2_VCB)sb->s_priv;

    if (EXT3_HAS_RO_COMPAT_FEATURE(sb,
                                   EXT4_FEATURE_RO_COMPAT_HUGE_FILE)) {
        /* we are using combined 48 bit field */
        i_blocks = ((u64)le16_to_cpu(raw_inode->i_blocks_high)) << 32 |
                   le32_to_cpu(raw_inode->i_blocks);
        if (inode->i_flags & EXT4_HUGE_FILE_FL) {
            /* i_blocks represent file system block size */
            return i_blocks  << (BLOCK_BITS - 9);
        } else {
            return i_blocks;
        }
    } else {
        return le32_to_cpu(raw_inode->i_blocks);
    }
}

int ext3_inode_blocks_set(struct ext3_inode *raw_inode,
                          struct inode * inode)
{
    u64 i_blocks = inode->i_blocks;
    struct super_block *sb = inode->i_sb;
    PEXT2_VCB Vcb = (PEXT2_VCB)sb->s_priv;

    if (i_blocks < 0x100000000) {
        /*
         * i_blocks can be represnted in a 32 bit variable
         * as multiple of 512 bytes
         */
        raw_inode->i_blocks = cpu_to_le32(i_blocks);
        raw_inode->i_blocks_high = 0;
        inode->i_flags &= ~EXT4_HUGE_FILE_FL;
        return 0;
    }
    if (!EXT3_HAS_RO_COMPAT_FEATURE(sb, EXT4_FEATURE_RO_COMPAT_HUGE_FILE))
        return -EFBIG;

    if (i_blocks <= 0xffffffffffff) {
        /*
         * i_blocks can be represented in a 48 bit variable
         * as multiple of 512 bytes
         */
        raw_inode->i_blocks = (__u32)cpu_to_le32(i_blocks);
        raw_inode->i_blocks_high = (__u16)cpu_to_le16(i_blocks >> 32);
        inode->i_flags &= ~EXT4_HUGE_FILE_FL;
    } else {
        inode->i_flags |= EXT4_HUGE_FILE_FL;
        /* i_block is stored in file system block size */
        i_blocks = i_blocks >> (BLOCK_BITS - 9);
        raw_inode->i_blocks  = (__u32)cpu_to_le32(i_blocks);
        raw_inode->i_blocks_high = (__u16)cpu_to_le16(i_blocks >> 32);
    }
    return 0;
}

ext4_fsblk_t ext4_block_bitmap(struct super_block *sb,
                               struct ext4_group_desc *bg)
{
    return le32_to_cpu(bg->bg_block_bitmap) |
           (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ?
            (ext4_fsblk_t)le32_to_cpu(bg->bg_block_bitmap_hi) << 32 : 0);
}

ext4_fsblk_t ext4_inode_bitmap(struct super_block *sb,
                               struct ext4_group_desc *bg)
{
    return le32_to_cpu(bg->bg_inode_bitmap) |
           (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ?
            (ext4_fsblk_t)le32_to_cpu(bg->bg_inode_bitmap_hi) << 32 : 0);
}

ext4_fsblk_t ext4_inode_table(struct super_block *sb,
                              struct ext4_group_desc *bg)
{
    return le32_to_cpu(bg->bg_inode_table) |
           (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ?
            (ext4_fsblk_t)le32_to_cpu(bg->bg_inode_table_hi) << 32 : 0);
}

__u32 ext4_free_blks_count(struct super_block *sb,
                           struct ext4_group_desc *bg)
{
    return le16_to_cpu(bg->bg_free_blocks_count) |
           (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ?
            (__u32)le16_to_cpu(bg->bg_free_blocks_count_hi) << 16 : 0);
}

__u32 ext4_free_inodes_count(struct super_block *sb,
                             struct ext4_group_desc *bg)
{
    return le16_to_cpu(bg->bg_free_inodes_count) |
           (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ?
            (__u32)le16_to_cpu(bg->bg_free_inodes_count_hi) << 16 : 0);
}

__u32 ext4_used_dirs_count(struct super_block *sb,
                           struct ext4_group_desc *bg)
{
    return le16_to_cpu(bg->bg_used_dirs_count) |
           (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ?
            (__u32)le16_to_cpu(bg->bg_used_dirs_count_hi) << 16 : 0);
}

__u32 ext4_itable_unused_count(struct super_block *sb,
                               struct ext4_group_desc *bg)
{
    return le16_to_cpu(bg->bg_itable_unused) |
           (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ?
            (__u32)le16_to_cpu(bg->bg_itable_unused_hi) << 16 : 0);
}

void ext4_block_bitmap_set(struct super_block *sb,
                           struct ext4_group_desc *bg, ext4_fsblk_t blk)
{
    bg->bg_block_bitmap = cpu_to_le32((u32)blk);
    if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
        bg->bg_block_bitmap_hi = cpu_to_le32(blk >> 32);
}

void ext4_inode_bitmap_set(struct super_block *sb,
                           struct ext4_group_desc *bg, ext4_fsblk_t blk)
{
    bg->bg_inode_bitmap  = cpu_to_le32((u32)blk);
    if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
        bg->bg_inode_bitmap_hi = cpu_to_le32(blk >> 32);
}

void ext4_inode_table_set(struct super_block *sb,
                          struct ext4_group_desc *bg, ext4_fsblk_t blk)
{
    bg->bg_inode_table = cpu_to_le32((u32)blk);
    if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
        bg->bg_inode_table_hi = cpu_to_le32(blk >> 32);
}

void ext4_free_blks_set(struct super_block *sb,
                        struct ext4_group_desc *bg, __u32 count)
{
    bg->bg_free_blocks_count = cpu_to_le16((__u16)count);
    if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
        bg->bg_free_blocks_count_hi = cpu_to_le16(count >> 16);
}

void ext4_free_inodes_set(struct super_block *sb,
                          struct ext4_group_desc *bg, __u32 count)
{
    bg->bg_free_inodes_count = cpu_to_le16((__u16)count);
    if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
        bg->bg_free_inodes_count_hi = cpu_to_le16(count >> 16);
}

void ext4_used_dirs_set(struct super_block *sb,
                        struct ext4_group_desc *bg, __u32 count)
{
    bg->bg_used_dirs_count = cpu_to_le16((__u16)count);
    if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
        bg->bg_used_dirs_count_hi = cpu_to_le16(count >> 16);
}

void ext4_itable_unused_set(struct super_block *sb,
                            struct ext4_group_desc *bg, __u32 count)
{
    bg->bg_itable_unused = cpu_to_le16((__u16)count);
    if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
        bg->bg_itable_unused_hi = cpu_to_le16(count >> 16);
}

/** CRC table for the CRC-16. The poly is 0x8005 (x16 + x15 + x2 + 1) */
__u16 const crc16_table[256] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

static inline __u16 crc16_byte(__u16 crc, const __u8 data)
{
    return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}

__u16 crc16(__u16 crc, __u8 const *buffer, size_t len)
{
    while (len--)
        crc = crc16_byte(crc, *buffer++);
    return crc;
}

__le16 ext4_group_desc_csum(struct ext3_sb_info *sbi, __u32 block_group,
                            struct ext4_group_desc *gdp)
{
    __u16 crc = 0;

    if (sbi->s_es->s_feature_ro_compat &
            cpu_to_le32(EXT4_FEATURE_RO_COMPAT_GDT_CSUM)) {
        int offset = offsetof(struct ext4_group_desc, bg_checksum);
        __le32 le_group = cpu_to_le32(block_group);

        crc = crc16(~0, sbi->s_es->s_uuid, sizeof(sbi->s_es->s_uuid));
        crc = crc16(crc, (__u8 *)&le_group, sizeof(le_group));
        crc = crc16(crc, (__u8 *)gdp, offset);
        offset += sizeof(gdp->bg_checksum); /* skip checksum */
        /* for checksum of struct ext4_group_desc do the rest...*/
        if ((sbi->s_es->s_feature_incompat &
                cpu_to_le32(EXT4_FEATURE_INCOMPAT_64BIT)) &&
                offset < le16_to_cpu(sbi->s_es->s_desc_size))
            crc = crc16(crc, (__u8 *)gdp + offset,
                        le16_to_cpu(sbi->s_es->s_desc_size) -
                        offset);
    }

    return cpu_to_le16(crc);
}

int ext4_group_desc_csum_verify(struct ext3_sb_info *sbi, __u32 block_group,
                                struct ext4_group_desc *gdp)
{
    if ((sbi->s_es->s_feature_ro_compat &
            cpu_to_le32(EXT4_FEATURE_RO_COMPAT_GDT_CSUM)) &&
            (gdp->bg_checksum != ext4_group_desc_csum(sbi, block_group, gdp)))
        return 0;

    return 1;
}


static inline int test_root(ext3_group_t a, ext3_group_t b)
{
    ext3_group_t num = b;

    while (a > num)
        num *= b;
    return num == a;
}

static int ext3_group_sparse(ext3_group_t group)
{
    if (group <= 1)
        return 1;
    if (!(group & 1))
        return 0;
    return (test_root(group, 7) || test_root(group, 5) ||
            test_root(group, 3));
}

/**
 *	ext4_bg_has_super - number of blocks used by the superblock in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the superblock (primary or backup)
 *	in this group.  Currently this will be only 0 or 1.
 */
int ext3_bg_has_super(struct super_block *sb, ext3_group_t group)
{
    if (EXT3_HAS_RO_COMPAT_FEATURE(sb,
                                   EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER) &&
            !ext3_group_sparse(group))
        return 0;
    return 1;
}

static unsigned long ext4_bg_num_gdb_meta(struct super_block *sb,
        ext4_group_t group)
{
    unsigned long metagroup = group / EXT4_DESC_PER_BLOCK(sb);
    ext4_group_t first = metagroup * EXT4_DESC_PER_BLOCK(sb);
    ext4_group_t last = first + EXT4_DESC_PER_BLOCK(sb) - 1;

    if (group == first || group == first + 1 || group == last)
        return 1;
    return 0;
}

static unsigned long ext4_bg_num_gdb_nometa(struct super_block *sb,
        ext4_group_t group)
{
    return ext3_bg_has_super(sb, group) ? EXT3_SB(sb)->s_gdb_count : 0;
}

/**
 *	ext4_bg_num_gdb - number of blocks used by the group table in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the group descriptor table
 *	(primary or backup) in this group.  In the future there may be a
 *	different number of descriptor blocks in each group.
 */
unsigned long ext4_bg_num_gdb(struct super_block *sb, ext4_group_t group)
{
    unsigned long first_meta_bg =
        le32_to_cpu(EXT3_SB(sb)->s_es->s_first_meta_bg);
    unsigned long metagroup = group / EXT4_DESC_PER_BLOCK(sb);

    if (!EXT3_HAS_INCOMPAT_FEATURE(sb,EXT4_FEATURE_INCOMPAT_META_BG) ||
            metagroup < first_meta_bg)
        return ext4_bg_num_gdb_nometa(sb, group);

    return ext4_bg_num_gdb_meta(sb,group);

}

ext3_fsblk_t descriptor_loc(struct super_block *sb,
                            ext3_fsblk_t logical_sb_block, unsigned int nr)
{
    struct ext3_sb_info *sbi = EXT3_SB(sb);
    ext3_group_t bg, first_meta_bg;
    int has_super = 0;

    first_meta_bg = le32_to_cpu(sbi->s_es->s_first_meta_bg);

    if (!EXT3_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_META_BG) ||
            nr < first_meta_bg)
        return logical_sb_block + nr + 1;
    bg = sbi->s_desc_per_block * nr;
    if (ext3_bg_has_super(sb, bg))
        has_super = 1;
    return (has_super + ext3_group_first_block_no(sb, bg));
}

#define ext4_set_bit(n, p) set_bit((int)(n), (unsigned long *)(p))

/*
 * The free inodes are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.
 */

/*
 * To avoid calling the atomic setbit hundreds or thousands of times, we only
 * need to use it within a single byte (to ensure we get endianness right).
 * We can use memset for the rest of the bitmap as there are no other users.
 */
void mark_bitmap_end(int start_bit, int end_bit, char *bitmap)
{
    int i;

    if (start_bit >= end_bit)
        return;

    DEBUG(DL_INF, ("mark end bits +%d through +%d used\n", start_bit, end_bit));
    for (i = start_bit; (unsigned)i < ((start_bit + 7) & ~7UL); i++)
        ext4_set_bit(i, bitmap);
    if (i < end_bit)
        memset(bitmap + (i >> 3), 0xff, (end_bit - i) >> 3);
}

/* Initializes an uninitialized inode bitmap */
unsigned ext4_init_inode_bitmap(struct super_block *sb, struct buffer_head *bh,
                                ext4_group_t block_group,
                                struct ext4_group_desc *gdp)
{
    struct ext3_sb_info *sbi = EXT3_SB(sb);

    mark_buffer_dirty(bh);

    /* If checksum is bad mark all blocks and inodes use to prevent
     * allocation, essentially implementing a per-group read-only flag. */
    if (!ext4_group_desc_csum_verify(sbi, block_group, gdp)) {
        ext4_error(sb, __FUNCTION__, "Checksum bad for group %u",
                   block_group);
        ext4_free_blks_set(sb, gdp, 0);
        ext4_free_inodes_set(sb, gdp, 0);
        ext4_itable_unused_set(sb, gdp, 0);
        memset(bh->b_data, 0xff, sb->s_blocksize);
        return 0;
    }

    memset(bh->b_data, 0, (EXT4_INODES_PER_GROUP(sb) + 7) / 8);
    mark_bitmap_end(EXT4_INODES_PER_GROUP(sb), sb->s_blocksize * 8,
                    bh->b_data);

    return EXT4_INODES_PER_GROUP(sb);
}

/*
 * Calculate the block group number and offset, given a block number
 */
void ext4_get_group_no_and_offset(struct super_block *sb, ext4_fsblk_t blocknr,
                                  ext4_group_t *blockgrpp, ext4_grpblk_t *offsetp)
{
    struct ext3_super_block *es = EXT3_SB(sb)->s_es;
    ext4_grpblk_t offset;

    blocknr = blocknr - le32_to_cpu(es->s_first_data_block);
    offset = do_div(blocknr, EXT4_BLOCKS_PER_GROUP(sb));
    if (offsetp)
        *offsetp = offset;
    if (blockgrpp)
        *blockgrpp = (ext4_grpblk_t)blocknr;

}

static int ext4_block_in_group(struct super_block *sb, ext4_fsblk_t block,
                               ext4_group_t block_group)
{
    ext4_group_t actual_group;
    ext4_get_group_no_and_offset(sb, block, &actual_group, NULL);
    if (actual_group == block_group)
        return 1;
    return 0;
}

static int ext4_group_used_meta_blocks(struct super_block *sb,
                                       ext4_group_t block_group)
{
    ext4_fsblk_t tmp;
    struct ext3_sb_info *sbi = EXT3_SB(sb);
    /* block bitmap, inode bitmap, and inode table blocks */
    int used_blocks = sbi->s_itb_per_group + 2;

    if (EXT3_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_FLEX_BG)) {
        struct ext4_group_desc *gdp;
        struct buffer_head *bh;

        gdp = ext4_get_group_desc(sb, block_group, &bh);
        if (!ext4_block_in_group(sb, ext4_block_bitmap(sb, gdp),
                                 block_group))
            used_blocks--;

        if (!ext4_block_in_group(sb, ext4_inode_bitmap(sb, gdp),
                                 block_group))
            used_blocks--;

        tmp = ext4_inode_table(sb, gdp);
        for (; tmp < ext4_inode_table(sb, gdp) +
                sbi->s_itb_per_group; tmp++) {
            if (!ext4_block_in_group(sb, tmp, block_group))
                used_blocks -= 1;
        }
    }
    return used_blocks;
}

/* Initializes an uninitialized block bitmap if given, and returns the
 * number of blocks free in the group. */
unsigned ext4_init_block_bitmap(struct super_block *sb, struct buffer_head *bh,
                                ext4_group_t block_group, struct ext4_group_desc *gdp)
{
    int bit, bit_max;
    unsigned free_blocks, group_blocks;
    struct ext3_sb_info *sbi = EXT3_SB(sb);

    if (bh) {
        mark_buffer_dirty(bh);
        /* If checksum is bad mark all blocks used to prevent allocation
         * essentially implementing a per-group read-only flag. */
        if (!ext4_group_desc_csum_verify(sbi, block_group, gdp)) {
            ext4_error(sb, __FUNCTION__,
                       "Checksum bad for group %u", block_group);
            ext4_free_blks_set(sb, gdp, 0);
            ext4_free_inodes_set(sb, gdp, 0);
            ext4_itable_unused_set(sb, gdp, 0);
            memset(bh->b_data, 0xff, sb->s_blocksize);
            return 0;
        }
        memset(bh->b_data, 0, sb->s_blocksize);
    }

    /* Check for superblock and gdt backups in this group */
    bit_max = ext3_bg_has_super(sb, block_group);

    if (!EXT3_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_META_BG) ||
            block_group < le32_to_cpu(sbi->s_es->s_first_meta_bg) *
            sbi->s_desc_per_block) {
        if (bit_max) {
            bit_max += ext4_bg_num_gdb(sb, block_group);
            bit_max +=
                le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks);
        }
    } else { /* For META_BG_BLOCK_GROUPS */
        bit_max += ext4_bg_num_gdb(sb, block_group);
    }

    if (block_group == sbi->s_groups_count - 1) {
        /*
         * Even though mke2fs always initialize first and last group
         * if some other tool enabled the EXT4_BG_BLOCK_UNINIT we need
         * to make sure we calculate the right free blocks
         */
        group_blocks = (unsigned int)(ext3_blocks_count(sbi->s_es) -
                                      le32_to_cpu(sbi->s_es->s_first_data_block) -
                                      (EXT4_BLOCKS_PER_GROUP(sb) * (sbi->s_groups_count - 1)));
    } else {
        group_blocks = EXT4_BLOCKS_PER_GROUP(sb);
    }

    free_blocks = group_blocks - bit_max;

    if (bh) {
        ext4_fsblk_t start, tmp;
        int flex_bg = 0;

        for (bit = 0; bit < bit_max; bit++)
            ext4_set_bit(bit, bh->b_data);

        start = ext3_group_first_block_no(sb, block_group);

        if (EXT3_HAS_INCOMPAT_FEATURE(sb,
                                      EXT4_FEATURE_INCOMPAT_FLEX_BG))
            flex_bg = 1;

        /* Set bits for block and inode bitmaps, and inode table */
        tmp = ext4_block_bitmap(sb, gdp);
        if (!flex_bg || ext4_block_in_group(sb, tmp, block_group))
            ext4_set_bit(tmp - start, bh->b_data);

        tmp = ext4_inode_bitmap(sb, gdp);
        if (!flex_bg || ext4_block_in_group(sb, tmp, block_group))
            ext4_set_bit(tmp - start, bh->b_data);

        tmp = ext4_inode_table(sb, gdp);
        for (; tmp < ext4_inode_table(sb, gdp) +
                sbi->s_itb_per_group; tmp++) {
            if (!flex_bg ||
                    ext4_block_in_group(sb, tmp, block_group))
                ext4_set_bit(tmp - start, bh->b_data);
        }
        /*
         * Also if the number of blocks within the group is
         * less than the blocksize * 8 ( which is the size
         * of bitmap ), set rest of the block bitmap to 1
         */
        mark_bitmap_end(group_blocks, sb->s_blocksize * 8, bh->b_data);
    }
    return free_blocks - ext4_group_used_meta_blocks(sb, block_group);
}

/**
 * ext4_get_group_desc() -- load group descriptor from disk
 * @sb:			super block
 * @block_group:	given block group
 * @bh:			pointer to the buffer head to store the block
 *			group descriptor
 */
struct ext4_group_desc * ext4_get_group_desc(struct super_block *sb,
                    ext4_group_t block_group, struct buffer_head **bh)
{
    unsigned int group_desc;
    unsigned int offset;
    struct ext4_group_desc *desc = NULL;
    struct ext3_sb_info *sbi = EXT3_SB(sb);
    PEXT2_VCB vcb = sb->s_priv;

    if (block_group >= sbi->s_groups_count) {
        ext4_error(sb, "ext4_get_group_desc",
                   "block_group >= groups_count - "
                   "block_group = %u, groups_count = %u",
                   block_group, sbi->s_groups_count);

        return NULL;
    }
    smp_rmb();

    group_desc = block_group >> EXT4_DESC_PER_BLOCK_BITS(sb);
    offset = block_group & (EXT4_DESC_PER_BLOCK(sb) - 1);

    ExAcquireResourceExclusiveLite(&vcb->MetaLock, TRUE);

    if (!sbi->s_group_desc || !sbi->s_group_desc[group_desc]) {
        if (!Ext2LoadGroup(vcb)) {
            ext4_error(sb, "ext4_get_group_desc",
                       "failed to load group desc: "
                       "block_group >= groups_count - "
                       "block_group = %u, groups_count = %u",
                       block_group, sbi->s_groups_count);
            goto errorout;
        }
    }

    if (!sbi->s_group_desc[group_desc]) {
        ext4_error(sb, "ext4_get_group_desc",
                   "Group descriptor not loaded - "
                   "block_group = %u, group_desc = %u, desc = %u",
                   block_group, group_desc, offset);
        goto errorout;
    }

    desc = (struct ext4_group_desc *)(
               (__u8 *)sbi->s_group_desc[group_desc]->b_data +
               offset * EXT4_DESC_SIZE(sb));
    if (bh)
        *bh = sbi->s_group_desc[group_desc];

errorout:

    ExReleaseResourceLite(&vcb->MetaLock);

    return desc;
}

/**
 * ext4_count_free_blocks() -- count filesystem free blocks
 * @sb:		superblock
 *
 * Adds up the number of free blocks from each block group.
 */
ext4_fsblk_t ext4_count_free_blocks(struct super_block *sb)
{
    ext4_fsblk_t desc_count;
    struct ext4_group_desc *gdp;
    ext4_group_t i;
    ext4_group_t ngroups = EXT3_SB(sb)->s_groups_count;

    desc_count = 0;
    smp_rmb();
    for (i = 0; i < ngroups; i++) {
        gdp = ext4_get_group_desc(sb, i, NULL);
        if (!gdp)
            continue;
        desc_count += ext4_free_blks_count(sb, gdp);
    }

    return desc_count;
}

unsigned long ext4_count_free_inodes(struct super_block *sb)
{
    unsigned long desc_count;
    struct ext4_group_desc *gdp;
    ext4_group_t i;

    desc_count = 0;
    for (i = 0; i < EXT3_SB(sb)->s_groups_count; i++) {
        gdp = ext4_get_group_desc(sb, i, NULL);
        if (!gdp)
            continue;
        desc_count += ext4_free_inodes_count(sb, gdp);
        cond_resched();
    }
    return desc_count;
}

/* Called at mount-time, super-block is locked */
unsigned long ext4_count_dirs(struct super_block * sb)
{
    unsigned long count = 0;
    ext4_group_t i;

    for (i = 0; i < EXT3_SB(sb)->s_groups_count; i++) {
        struct ext4_group_desc *gdp = ext4_get_group_desc(sb, i, NULL);
        if (!gdp)
            continue;
        count += ext4_used_dirs_count(sb, gdp);
    }
    return count;
}

/* Called at mount-time, super-block is locked */
int ext4_check_descriptors(struct super_block *sb)
{
    PEXT2_VCB            Vcb = sb->s_priv;
    struct ext3_sb_info *sbi = EXT3_SB(sb);
    ext4_fsblk_t first_block = le32_to_cpu(sbi->s_es->s_first_data_block);
    ext4_fsblk_t last_block;
    ext4_fsblk_t block_bitmap;
    ext4_fsblk_t inode_bitmap;
    ext4_fsblk_t inode_table;
    int flexbg_flag = 0;
    ext4_group_t i;

    if (EXT3_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_FLEX_BG))
        flexbg_flag = 1;

    DEBUG(DL_INF, ("Checking group descriptors"));

    for (i = 0; i < sbi->s_groups_count; i++) {
        struct ext4_group_desc *gdp = ext4_get_group_desc(sb, i, NULL);

        if (i == sbi->s_groups_count - 1 || flexbg_flag)
            last_block = ext3_blocks_count(sbi->s_es) - 1;
        else
            last_block = first_block +
                         (EXT3_BLOCKS_PER_GROUP(sb) - 1);

        block_bitmap = ext4_block_bitmap(sb, gdp);
        if (block_bitmap < first_block || block_bitmap > last_block) {
            printk(KERN_ERR "EXT4-fs: ext4_check_descriptors: "
                   "Block bitmap for group %u not in group "
                   "(block %llu)!\n", i, block_bitmap);
            return 0;
        }
        inode_bitmap = ext4_inode_bitmap(sb, gdp);
        if (inode_bitmap < first_block || inode_bitmap > last_block) {
            printk(KERN_ERR "EXT4-fs: ext4_check_descriptors: "
                   "Inode bitmap for group %u not in group "
                   "(block %llu)!\n", i, inode_bitmap);
            return 0;
        }
        inode_table = ext4_inode_table(sb, gdp);
        if (inode_table < first_block ||
                inode_table + sbi->s_itb_per_group - 1 > last_block) {
            printk(KERN_ERR "EXT4-fs: ext4_check_descriptors: "
                   "Inode table for group %u not in group "
                   "(block %llu)!\n", i, inode_table);
            return 0;
        }

        if (!ext4_group_desc_csum_verify(sbi, i, gdp)) {
            printk(KERN_ERR "EXT4-fs: ext4_check_descriptors: "
                   "Checksum for group %u failed (%u!=%u)\n",
                   i, le16_to_cpu(ext4_group_desc_csum(sbi, i,
                                                       gdp)), le16_to_cpu(gdp->bg_checksum));
            if (!IsFlagOn(Vcb->Flags, VCB_READ_ONLY)) {
                return 0;
            }
        }

        if (!flexbg_flag)
            first_block += EXT4_BLOCKS_PER_GROUP(sb);
    }

    ext3_free_blocks_count_set(sbi->s_es, ext4_count_free_blocks(sb));
    sbi->s_es->s_free_inodes_count = cpu_to_le32(ext4_count_free_inodes(sb));
    return 1;
}
