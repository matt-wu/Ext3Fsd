#include <ext2fs.h>
#include <linux/errno.h>

#define BUFFER_SIZE sizeof(PUBLIC_BCB)

/*
 * extents_bread: This function is a wrapper of CcPinRead routine.
 * 
 * @sb:    the device we need to undergo buffered IO on.
 * @block: the block we want to read from.
 *
 * If the call to this routine succeeds, the pages underlying the buffer header
 * will be locked into memory, so that the buffer header returned for use is safe.
 */
PPUBLIC_BCB 
extents_bread(struct super_block *sb, sector_t block, PVOID *pdata)
{
    PEXT2_VCB Vcb = sb->s_bdev->bd_priv;
    LARGE_INTEGER offset;
    PVOID         ptr;
    unsigned long size = sb->s_blocksize;
    BOOLEAN       ret;

    PPUBLIC_BCB Bcb = NULL;

    /* check the block is valid or not */
    if (block >= TOTAL_BLOCKS) {
        DbgBreak();
        goto errorout;
    }

    offset.QuadPart = (s64)block;
    offset.QuadPart <<= BLOCK_BITS;

    ret = CcPinRead(Vcb->Volume,
                    &offset,
                    size,
                    PIN_WAIT,
                    &Bcb,
                    pdata);

    if (!ret) {
        DbgPrint("Insufficient memory resources!\n");
        Bcb = NULL;
        goto errorout;
    }

    /* we get it */
    INC_MEM_COUNT(PS_EXTENTS_BUFF, Bcb, BUFFER_SIZE);
errorout:
    return Bcb;
}

/*
 * extents_bwrite: This function is a wrapper of CcPreparePinWrite routine.
 * 
 * @sb:    the device we need to undergo buffered IO on.
 * @block: the block we want to write to.
 */
PPUBLIC_BCB 
extents_bwrite(struct super_block *sb, sector_t block, PVOID *pdata)
{
    PEXT2_VCB Vcb = sb->s_bdev->bd_priv;
    LARGE_INTEGER offset;
    PVOID         ptr;
    unsigned long size = sb->s_blocksize;
    BOOLEAN       ret;

    PPUBLIC_BCB Bcb = NULL;

    /* check the block is valid or not */
    if (block >= TOTAL_BLOCKS) {
        DbgBreak();
        goto errorout;
    }

    offset.QuadPart = (s64)block;
    offset.QuadPart <<= BLOCK_BITS;

    SetFlag(Vcb->Volume->Flags, FO_FILE_MODIFIED);
    ret = CcPreparePinWrite(Vcb->Volume,
                            &offset,
                            size,
                            FALSE,
                            PIN_WAIT,
                            &Bcb,
                            pdata);

    if (!ret) {
        DbgPrint("Insufficient memory resources!\n");
        Bcb = NULL;
        goto errorout;
    }

    /* we get it */
    INC_MEM_COUNT(PS_EXTENTS_BUFF, Bcb, BUFFER_SIZE);
errorout:
    return Bcb;
}

/*
 * extents_mark_buffer_dirty: Mark the buffer dirtied and so
 *                            that changes will be written back.
 * 
 * @Bcb: The corresponding buffer header that is modified.
 */
void extents_mark_buffer_dirty(struct super_block *sb, PPUBLIC_BCB Bcb)
{
    PEXT2_VCB Vcb = sb->s_bdev->bd_priv;

    ASSERT(Vcb->Identifier.Type == EXT2VCB);

    CcSetDirtyPinnedData(Bcb, NULL);
    Ext2AddBlockExtent( Vcb, NULL,
                        (ULONG)(Bcb->MappedFileOffset.QuadPart >> BLOCK_BITS),
                        (ULONG)(Bcb->MappedFileOffset.QuadPart >> BLOCK_BITS),
                        (BLOCK_SIZE >> BLOCK_BITS));
}

/*
 * extents_brelse: Release the corresponding buffer header.
 *
 * @Bcb: The corresponding buffer header that is going to be freed.
 *
 * The pages underlying the buffer header will be unlocked.
 */
void extents_brelse(PPUBLIC_BCB Bcb)
{
    if (Bcb == NULL)
        return;

    DEC_MEM_COUNT(PS_EXTENTS_BUFF, Bcb, BUFFER_SIZE);
    CcUnpinData(Bcb);
}
