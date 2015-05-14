#include <ext2fs.h>
#include <linux/errno.h>

#define BUFFER_SIZE sizeof(struct buffer_head)

static NPAGED_LOOKASIDE_LIST extents_cache;
static atomic_t              extents_cache_alloc_count;

/*
 * Initialize extents_cache so that we can allocate buffer
 * header quickly.
 */
int ext4_init_extents_bh()
{
    ExInitializeNPagedLookasideList(
        &extents_cache,
        NULL,
        NULL,
        0,
        BUFFER_SIZE,
        'BTXE',
        0);
    return 0;
}

/*
 * Destroy extents_cache before the driver goes down.
 */
void ext4_destroy_extents_bh()
{
    int buffer_alloc_count = 0;
    ExDeleteNPagedLookasideList(&extents_cache);
    if ((buffer_alloc_count = atomic_read(&extents_cache_alloc_count)) != 0) {
        DbgPrint("EXTENTS_CACHE WARNING: There is buffer yet to be freed !!!\
                  Count: %d\n", buffer_alloc_count);
        DbgBreak();
    }
}

/*
 * Allocate a new buffer header and zero it.
 */
static struct buffer_head *extents_new_buffer_head()
{
    PVOID  bh = NULL;
    bh = ExAllocateFromNPagedLookasideList(&extents_cache);
    if (bh) {
        memset(bh, 0, BUFFER_SIZE);
        DEBUG(DL_BH, ("bh=%p allocated.\n", bh));
        atomic_inc(&extents_cache_alloc_count);
        INC_MEM_COUNT(PS_EXTENTS_BUFF, bh, BUFFER_SIZE);
    }
    return bh;
}

/*
 * Free the buffer header.
 */
static void extents_free_buffer_head(struct buffer_head * bh)
{
    if (bh) {
        DEBUG(DL_BH, ("bh=%p freed.\n", bh));
        ExFreeToNPagedLookasideList(&extents_cache, bh);
        atomic_dec(&extents_cache_alloc_count);
        DEC_MEM_COUNT(PS_EXTENTS_BUFF, bh, BUFFER_SIZE);
    }
}

/*
 * extents_bread: This function is a wrapper of CcPinRead routine.
 * 
 * @sb:    the device we need to undergo buffered IO on.
 * @block: the block we want to read from.
 *
 * If the call to this routine succeeds, the pages underlying the buffer header
 * will be locked into memory, so that the buffer header returned for use is safe.
 */
struct buffer_head *
extents_bread(struct super_block *sb, sector_t block)
{
    PEXT2_VCB Vcb = sb->s_bdev->bd_priv;
    LARGE_INTEGER offset;
    PVOID         ptr;
    unsigned long size = sb->s_blocksize;
    BOOLEAN       ret;

    /* allocate buffer_head and initialize it */
    struct buffer_head *bh = NULL;

    /* check the block is valid or not */
    if (block >= TOTAL_BLOCKS) {
        DbgBreak();
        goto errorout;
    }

    bh = extents_new_buffer_head();
    if (!bh) {
        goto errorout;
    }
    bh->b_bdev = sb->s_bdev;
    bh->b_blocknr = block;
    bh->b_size = size;
    bh->b_data = NULL;

    offset.QuadPart = (s64)block;
    offset.QuadPart <<= BLOCK_BITS;

    ret = CcPinRead(Vcb->Volume,
                    &offset,
                    size,
                    PIN_WAIT,
                    &bh->b_bcb,
                    &ptr);

    if (!ret) {
        DbgPrint("Insufficient memory resources!\n");
        extents_free_buffer_head(bh);
        bh = NULL;
        goto errorout;
    }
    
    bh->b_mdl = Ext2CreateMdl(ptr, TRUE, bh->b_size, IoModifyAccess);
    if (bh->b_mdl) {
        /* muse map the PTE to NonCached zone. journal recovery will
           access the PTE under spinlock: DISPATCH_LEVEL IRQL */
        bh->b_data = MmMapLockedPagesSpecifyCache(
                         bh->b_mdl, KernelMode, MmNonCached,
                         NULL,FALSE, HighPagePriority);
    } else {
        DbgPrint("Unable to make pages resident in memory!\n");
        CcUnpinData(bh->b_bcb);
        extents_free_buffer_head(bh);
        bh = NULL;
        goto errorout;
    }

    set_buffer_new(bh);
    set_buffer_uptodate(bh);
    get_bh(bh);

    /* we get it */
    CcUnpinData(bh->b_bcb);
    bh->b_bcb = NULL;
errorout:
    return bh;
}

/*
 * extents_bwrite: This function is a wrapper of CcPreparePinWrite routine.
 * 
 * @sb:    the device we need to undergo buffered IO on.
 * @block: the block we want to write to.
 */
struct buffer_head *
extents_bwrite(struct super_block *sb, sector_t block)
{
    PEXT2_VCB Vcb = sb->s_bdev->bd_priv;
    LARGE_INTEGER offset;
    PVOID         ptr;
    unsigned long size = sb->s_blocksize;
    BOOLEAN       ret;

    /* allocate buffer_head and initialize it */
    struct buffer_head *bh = NULL;

    /* check the block is valid or not */
    if (block >= TOTAL_BLOCKS) {
        DbgBreak();
        goto errorout;
    }

    bh = extents_new_buffer_head();
    if (!bh) {
        goto errorout;
    }
    bh->b_bdev = sb->s_bdev;
    bh->b_blocknr = block;
    bh->b_size = size;
    bh->b_data = NULL;

    offset.QuadPart = (s64)block;
    offset.QuadPart <<= BLOCK_BITS;

    SetFlag(Vcb->Volume->Flags, FO_FILE_MODIFIED);
    ret = CcPreparePinWrite(Vcb->Volume,
                            &offset,
                            size,
                            FALSE,
                            PIN_WAIT,
                            &bh->b_bcb,
                            &ptr);

    if (!ret) {
        DbgPrint("Insufficient memory resources!\n");
        extents_free_buffer_head(bh);
        bh = NULL;
        goto errorout;
    }

    bh->b_mdl = Ext2CreateMdl(ptr, TRUE, bh->b_size, IoModifyAccess);
    if (bh->b_mdl) {
        /* muse map the PTE to NonCached zone. journal recovery will
           access the PTE under spinlock: DISPATCH_LEVEL IRQL */
        bh->b_data = MmMapLockedPagesSpecifyCache(
                         bh->b_mdl, KernelMode, MmNonCached,
                         NULL,FALSE, HighPagePriority);
    } else {
        DbgPrint("Unable to make pages resident in memory!\n");
        CcUnpinData(bh->b_bcb);
        extents_free_buffer_head(bh);
        bh = NULL;
        goto errorout;
    }
    
    set_buffer_new(bh);
    get_bh(bh);

    /* we get it */
    CcUnpinData(bh->b_bcb);
    bh->b_bcb = NULL;
errorout:
    return bh;
}

/*
 * extents_mark_buffer_dirty: Mark the buffer dirtied and so
 *                            that changes will be written back.
 * 
 * @bh: The corresponding buffer header that is modified.
 */
void extents_mark_buffer_dirty(struct buffer_head *bh)
{
	struct block_device *bdev = bh->b_bdev;
	PEXT2_VCB            Vcb  = bdev->bd_priv;
	PBCB                 Bcb;
	PVOID                Buffer;
	LARGE_INTEGER        Offset;

    if (bh == NULL)
        return;

    bdev = bh->b_bdev;
    Vcb = (PEXT2_VCB)bdev->bd_priv;

    ASSERT(Vcb->Identifier.Type == EXT2VCB);
    ASSERT(bh->b_data);
    
    if (IsVcbReadOnly(Vcb)) {
        return;
    }

    set_buffer_dirty(bh);

	SetFlag(Vcb->Volume->Flags, FO_FILE_MODIFIED);
	Offset.QuadPart = ((LONGLONG)bh->b_blocknr) << BLOCK_BITS;
	if (CcPreparePinWrite(
				Vcb->Volume,
				&Offset,
				bh->b_size,
				FALSE,
				PIN_WAIT,
				&Bcb,
				&Buffer )) {
		CcSetDirtyPinnedData(Bcb, NULL);
		Ext2AddBlockExtent( Vcb, NULL,
							(ULONG)bh->b_blocknr,
							(ULONG)bh->b_blocknr,
							(bh->b_size >> BLOCK_BITS));
		CcUnpinData(Bcb);
	}
}

/*
 * extents_brelse: Release the corresponding buffer header.
 *
 * @bh: The corresponding buffer header that is going to be freed.
 *
 * The pages underlying the buffer header will be unlocked.
 */
void extents_brelse(struct buffer_head *bh)
{
    if (bh == NULL)
        return;
    
    if (bh->b_mdl) {
        DEBUG(DL_BH, ("bh=%p mdl=%p (Flags:%xh VA:%p) released.\n", bh, bh->b_mdl,
                      bh->b_mdl->MdlFlags, bh->b_mdl->MappedSystemVa));
        if (IsFlagOn(bh->b_mdl->MdlFlags, MDL_PAGES_LOCKED)) {
            /* MmUnlockPages will release it's VA */
            MmUnlockPages(bh->b_mdl);
        } else if (IsFlagOn(bh->b_mdl->MdlFlags, MDL_MAPPED_TO_SYSTEM_VA)) {
            MmUnmapLockedPages(bh->b_mdl->MappedSystemVa, bh->b_mdl);
        }

        Ext2DestroyMdl(bh->b_mdl);
    }
    extents_free_buffer_head(bh);
}

/*
 * extents_bforget: Release the corresponding buffer header
 *					and purge the buffer.
 *
 * @bh: The corresponding buffer header that is going to be freed.
 *
 * The pages underlying the buffer header will be unlocked.
 */
void extents_bforget(struct buffer_head *bh)
{
	struct block_device *bdev = bh->b_bdev;
	PEXT2_VCB            Vcb  = bdev->bd_priv;
	LARGE_INTEGER        Offset;
    if (bh == NULL)
        return;
    
    if (bh->b_mdl) {
        DEBUG(DL_BH, ("bh=%p mdl=%p (Flags:%xh VA:%p) released.\n", bh, bh->b_mdl,
                      bh->b_mdl->MdlFlags, bh->b_mdl->MappedSystemVa));
        if (IsFlagOn(bh->b_mdl->MdlFlags, MDL_PAGES_LOCKED)) {
            /* MmUnlockPages will release it's VA */
            MmUnlockPages(bh->b_mdl);
        } else if (IsFlagOn(bh->b_mdl->MdlFlags, MDL_MAPPED_TO_SYSTEM_VA)) {
            MmUnmapLockedPages(bh->b_mdl->MappedSystemVa, bh->b_mdl);
        }

        Ext2DestroyMdl(bh->b_mdl);
    }
	
	Offset.QuadPart = ((LONGLONG)bh->b_blocknr) << BLOCK_BITS;
	CcPurgeCacheSection(&Vcb->SectionObject, &Offset, bh->b_size, FALSE);
    extents_free_buffer_head(bh);
}
