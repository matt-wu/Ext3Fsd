#include <ext2fs.h>
#include <linux/errno.h>

static kmem_cache_t *extents_cache;

int ext4_init_extents_bh()
{
    extents_cache = kmem_cache_create(
                         "extents_cache",   /* bh */
                         sizeof(struct buffer_head),
                         0,		        /* offset */
                         SLAB_TEMPORARY,	/* flags */
                         NULL);		    /* ctor */
    if (extents_cache == NULL) {
        printk(KERN_EMERG "JBD: failed to create extents handle cache\n");
        return -ENOMEM;
    }
    return 0;
}

void ext4_destroy_extents_bh()
{
    if (extents_cache) {
        kmem_cache_destroy(extents_cache);
        extents_cache = NULL;
    }
}

static struct buffer_head *extents_new_buffer_head()
{
    struct buffer_head * bh = NULL;
    bh = kmem_cache_alloc(extents_cache, GFP_NOFS);
    if (bh) {
        memset(bh, 0, sizeof(struct buffer_head));
        DEBUG(DL_BH, ("bh=%p allocated.\n", bh));
    }
    return bh;
}

static void extents_free_buffer_head(struct buffer_head * bh)
{
    if (bh) {
        DEBUG(DL_BH, ("bh=%p freed.\n", bh));
        kmem_cache_free(extents_cache, bh);
    }
}

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
                    &bh->b_data);

    if (!ret) {
        DbgPrint("Insufficient memory resources!\n");
        extents_free_buffer_head(bh);
        bh = NULL;
        goto errorout;
    }

    set_buffer_new(bh);
    set_buffer_uptodate(bh);
    get_bh(bh);

    /* we get it */
errorout:
    return bh;
}

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
                            &bh->b_data);

    if (!ret) {
        DbgPrint("Insufficient memory resources!\n");
        extents_free_buffer_head(bh);
        bh = NULL;
        goto errorout;
    }

    set_buffer_new(bh);
    get_bh(bh);

    /* we get it */
errorout:
    return bh;
}

void extents_mark_buffer_dirty(struct buffer_head *bh)
{
    set_buffer_dirty(bh);
}

void extents_brelse(struct buffer_head *bh)
{
    struct block_device *bdev;
    PEXT2_VCB Vcb;

    if (bh == NULL)
        return;

    bdev = bh->b_bdev;
    Vcb = (PEXT2_VCB)bdev->bd_priv;

    ASSERT(Vcb->Identifier.Type == EXT2VCB);

    if (buffer_dirty(bh)) {
        Ext2AddBlockExtent(Vcb, NULL,
                            (ULONG)bh->b_blocknr,
                            (ULONG)bh->b_blocknr,
                            (bh->b_size >> BLOCK_BITS));
        CcSetDirtyPinnedData(bh->b_bcb, NULL);
    }
    if (bh->b_bcb)
        CcUnpinData(bh->b_bcb);

    extents_free_buffer_head(bh);
}
