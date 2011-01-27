#ifndef _LINUX_EXT4_EXT
#define _LINUX_EXT4_EXT

typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;

/*
 * This is the extent on-disk structure.
 * It's used at the bottom of the tree.
 */
typedef struct ext4_extent {
    uint32_t ee_block; /* first logical block extent covers */
    uint16_t ee_len; /* number of blocks covered by extent */
    uint16_t ee_start_hi; /* high 16 bits of physical block */
    uint32_t ee_start_lo; /* low 32 bits of physical block */
} __attribute__ ((__packed__)) EXT4_EXTENT;

/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
typedef struct ext4_extent_idx {
    uint32_t  ei_block;       /* index covers logical blocks from 'block' */
    uint32_t  ei_leaf_lo;     /* pointer to the physical block of the next *
                                 * level. leaf or next index could be there */
    uint16_t  ei_leaf_hi;     /* high 16 bits of physical block */
    uint16_t   ei_unused;
}__attribute__ ((__packed__)) EXT4_EXTENT_IDX;

/*
 * Each block (leaves and indexes), even inode-stored has header.
 */
typedef struct ext4_extent_header {
    uint16_t  eh_magic;       /* probably will support different formats */
    uint16_t  eh_entries;     /* number of valid entries */
    uint16_t  eh_max;         /* capacity of store in entries */
    uint16_t  eh_depth;       /* has tree real underlying blocks? */
    uint32_t  eh_generation;  /* generation of the tree */
}__attribute__ ((__packed__)) EXT4_EXTENT_HEADER;


#define EXT4_EXT_MAGIC          0xf30a
#define get_ext4_header(i)      ((struct ext4_extent_header *) (i)->i_block)

#define EXT_FIRST_EXTENT(__hdr__) \
((struct ext4_extent *) (((char *) (__hdr__)) +         \
                         sizeof(struct ext4_extent_header)))

#define EXT_FIRST_INDEX(__hdr__) \
        ((struct ext4_extent_idx *) (((char *) (__hdr__)) +     \
                                     sizeof(struct ext4_extent_header)))

#define INODE_HAS_EXTENT(i) ((i)->i_flags & EXT2_EXTENTS_FL)

static inline uint64_t ext_to_block(EXT4_EXTENT *extent)
{
    uint64_t block;

    block = (uint64_t)extent->ee_start_lo;
    block |= ((uint64_t) extent->ee_start_hi << 31) << 1;

    return block;
}

static inline uint64_t idx_to_block(EXT4_EXTENT_IDX *idx)
{
    uint64_t block;

    block = (uint64_t)idx->ei_leaf_lo;
    block |= ((uint64_t) idx->ei_leaf_hi << 31) << 1;

    return block;
}

#endif	/* _LINUX_EXT4_EXT */
