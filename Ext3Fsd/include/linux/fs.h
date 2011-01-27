#ifndef _LINUX_FS_INCLUDE_
#define _LINUX_FS_INCLUDE_

#include <linux/types.h>
#include <linux/atomic.h>

//
// kdev
//

#define NODEV           0

typedef struct block_device * kdev_t;

#define MINORBITS   8
#define MINORMASK   ((1U << MINORBITS) - 1)

#define MAJOR(dev)   ((unsigned int)((int)(dev) >> MINORBITS))
#define MINOR(dev)   ((unsigned int)((int)(dev) & MINORMASK))

static inline unsigned int kdev_t_to_nr(kdev_t dev) {
    /*return (unsigned int)(MAJOR(dev)<<8) | MINOR(dev);*/
    return 0;
}

#define NODEV		0
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

static inline kdev_t to_kdev_t(int dev)
{
#if 0
    int major, minor;
#if 0
    major = (dev >> 16);
    if (!major) {
        major = (dev >> 8);
        minor = (dev & 0xff);
    } else
        minor = (dev & 0xffff);
#else
    major = (dev >> 8);
    minor = (dev & 0xff);
#endif
    return (kdev_t) MKDEV(major, minor);
#endif
    return 0;
}


//
// file system specific structures
//

/*
 * Kernel pointers have redundant information, so we can use a
 * scheme where we can return either an error code or a dentry
 * pointer with the same return value.
 *
 * This should be a per-architecture thing, to allow different
 * error and pointer decisions.
 */


struct super_block {
    unsigned long       s_magic;
    unsigned long       s_flags;
    unsigned long		s_blocksize;        /* blocksize */
    unsigned long long  s_maxbytes;
    unsigned char		s_blocksize_bits;   /* bits of blocksize */
    unsigned char		s_dirt;             /* any thing */
    char                s_id[30];           /* id string */
    kdev_t              s_bdev;             /* block_device */
    void *              s_priv;             /* EXT2_VCB */
    struct dentry      *s_root;
    void               *s_fs_info;
};

struct inode {
    __u32           i_ino;      /* inode number */
    umode_t			i_mode;     /* mode */
    loff_t			i_size;     /* size */
    atomic_t        i_count;    /* ref count */
    __u32           i_nlink;
    __u32           i_generation;
    __u32           i_version;
    __u32           i_flags;
    struct super_block	*i_sb;  /* super_block */
    void *          i_priv;     /* EXT2_MCB */
};

//
//  Inode state bits
//

#define I_DIRTY_SYNC        1 /* Not dirty enough for O_DATASYNC */
#define I_DIRTY_DATASYNC    2 /* Data-related inode changes pending */
#define I_DIRTY_PAGES       4 /* Data-related inode changes pending */
#define I_LOCK              8
#define I_FREEING          16
#define I_CLEAR            32

#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)


struct dentry {
    atomic_t                d_count;
    struct {
        int             len;
        char           *name;
    } d_name;
    struct inode           *d_inode;
    struct dentry          *d_parent;
    void                   *d_fsdata;
    struct super_block     *d_sb;
};

struct file {

    unsigned int    f_flags;
    umode_t         f_mode;
    __int64         f_size;
    loff_t          f_pos;
    struct dentry  *f_dentry;
    void           *private_data;
};

unsigned long bmap(struct inode *, unsigned long);
void iput(struct inode *inode);
void iget(struct inode *inode);


#endif /*_LINUX_FS_INCLUDE_*/