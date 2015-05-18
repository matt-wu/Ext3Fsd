#include "ext2fs.h"
#include "linux\ext4.h"

#pragma warning(push)
#pragma warning(disable: 4018)
#pragma warning(disable: 4242)
#pragma warning(disable: 4244)

// #define AGGRESSIVE_TEST
// #ifdef _EXTENTS_TEST

#define ext4_mark_inode_dirty(icb, n) ext3_mark_inode_dirty(icb, n)
static inline ext4_fsblk_t ext4_inode_to_goal_block(struct inode *inode)
{
	PEXT2_VCB Vcb;
	Vcb = inode->i_sb->s_priv;
	return (inode->i_ino - 1) / BLOCKS_PER_GROUP;
}

static ext4_fsblk_t ext4_new_meta_blocks(void *icb, struct inode *inode,
		ext4_fsblk_t goal,
		unsigned int flags,
		unsigned long *count, int *errp)
{
	NTSTATUS status;
	ULONG blockcnt = (count)?*count:1;
	ULONG block = 0;

	status = Ext2NewBlock((PEXT2_IRP_CONTEXT)icb,
			inode->i_sb->s_priv,
			0, (ULONG)goal,
			&block,
			&blockcnt);
	if (count)
		*count = blockcnt;

	if (!NT_SUCCESS(status)) {
		*errp = Ext2LinuxError(status);
		return 0;
	}
	inode->i_blocks += (blockcnt * (inode->i_sb->s_blocksize >> 9));
	return block;
}

static void ext4_free_blocks(void *icb, struct inode *inode,
		ext4_fsblk_t block, int count, int flags)
{
	Ext2FreeBlock((PEXT2_IRP_CONTEXT)icb, inode->i_sb->s_priv, block, count);
	inode->i_blocks -= count * (inode->i_sb->s_blocksize >> 9);
	return;
}


static inline int ext4_ext_space_block(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 6)
		size = 6;
#endif
	return size;
}

static inline int ext4_ext_space_block_idx(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 5)
		size = 5;
#endif
	return size;
}

static inline int ext4_ext_space_root(struct inode *inode, int check)
{
	int size;

	size = sizeof(EXT4_I(inode)->i_block);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 3)
		size = 3;
#endif
	return size;
}

static inline int ext4_ext_space_root_idx(struct inode *inode, int check)
{
	int size;

	size = sizeof(EXT4_I(inode)->i_block);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 4)
		size = 4;
#endif
	return size;
}

static int ext4_ext_max_entries(struct inode *inode, int depth)
{
	int max;

	if (depth == ext_depth(inode)) {
		if (depth == 0)
			max = ext4_ext_space_root(inode, 1);
		else
			max = ext4_ext_space_root_idx(inode, 1);
	} else {
		if (depth == 0)
			max = ext4_ext_space_block(inode, 1);
		else
			max = ext4_ext_space_block_idx(inode, 1);
	}

	return max;
}

static ext4_fsblk_t ext4_ext_find_goal(struct inode *inode,
			      struct ext4_ext_path *path,
			      ext4_lblk_t block)
{
	if (path) {
		int depth = path->p_depth;
		struct ext4_extent *ex;

		/*
		 * Try to predict block placement assuming that we are
		 * filling in a file which will eventually be
		 * non-sparse --- i.e., in the case of libbfd writing
		 * an ELF object sections out-of-order but in a way
		 * the eventually results in a contiguous object or
		 * executable file, or some database extending a table
		 * space file.  However, this is actually somewhat
		 * non-ideal if we are writing a sparse file such as
		 * qemu or KVM writing a raw image file that is going
		 * to stay fairly sparse, since it will end up
		 * fragmenting the file system's free space.  Maybe we
		 * should have some hueristics or some way to allow
		 * userspace to pass a hint to file system,
		 * especially if the latter case turns out to be
		 * common.
		 */
		ex = path[depth].p_ext;
		if (ex) {
			ext4_fsblk_t ext_pblk = ext4_ext_pblock(ex);
			ext4_lblk_t ext_block = le32_to_cpu(ex->ee_block);

			if (block > ext_block)
				return ext_pblk + (block - ext_block);
			else
				return ext_pblk - (ext_block - block);
		}

		/* it looks like index is empty;
		 * try to find starting block from index itself */
		if (path[depth].p_bcb) {
				struct super_block *sb = inode->i_sb;
				return path[depth].p_bcb->MappedFileOffset.QuadPart
						>> sb->s_blocksize_bits;
		}
	}

	/* OK. use inode's group */
	return ext4_inode_to_goal_block(inode);
}

/*
 * Allocation for a meta data block
 */
static ext4_fsblk_t
ext4_ext_new_meta_block(void *icb, struct inode *inode,
			struct ext4_ext_path *path,
			struct ext4_extent *ex, int *err, unsigned int flags)
{
	ext4_fsblk_t goal, newblock;

	goal = ext4_ext_find_goal(inode, path, le32_to_cpu(ex->ee_block));
	newblock = ext4_new_meta_blocks(icb, inode, goal, flags,
					NULL, err);
	return newblock;
}

static int __ext4_ext_dirty(void *icb, struct inode *inode,
		      struct ext4_ext_path *path)
{
	int err;

	if (path->p_bcb) {
		/*ext4_extent_block_csum_set(inode, ext_block_hdr(path->p_data));*/
		/* path points to block */
		err = 0;
		extents_mark_buffer_dirty(inode->i_sb, path->p_bcb);
	} else {
		/* path points to leaf/index in inode body */
		err = ext4_mark_inode_dirty(icb, inode);
	}
	return err;
}

void ext4_ext_drop_refs(struct ext4_ext_path *path)
{
	int depth, i;

	if (!path)
		return;
	depth = path->p_depth;
	for (i = 0; i <= depth; i++, path++)
		if (path->p_bcb) {
			extents_brelse(path->p_bcb);
			path->p_bcb = NULL;
			path->p_data = NULL;
		}
}

static uint32_t ext4_ext_block_csum(struct inode *inode,
				    struct ext4_extent_header *eh)
{
	/* return ext4_crc32c(inode->i_csum, eh, EXT4_EXTENT_TAIL_OFFSET(eh)); */
	return 0;
}

static void ext4_extent_block_csum_set(struct inode *inode,
				    struct ext4_extent_header *eh)
{
	struct ext4_extent_tail *tail;

	tail = find_ext4_extent_tail(eh);
	tail->et_checksum = ext4_ext_block_csum(
			inode, eh);
}

/*
 * Check that whether the basic information inside the extent header
 * is correct or not.
 */
static int ext4_ext_check(struct inode *inode,
			    struct ext4_extent_header *eh, int depth,
			    ext4_fsblk_t pblk)
{
	struct ext4_extent_tail *tail;
	const char *error_msg;
	int max = 0;

	if (eh->eh_magic != EXT4_EXT_MAGIC) {
		error_msg = "invalid magic";
		goto corrupted;
	}
	if (le16_to_cpu(eh->eh_depth) != depth) {
		error_msg = "unexpected eh_depth";
		goto corrupted;
	}
	if (eh->eh_max == 0) {
		error_msg = "invalid eh_max";
		goto corrupted;
	}
	if (eh->eh_entries > eh->eh_max) {
		error_msg = "invalid eh_entries";
		goto corrupted;
	}

	tail = find_ext4_extent_tail(eh);
	if (tail->et_checksum != ext4_ext_block_csum(inode, eh)) {
		/* FIXME: Warning: extent checksum damaged? */
	}

	return 0;

corrupted:
	return -EIO;
}

static PPUBLIC_BCB
read_extent_tree_block(struct inode *inode, ext4_fsblk_t pblk, int depth,
			 PVOID *pdata, int *perr, int flags)
{
	PPUBLIC_BCB bcb;
	int				err;

	if (perr)
		*perr = 0;

	err = 0;
	bcb = extents_bread(inode->i_sb, pblk, pdata);
	if (!bcb) {
		err = -ENOMEM;
		goto errout;
	}

	err = ext4_ext_check(inode,
			       ext_block_hdr(*pdata), depth, pblk);
	if (err)
		goto errout;
out:
	return bcb;
errout:
	if (bcb)
		extents_brelse(bcb);
	if (perr)
		*perr = err;
	return NULL;
}

/*
 * ext4_ext_binsearch_idx:
 * binary search for the closest index of the given block
 * the header must be checked before calling this
 */
static void
ext4_ext_binsearch_idx(struct inode *inode,
			struct ext4_ext_path *path, ext4_lblk_t block)
{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent_idx *r, *l, *m;

	l = EXT_FIRST_INDEX(eh) + 1;
	r = EXT_LAST_INDEX(eh);
	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ei_block))
			r = m - 1;
		else
			l = m + 1;
	}

	path->p_idx = l - 1;

}

/*
 * ext4_ext_binsearch:
 * binary search for closest extent of the given block
 * the header must be checked before calling this
 */
static void
ext4_ext_binsearch(struct inode *inode,
		struct ext4_ext_path *path, ext4_lblk_t block)
{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent *r, *l, *m;

	if (eh->eh_entries == 0) {
		/*
		 * this leaf is empty:
		 * we get such a leaf in split/add case
		 */
		return;
	}

	l = EXT_FIRST_EXTENT(eh) + 1;
	r = EXT_LAST_EXTENT(eh);

	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ee_block))
			r = m - 1;
		else
			l = m + 1;
	}

	path->p_ext = l - 1;

}

int ext4_find_extent(struct inode *inode, ext4_lblk_t block,
		 struct ext4_ext_path **orig_path, int flags)
{
	struct ext4_extent_header *eh;
	PPUBLIC_BCB bcb;
	PVOID data;
	struct ext4_ext_path *path = *orig_path;
	int depth, i, ppos = 0;
	int ret;

	eh = ext_inode_hdr(inode);
	depth = ext_depth(inode);

	if (path) {
		ext4_ext_drop_refs(path);
		if (depth > path[0].p_maxdepth) {
			kfree(path);
			*orig_path = path = NULL;
		}
	}
	if (!path) {
		/* account possible depth increase */
		path = kzalloc(sizeof(struct ext4_ext_path) * (depth + 2),
				GFP_NOFS);
		if (!path)
			return -ENOMEM;
		path[0].p_maxdepth = depth + 1;
	}
	path[0].p_hdr = eh;
	path[0].p_bcb = NULL;
	path[0].p_data = NULL;

	i = depth;
	/* walk through the tree */
	while (i) {
		ext4_ext_binsearch_idx(inode, path + ppos, block);
		path[ppos].p_block = ext4_idx_pblock(path[ppos].p_idx);
		path[ppos].p_depth = i;
		path[ppos].p_ext = NULL;

		bcb = read_extent_tree_block(inode, path[ppos].p_block, --i,
					    &data, &ret, flags);
		if (ret) {
			goto err;
		}

		eh = ext_block_hdr(data);
		ppos++;
		if (ppos > depth) {
			extents_brelse(bcb);
			ret = -EIO;
			goto err;
		}
		path[ppos].p_bcb = bcb;
		path[ppos].p_data = data;
		path[ppos].p_hdr = eh;
	}

	path[ppos].p_depth = i;
	path[ppos].p_ext = NULL;
	path[ppos].p_idx = NULL;

	/* find extent */
	ext4_ext_binsearch(inode, path + ppos, block);
	/* if not an empty leaf */
	if (path[ppos].p_ext)
		path[ppos].p_block = ext4_ext_pblock(path[ppos].p_ext);

	*orig_path = path;

	ret = 0;
	return ret;

err:
	ext4_ext_drop_refs(path);
	kfree(path);
	if (orig_path)
		*orig_path = NULL;
	return ret;
}

/*
 * Be cautious, the buffer_head returned is not yet mark dirtied. */
static int ext4_ext_split_node(void *icb, struct inode *inode,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext,
			       ext4_fsblk_t *sibling,
			       PPUBLIC_BCB *new_bcb,
			       PVOID *pdata)
{
	int ret;
	ext4_fsblk_t newblock;
	PVOID data;
	PPUBLIC_BCB bcb = NULL;
	int depth = ext_depth(inode);

	ASSERT(sibling);
	ASSERT(new_bcb);
	/* FIXME: currently we split at the point after the current extent. */
	newblock = ext4_ext_new_meta_block(icb, inode, path,
					   newext, &ret, 0);
	if (ret)
		goto cleanup;

	/*  For write access.*/
	bcb = extents_bwrite(inode->i_sb, newblock, &data);
	if (!bcb) {
		ret = -ENOMEM;
		goto cleanup;
	}

	if (at == depth) {
		/* start copy from next extent */
		int m = EXT_MAX_EXTENT(path[at].p_hdr) - path[at].p_ext;
		struct ext4_extent_header *neh;
		neh = ext_block_hdr(data);
		neh->eh_entries = 0;
		neh->eh_max = cpu_to_le16(ext4_ext_space_block(inode, 0));
		neh->eh_magic = EXT4_EXT_MAGIC;
		neh->eh_depth = 0;
		if (m) {
			struct ext4_extent *ex;
			ex = EXT_FIRST_EXTENT(neh);
			memmove(ex, path[at].p_ext + 1, sizeof(struct ext4_extent) * m);
			le16_add_cpu(&neh->eh_entries, m);
			le16_add_cpu(&path[at].p_hdr->eh_entries, -m);
			ret = __ext4_ext_dirty(icb, inode, path + at);
			if (ret)
				goto cleanup;

		}
	} else {
		int m = EXT_MAX_INDEX(path[at].p_hdr) - path[at].p_idx;
		struct ext4_extent_header *neh;
		neh = ext_block_hdr(data);
		neh->eh_entries = 0;
		neh->eh_max = cpu_to_le16(ext4_ext_space_block(inode, depth - at));
		neh->eh_magic = EXT4_EXT_MAGIC;
		neh->eh_depth = cpu_to_le16(depth - at);
		if (m) {
			struct ext4_extent_idx *ix;
			ix = EXT_FIRST_INDEX(neh);
			memmove(ix, path[at].p_idx + 1, sizeof(struct ext4_extent) * m);
			le16_add_cpu(&neh->eh_entries, m);
			le16_add_cpu(&path[at].p_hdr->eh_entries, -m);
			ret = __ext4_ext_dirty(icb, inode, path + at);
			if (ret)
				goto cleanup;

		}
	}
cleanup:
	if (ret) {
		if (bcb) {
			extents_brelse(bcb);
			bcb = NULL;
			data = NULL;
		}
		if (newblock)
			ext4_free_blocks(icb, inode, newblock, 1, 0);

		newblock = 0;
	}
	*sibling = newblock;
	*new_bcb = bcb;
	*pdata = data;
	return ret;
}

static ext4_lblk_t ext4_ext_block_index(PVOID data)
{
	struct ext4_extent_header *neh;
	neh = ext_block_hdr(data);

	if (neh->eh_depth)
		return le32_to_cpu(EXT_FIRST_INDEX(neh)->ei_block);
	return le32_to_cpu(EXT_FIRST_EXTENT(neh)->ee_block);
}

#define EXT_INODE_HDR_NEED_GROW 0x1

static int ext4_ext_insert_index(void *icb, struct inode *inode,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext,
			       ext4_lblk_t insert_index,
			       ext4_fsblk_t insert_block,
			       ext4_lblk_t *sibling_index,
			       ext4_fsblk_t *sibling)
{
	struct ext4_extent_idx *ix;
	struct ext4_ext_path *curp = path + at;
	PPUBLIC_BCB bcb;
	PVOID data = NULL;
	int len, err;
	struct ext4_extent_header *eh;

	if (curp->p_idx && insert_index == le32_to_cpu(curp->p_idx->ei_block))
		return -EIO;

	if (le16_to_cpu(curp->p_hdr->eh_entries)
			     == le16_to_cpu(curp->p_hdr->eh_max)) {
		if (at) {
			struct ext4_extent_header *neh;
			err = ext4_ext_split_node(icb, inode, path, at,
						  newext, sibling, &bcb, &data);
			if (err)
				goto out;

			neh = ext_block_hdr(data);
			if (insert_index >
				le32_to_cpu(curp->p_idx->ei_block)) {
				/* Make decision which node should be used to insert the index.*/
				if (le16_to_cpu(neh->eh_entries) > le16_to_cpu(curp->p_hdr->eh_entries)) {
					eh = curp->p_hdr;
					/* insert after */
					ix = EXT_LAST_INDEX(eh) + 1;
				} else {
					eh = neh;
					ix = EXT_FIRST_INDEX(eh);
				}
			} else {
				eh = curp->p_hdr;
				/* insert before */
				ix = EXT_LAST_INDEX(eh);
			}
		} else {
			err = EXT_INODE_HDR_NEED_GROW;
			goto out;
		}
	} else {
		eh = curp->p_hdr;
		if (curp->p_idx == NULL) {
			ix = EXT_FIRST_INDEX(eh);
			curp->p_idx = ix;
		} else if (insert_index > le32_to_cpu(curp->p_idx->ei_block)) {
			/* insert after */
			ix = curp->p_idx + 1;
		} else {
			/* insert before */
			ix = curp->p_idx;
		}
	}

	len = EXT_LAST_INDEX(eh) - ix + 1;
	ASSERT(len >= 0);
	if (len > 0)
		memmove(ix + 1, ix, len * sizeof(struct ext4_extent_idx));

	if (ix > EXT_MAX_INDEX(eh)) {
		err = -EIO;
		goto out;
	}

	ix->ei_block = cpu_to_le32(insert_index);
	ext4_idx_store_pblock(ix, insert_block);
	le16_add_cpu(&eh->eh_entries, 1);

	if (ix > EXT_LAST_INDEX(eh)) {
		err = -EIO;
		goto out;
	}

	if (eh == curp->p_hdr)
		err = __ext4_ext_dirty(icb, inode, curp);
	else
		err = 0;

out:
	if (err) {
		if (bcb)
			extents_bforget(bcb);

	} else if (bcb) {
		/* If we got a sibling leaf. */
		*sibling_index = ext4_ext_block_index(data);
		extents_mark_buffer_dirty(inode->i_sb, bcb);
		extents_brelse(bcb);
	} else {
		*sibling_index = 0;
		*sibling = 0;
	}
	return err;

}

/*
 * ext4_ext_correct_indexes:
 * if leaf gets modified and modified extent is first in the leaf,
 * then we have to correct all indexes above.
 * TODO: do we need to correct tree in all cases?
 */
static int ext4_ext_correct_indexes(void *icb, struct inode *inode,
				    struct ext4_ext_path *path)
{
	struct ext4_extent_header *eh;
	int depth = ext_depth(inode);
	struct ext4_extent *ex;
	__le32 border;
	int k, err = 0;

	eh = path[depth].p_hdr;
	ex = path[depth].p_ext;

	if (ex == NULL || eh == NULL) {
		return -EIO;
	}

	if (depth == 0) {
		/* there is no tree at all */
		return 0;
	}

	if (ex != EXT_FIRST_EXTENT(eh)) {
		/* we correct tree if first leaf got modified only */
		return 0;
	}

	/*
	 * TODO: we need correction if border is smaller than current one
	 */
	k = depth - 1;
	border = path[depth].p_ext->ee_block;
	path[k].p_idx->ei_block = border;
	err = __ext4_ext_dirty(icb, inode, path + k);
	if (err)
		return err;

	while (k--) {
		/* change all left-side indexes */
		if (path[k+1].p_idx != EXT_FIRST_INDEX(path[k+1].p_hdr))
			break;
		path[k].p_idx->ei_block = border;
		err = __ext4_ext_dirty(icb, inode, path + k);
		if (err)
			break;
	}

	return err;
}

static inline int ext4_extent_in_range(ext4_lblk_t iblock, struct ext4_extent *ex)
{
	return (iblock >= le32_to_cpu(ex->ee_block))
		&& (iblock < le32_to_cpu(ex->ee_block) + ext4_ext_get_actual_len(ex));
}

static inline int ext4_ext_can_prepend(struct ext4_extent *ex1, struct ext4_extent *ex2)
{
	if (ext4_ext_pblock(ex2) + ext4_ext_get_actual_len(ex2)
		!= ext4_ext_pblock(ex1))
		return 0;

#ifdef AGGRESSIVE_TEST
	if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2) > 4)
		return 0;
#else
	if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2) > EXT_INIT_MAX_LEN)
		return 0;
#endif

	if (le32_to_cpu(ex2->ee_block) + ext4_ext_get_actual_len(ex2) !=
			le32_to_cpu(ex1->ee_block))
		return 0;

	return 1;
}

static inline int ext4_ext_can_append(struct ext4_extent *ex1, struct ext4_extent *ex2)
{
	if (ext4_ext_pblock(ex1) + ext4_ext_get_actual_len(ex1)
		!= ext4_ext_pblock(ex2))
		return 0;

#ifdef AGGRESSIVE_TEST
	if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2) > 4)
		return 0;
#else
	if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2) > EXT_INIT_MAX_LEN)
		return 0;
#endif

	if (le32_to_cpu(ex1->ee_block) + ext4_ext_get_actual_len(ex1) !=
			le32_to_cpu(ex2->ee_block))
		return 0;

	return 1;
}

static int ext4_ext_insert_leaf(void *icb, struct inode *inode,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext,
			       ext4_lblk_t *sibling_index,
			       ext4_fsblk_t *sibling)
{
	struct ext4_extent *ex;
	struct ext4_ext_path *curp = path + at;
	PPUBLIC_BCB bcb;
	PVOID data = NULL;
	int len, err;
	struct ext4_extent_header *eh;

	if (curp->p_ext && le32_to_cpu(newext->ee_block) == le32_to_cpu(curp->p_ext->ee_block))
		return -EIO;

	if (curp->p_ext && ext4_ext_can_append(curp->p_ext, newext)) {
		curp->p_ext->ee_len = ext4_ext_get_actual_len(curp->p_ext)
			+ ext4_ext_get_actual_len(newext);
		err = __ext4_ext_dirty(icb, inode, curp);
		goto out;

	}

	if (curp->p_ext && ext4_ext_can_prepend(curp->p_ext, newext)) {
		curp->p_ext->ee_block = newext->ee_block;
		curp->p_ext->ee_len = ext4_ext_get_actual_len(curp->p_ext)
			+ ext4_ext_get_actual_len(newext);
		err = __ext4_ext_dirty(icb, inode, curp);
		goto out;

	}

	if (le16_to_cpu(curp->p_hdr->eh_entries)
			     == le16_to_cpu(curp->p_hdr->eh_max)) {
		if (at) {
			struct ext4_extent_header *neh;
			err = ext4_ext_split_node(icb, inode, path, at,
						  newext, sibling, &bcb, &data);
			if (err)
				goto out;

			neh = ext_block_hdr(data);
			if (le32_to_cpu(newext->ee_block) >
				le32_to_cpu(curp->p_ext->ee_block)) {
				if (le16_to_cpu(neh->eh_entries) > le16_to_cpu(curp->p_hdr->eh_entries)) {
					eh = curp->p_hdr;
					/* insert after */
					ex = EXT_LAST_EXTENT(eh) + 1;
				} else {
					eh = neh;
					ex = EXT_FIRST_EXTENT(eh);
				}
			} else {
				eh = curp->p_hdr;
				/* insert before */
				ex = EXT_LAST_EXTENT(eh);
			}
		} else {
			err = EXT_INODE_HDR_NEED_GROW;
			goto out;
		}
	} else {
		eh = curp->p_hdr;
		if (curp->p_ext == NULL) {
			ex = EXT_FIRST_EXTENT(eh);
			curp->p_ext = ex;
		} else if (le32_to_cpu(newext->ee_block) > le32_to_cpu(curp->p_ext->ee_block)) {
			/* insert after */
			ex = curp->p_ext + 1;
		} else {
			/* insert before */
			ex = curp->p_ext;
		}
	}

	len = EXT_LAST_EXTENT(eh) - ex + 1;
	ASSERT(len >= 0);
	if (len > 0)
		memmove(ex + 1, ex, len * sizeof(struct ext4_extent));

	if (ex > EXT_MAX_EXTENT(eh)) {
		err = -EIO;
		goto out;
	}

	ex->ee_block = newext->ee_block;
	ex->ee_len = ext4_ext_get_actual_len(newext);
	ext4_ext_store_pblock(ex, ext4_ext_pblock(newext));
	le16_add_cpu(&eh->eh_entries, 1);

	if (ex > EXT_LAST_EXTENT(eh)) {
		err = -EIO;
		goto out;
	}

	if (eh == curp->p_hdr) {
		err = ext4_ext_correct_indexes(icb, inode, path);
		if (err)
			goto out;
		err = __ext4_ext_dirty(icb, inode, curp);
	} else
		err = 0;

out:
	if (err) {
		if (bcb)
			extents_bforget(bcb);

	} else if (bcb) {
		/* If we got a sibling leaf. */
		*sibling_index = ext4_ext_block_index(data);
		extents_mark_buffer_dirty(bcb);
		extents_brelse(bcb);
	} else {
		*sibling_index = 0;
		*sibling = 0;
	}

	return err;

}

/*
 * ext4_ext_grow_indepth:
 * implements tree growing procedure:
 * - allocates new block
 * - moves top-level data (index block or leaf) into the new block
 * - initializes new top-level, creating index that points to the
 *   just created block
 */
static int ext4_ext_grow_indepth(void *icb, struct inode *inode,
				 unsigned int flags)
{
	struct ext4_extent_header *neh;
	PPUBLIC_BCB bcb;
	PVOID data;
	ext4_fsblk_t newblock, goal = 0;
	int err = 0;

	/* Try to prepend new index to old one */
	if (ext_depth(inode))
		goal = ext4_idx_pblock(EXT_FIRST_INDEX(ext_inode_hdr(inode)));
	goal = ext4_inode_to_goal_block(inode);
	newblock = ext4_new_meta_blocks(icb, inode, goal, flags,
					NULL, &err);
	if (newblock == 0)
		return err;

	bcb = extents_bwrite(inode->i_sb, newblock, &data);
	if (!bcb) {
		ext4_free_blocks(icb, inode, newblock, 1, 0);
		err = -ENOMEM;
		return err;
	}

	/* move top-level index/leaf into new block */
	memmove(data, EXT4_I(inode)->i_block,
		sizeof(EXT4_I(inode)->i_block));

	/* set size of new block */
	neh = ext_block_hdr(data);
	/* old root could have indexes or leaves
	 * so calculate e_max right way */
	if (ext_depth(inode))
		neh->eh_max = (ext4_ext_space_block_idx(inode, 0));
	else
		neh->eh_max = (ext4_ext_space_block(inode, 0));
	neh->eh_magic = EXT4_EXT_MAGIC;
	ext4_extent_block_csum_set(inode, neh);

	extents_mark_buffer_dirty(inode->i_sb, bcb);

	/* Update top-level index: num,max,pointer */
	neh = ext_inode_hdr(inode);
	neh->eh_entries = (1);
	ext4_idx_store_pblock(EXT_FIRST_INDEX(neh), newblock);
	if (neh->eh_depth == 0) {
		/* Root extent block becomes index block */
		neh->eh_max = (ext4_ext_space_root_idx(inode, 0));
		EXT_FIRST_INDEX(neh)->ei_block =
			EXT_FIRST_EXTENT(neh)->ee_block;
	}

	le16_add_cpu(&neh->eh_depth, 1);
	ext4_mark_inode_dirty(icb, inode);
	extents_brelse(bcb);

	return err;
}

int ext4_ext_insert_extent(void *icb, struct inode *inode, struct ext4_ext_path **ppath, struct ext4_extent *newext)
{
	int i, depth, level, ret = 0;
	struct ext4_ext_path *path;
	ext4_lblk_t index;
	ext4_fsblk_t ptr;

	ASSERT(ppath);
	level = 0;

again:
	depth = ext_depth(inode);

	do {
		if (!level) {
			ret = ext4_ext_insert_leaf(icb, inode, *ppath, depth - level,
					     newext, &index,
					     &ptr);
		} else
			ret = ext4_ext_insert_index(icb, inode, *ppath, depth - level,
					     newext, index, ptr,
					     &index, &ptr);

		if (ret && ret != EXT_INODE_HDR_NEED_GROW)
			goto out;

		level++;
	} while (ptr != 0 && level <= depth);
	
	if (level > depth && ptr) {
		ret = ext4_ext_grow_indepth(icb, inode, 0);
		if (ret)
			goto out;
		ret = ext4_find_extent(inode, le32_to_cpu(newext->ee_block), ppath, 0);
		if (ret)
			goto out;
		level = depth;
		goto again;
	}
out:
	if (ret) {
		if (*ppath)
			ext4_ext_drop_refs(*ppath);
		
		*ppath = NULL;
	}
	return ret;
}

#define EXT_MAX_BLOCKS (ext4_lblk_t)-1

static int ext4_remove_blocks(void *icb, handle_t *handle, struct inode *inode,
		struct ext4_extent *ex,
		unsigned long from, unsigned long to)
{
	int i;

	if (from >= le32_to_cpu(ex->ee_block)
			&& to == le32_to_cpu(ex->ee_block) + ext4_ext_get_actual_len(ex) - 1) {
		/* tail removal */
		unsigned long num, start;
		num = le32_to_cpu(ex->ee_block) + ext4_ext_get_actual_len(ex) - from;
		start = ext4_ext_pblock(ex) + ext4_ext_get_actual_len(ex) - num;
		ext4_free_blocks(icb, inode, start, num, 0);
	} else if (from == le32_to_cpu(ex->ee_block)
			&& to <= le32_to_cpu(ex->ee_block) + ext4_ext_get_actual_len(ex) - 1) {
	} else {
	}
	return 0;
}

/*
 * routine removes index from the index block
 * it's used in truncate case only. thus all requests are for
 * last index in the block only
 */
int ext4_ext_rm_idx(void *icb, handle_t *handle, struct inode *inode,
		struct ext4_ext_path *path)
{
	int err;
	ext4_fsblk_t leaf;

	/* free index block */
	path--;
	leaf = ext4_idx_pblock(path->p_idx);
	ASSERT(path->p_hdr->eh_entries != 0);
	path->p_hdr->eh_entries = cpu_to_le16(le16_to_cpu(path->p_hdr->eh_entries)-1);
	if ((err = __ext4_ext_dirty(icb, inode, path)))
		return err;
	ext4_free_blocks(icb, inode, leaf, 1, 0);
	return err;
}

static int
ext4_ext_rm_leaf(void *icb, handle_t *handle, struct inode *inode,
		struct ext4_ext_path *path, unsigned long start)
{
	int err = 0, correct_index = 0;
	int depth = ext_depth(inode), credits;
	struct ext4_extent_header *eh;
	unsigned a, b, block, num;
	unsigned long ex_ee_block;
	unsigned short ex_ee_len;
	struct ext4_extent *ex;

	/* the header must be checked already in ext4_ext_remove_space() */
	if (!path[depth].p_hdr)
		path[depth].p_hdr = ext_block_hdr(path[depth].p_data);
	eh = path[depth].p_hdr;
	ASSERT(eh != NULL);

	/* find where to start removing */
	ex = EXT_LAST_EXTENT(eh);

	ex_ee_block = le32_to_cpu(ex->ee_block);
	ex_ee_len = ext4_ext_get_actual_len(ex);

	while (ex >= EXT_FIRST_EXTENT(eh) &&
			ex_ee_block + ex_ee_len > start) {
		path[depth].p_ext = ex;

		a = ex_ee_block > start ? ex_ee_block : start;
		b = (unsigned long long)ex_ee_block + ex_ee_len - 1 < 
			EXT_MAX_BLOCKS ? ex_ee_block + ex_ee_len - 1 : EXT_MAX_BLOCKS;


		if (a != ex_ee_block && b != ex_ee_block + ex_ee_len - 1) {
			block = 0;
			num = 0;
			BUG();
		} else if (a != ex_ee_block) {
			/* remove tail of the extent */
			block = ex_ee_block;
			num = a - block;
		} else if (b != ex_ee_block + ex_ee_len - 1) {
			/* remove head of the extent */
			block = a;
			num = b - a;
			/* there is no "make a hole" API yet */
			BUG();
		} else {
			/* remove whole extent: excellent! */
			block = ex_ee_block;
			num = 0;
		}

		/* at present, extent can't cross block group */
		/* leaf + bitmap + group desc + sb + inode */
		credits = 5;
		if (ex == EXT_FIRST_EXTENT(eh)) {
			correct_index = 1;
			credits += (ext_depth(inode)) + 1;
		}

		/*handle = ext4_ext_journal_restart(icb, handle, credits);*/
		/*if (IS_ERR(icb, handle)) {*/
		/*err = PTR_ERR(icb, handle);*/
		/*goto out;*/
		/*}*/

		err = ext4_remove_blocks(icb, handle, inode, ex, a, b);
		if (err)
			goto out;

		if (num == 0) {
			/* this extent is removed entirely mark slot unused */
			ext4_ext_store_pblock(ex, 0);
			eh->eh_entries = cpu_to_le16(le16_to_cpu(eh->eh_entries)-1);
		}

		ex->ee_block = cpu_to_le32(block);
		ex->ee_len = cpu_to_le16(num);

		err = __ext4_ext_dirty(icb, inode, path + depth);
		if (err)
			goto out;

		ex--;
		ex_ee_block = le32_to_cpu(ex->ee_block);
		ex_ee_len = ext4_ext_get_actual_len(ex);
	}

	if (correct_index && eh->eh_entries)
		err = ext4_ext_correct_indexes(icb, inode, path);

	/* if this leaf is free, then we should
	 * remove it from index block above */
	if (err == 0 && eh->eh_entries == 0 && path[depth].p_bcb != NULL)
		err = ext4_ext_rm_idx(icb, handle, inode, path + depth);

out:
	return err;
}

/*
 * returns 1 if current index have to be freed (even partial)
 */
static int inline
ext4_ext_more_to_rm(struct ext4_ext_path *path)
{
	ASSERT(path->p_idx != NULL);

	if (path->p_idx < EXT_FIRST_INDEX(path->p_hdr))
		return 0;

	/*
	 * if truncate on deeper level happened it it wasn't partial
	 * so we have to consider current index for truncation
	 */
	if (le16_to_cpu(path->p_hdr->eh_entries) == path->p_block)
		return 0;
	return 1;
}

int ext4_ext_remove_space(void *icb, struct inode *inode, unsigned long start)
{
	struct super_block *sb = inode->i_sb;
	int depth = ext_depth(inode);
	struct ext4_ext_path *path;
	handle_t *handle = NULL;
	int i = 0, err = 0;

	/* probably first extent we're gonna free will be last in block */
	/*handle = ext4_journal_start(inode, depth + 1);*/
	/*if (IS_ERR(icb, handle))*/
	/*return PTR_ERR(icb, handle);*/

	/*
	 * we start scanning from right side freeing all the blocks
	 * after i_size and walking into the deep
	 */
	path = kmalloc(sizeof(struct ext4_ext_path) * (depth + 1), GFP_KERNEL);
	if (path == NULL) {
		ext4_journal_stop(icb, handle);
		return -ENOMEM;
	}
	memset(path, 0, sizeof(struct ext4_ext_path) * (depth + 1));
	path[0].p_hdr = ext_inode_hdr(inode);
	path[0].p_depth = depth;

	while (i >= 0 && err == 0) {
		if (i == depth) {
			/* this is leaf block */
			err = ext4_ext_rm_leaf(icb, handle, inode, path, start);
			/* root level have p_bcb == NULL, extents_brelse() eats this */
			extents_brelse(path[i].p_bcb);
			path[i].p_bcb = NULL;
			path[i].p_data = NULL;
			i--;
			continue;
		}

		/* this is index block */
		if (!path[i].p_hdr) {
			path[i].p_hdr = ext_block_hdr(path[i].p_data);
		}

		if (!path[i].p_idx) {
			/* this level hasn't touched yet */
			path[i].p_idx = EXT_LAST_INDEX(path[i].p_hdr);
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries)+1;
		} else {
			/* we've already was here, see at next index */
			path[i].p_idx--;
		}

		if (ext4_ext_more_to_rm(path + i)) {
			PPUBLIC_BCB bcb;
			PVOID data;
			/* go to the next level */
			memset(path + i + 1, 0, sizeof(*path));
			bcb = read_extent_tree_block(inode,
										ext4_idx_pblock(path[i].p_idx),
										path[0].p_depth - (i + 1),
										&data, &err,
										0);
			if (err) {
				/* should we reset i_size? */
				break;
			}
			path[i+1].p_bcb = bcb;
			path[i+1].p_data = data;

			/* put actual number of indexes to know is this
			 * number got changed at the next iteration */
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries);
			i++;
		} else {
			/* we finish processing this index, go up */
			if (path[i].p_hdr->eh_entries == 0 && i > 0) {
				/* index is empty, remove it
				 * handle must be already prepared by the
				 * truncatei_leaf() */
				err = ext4_ext_rm_idx(icb, handle, inode, path + i);
			}
			/* root level have p_bcb == NULL, extents_brelse() eats this */
			extents_brelse(path[i].p_bcb);
			path[i].p_bcb = NULL;
			path[i].p_data = NULL;
			i--;
		}
	}

	/* TODO: flexible tree reduction should be here */
	if (path->p_hdr->eh_entries == 0) {
		/*
		 * truncate to zero freed all the tree
		 * so, we need to correct eh_depth
		 */
		ext_inode_hdr(inode)->eh_depth = 0;
		ext_inode_hdr(inode)->eh_max =
			cpu_to_le16(ext4_ext_space_root(inode, 0));
		err = __ext4_ext_dirty(icb, inode, path);
	}
	if (path) {
		ext4_ext_drop_refs(path);
		kfree(path);
	}
	ext4_journal_stop(icb, handle);

	return err;
}

int ext4_ext_tree_init(void *icb, handle_t *v, struct inode *inode)
{
	struct ext4_extent_header *eh;

	eh = ext_inode_hdr(inode);
	eh->eh_depth = 0;
	eh->eh_entries = 0;
	eh->eh_magic = EXT4_EXT_MAGIC;
	eh->eh_max = cpu_to_le16(ext4_ext_space_root(inode, 0));
	ext4_mark_inode_dirty(icb, inode);
	return 0;
}

/*
 * ext4_ext_next_allocated_block:
 * returns allocated block in subsequent extent or EXT_MAX_BLOCKS.
 * NOTE: it considers block number from index entry as
 * allocated block. Thus, index entries have to be consistent
 * with leaves.
 */
ext4_lblk_t
ext4_ext_next_allocated_block(struct ext4_ext_path *path)
{
	int depth;

	depth = path->p_depth;

	if (depth == 0 && path->p_ext == NULL)
		return EXT_MAX_BLOCKS;

	while (depth >= 0) {
		if (depth == path->p_depth) {
			/* leaf */
			if (path[depth].p_ext &&
				path[depth].p_ext !=
					EXT_LAST_EXTENT(path[depth].p_hdr))
			  return le32_to_cpu(path[depth].p_ext[1].ee_block);
		} else {
			/* index */
			if (path[depth].p_idx !=
					EXT_LAST_INDEX(path[depth].p_hdr))
			  return le32_to_cpu(path[depth].p_idx[1].ei_block);
		}
		depth--;
	}

	return EXT_MAX_BLOCKS;
}

int ext4_ext_get_blocks(void *icb, handle_t *handle, struct inode *inode, ext4_fsblk_t iblock,
			unsigned long max_blocks, struct buffer_head *bh_result,
			int create, int extend_disksize)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent newex, *ex;
	int goal, err = 0, depth;
	ext4_lblk_t allocated = 0;
	ext4_fsblk_t next, newblock;

	clear_buffer_new(bh_result);

	/* find extent for this block */
	err = ext4_find_extent(inode, iblock, &path, 0);
	if (err) {
		path = NULL;
		goto out2;
	}

	depth = ext_depth(inode);

	/*
	 * consistent leaf must not be empty
	 * this situations is possible, though, _during_ tree modification
	 * this is why ASSERT can't be put in ext4_ext_find_extent()
	 */
	if ((ex = path[depth].p_ext)) {
	        ext4_lblk_t ee_block = le32_to_cpu(ex->ee_block);
		ext4_fsblk_t ee_start = ext4_ext_pblock(ex);
		unsigned int ee_len  = ext4_ext_get_actual_len(ex);
		/* if found exent covers block, simple return it */
	        if (iblock >= ee_block && iblock < ee_block + ee_len) {
			newblock = iblock - ee_block + ee_start;
			/* number of remain blocks in the extent */
			allocated = ee_len - (iblock - ee_block);
			goto out;
		}
	}

	/*
	 * requested block isn't allocated yet
	 * we couldn't try to create block if create flag is zero
	 */
	if (!create) {
		goto out2;
	}

	/* find next allocated block so that we know how many
	 * blocks we can allocate without ovelapping next extent */
	next = ext4_ext_next_allocated_block(path);
	allocated = next - iblock;
	if (allocated > max_blocks)
		allocated = max_blocks;

	/* allocate new block */
	goal = ext4_ext_find_goal(inode, path, iblock);
	newblock = ext4_new_meta_blocks(icb, inode, goal, 0,
					&allocated, &err);
	if (!newblock)
		goto out2;

	/* try to insert new extent into found leaf and return */
	newex.ee_block = cpu_to_le32(iblock);
	ext4_ext_store_pblock(&newex, newblock);
	newex.ee_len = cpu_to_le16(allocated);
	err = ext4_ext_insert_extent(icb, inode, &path, &newex);
	if (err) {
		/* free data blocks we just allocated */
		ext4_free_blocks(icb, inode, ext4_ext_pblock(&newex),
				le16_to_cpu(newex.ee_len), 0);
		goto out2;
	}

	/* previous routine could use block we allocated */
	newblock = ext4_ext_pblock(&newex);
	set_buffer_new(bh_result);

out:
	if (allocated > max_blocks)
		allocated = max_blocks;
	set_buffer_mapped(bh_result);
	bh_result->b_bdev = inode->i_sb->s_bdev;
	bh_result->b_blocknr = newblock;
out2:
	if (path) {
		ext4_ext_drop_refs(path);
		kfree(path);
	}

	return err ? err : allocated;
}

#pragma pop
