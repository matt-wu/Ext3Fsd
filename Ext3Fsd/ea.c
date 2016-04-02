/*
 * Copyright (c) 2015 Grzegorz Kostka (kostka.grzegorz@gmail.com)
 * Copyright (c) 2015 Kaho Ng (ngkaho1234@gmail.com)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * - The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @addtogroup lwext4
 * @{
 */
/**
 * @file  ext4_xattr.c
 * @brief Extended Attribute manipulation.
 */

#include "ext4_config.h"
#include "ext4_types.h"
#include "ext4_misc.h"
#include "ext4_errno.h"
#include "ext4_debug.h"

#include "ext4_fs.h"
#include "ext4_trans.h"
#include "ext4_xattr.h"
#include "ext4_blockdev.h"
#include "ext4_super.h"
#include "ext4_crc32.h"
#include "ext4_block_group.h"
#include "ext4_balloc.h"
#include "ext4_inode.h"

#include <string.h>
#include <stdlib.h>

/**
 * @file  ext4_xattr.c
 * @brief Extended Attribute Manipulation
 */

#define NAME_HASH_SHIFT 5
#define VALUE_HASH_SHIFT 16

static inline void ext4_xattr_compute_hash(struct ext4_xattr_header *header,
					   struct ext4_xattr_entry *entry)
{
	uint32_t hash = 0;
	char *name = EXT4_XATTR_NAME(entry);
	int n;

	for (n = 0; n < entry->e_name_len; n++) {
		hash = (hash << NAME_HASH_SHIFT) ^
		       (hash >> (8 * sizeof(hash) - NAME_HASH_SHIFT)) ^ *name++;
	}

	if (entry->e_value_block == 0 && entry->e_value_size != 0) {
		uint32_t *value =
		    (uint32_t *)((char *)header + to_le16(entry->e_value_offs));
		for (n = (to_le32(entry->e_value_size) + EXT4_XATTR_ROUND) >>
			 EXT4_XATTR_PAD_BITS;
		     n; n--) {
			hash = (hash << VALUE_HASH_SHIFT) ^
			       (hash >> (8 * sizeof(hash) - VALUE_HASH_SHIFT)) ^
			       to_le32(*value++);
		}
	}
	entry->e_hash = to_le32(hash);
}

#define BLOCK_HASH_SHIFT 16

/*
 * ext4_xattr_rehash()
 *
 * Re-compute the extended attribute hash value after an entry has changed.
 */
static void ext4_xattr_rehash(struct ext4_xattr_header *header,
			      struct ext4_xattr_entry *entry)
{
	struct ext4_xattr_entry *here;
	uint32_t hash = 0;

	ext4_xattr_compute_hash(header, entry);
	here = EXT4_XATTR_ENTRY(header + 1);
	while (!EXT4_XATTR_IS_LAST_ENTRY(here)) {
		if (!here->e_hash) {
			/* Block is not shared if an entry's hash value == 0 */
			hash = 0;
			break;
		}
		hash = (hash << BLOCK_HASH_SHIFT) ^
		       (hash >> (8 * sizeof(hash) - BLOCK_HASH_SHIFT)) ^
		       to_le32(here->e_hash);
		here = EXT4_XATTR_NEXT(here);
	}
	header->h_hash = to_le32(hash);
}

#define ext4_xattr_block_checksum(...) 0

static void
ext4_xattr_set_block_checksum(struct ext4_inode_ref *inode_ref,
			      ext4_fsblk_t blocknr __unused,
			      struct ext4_xattr_header *header)
{
	struct ext4_sblock *sb = &inode_ref->fs->sb;
	if (!ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		return;

	header->h_checksum =
		ext4_xattr_block_checksum(inode_ref, blocknr, header);
}

static int ext4_xattr_item_cmp(struct ext4_xattr_item *a,
			       struct ext4_xattr_item *b)
{
	int result;
	if (a->in_inode && !b->in_inode)
		return -1;
	
	if (!a->in_inode && b->in_inode)
		return 1;

	result = a->name_index - b->name_index;
	if (result)
		return result;

	result = a->name_len - b->name_len;
	if (result)
		return result;

	return memcmp(a->name, b->name, a->name_len);
}

RB_GENERATE_INTERNAL(ext4_xattr_tree, ext4_xattr_item, node,
		     ext4_xattr_item_cmp, static inline)

static struct ext4_xattr_item *
ext4_xattr_item_alloc(uint8_t name_index, const char *name, size_t name_len)
{
	struct ext4_xattr_item *item;
	item = malloc(sizeof(struct ext4_xattr_item) + name_len);
	if (!item)
		return NULL;

	item->name_index = name_index;
	item->name = (char *)(item + 1);
	item->name_len = name_len;
	item->data = NULL;
	item->data_size = 0;

	memset(&item->node, 0, sizeof(item->node));
	memcpy(item->name, name, name_len);

	if (name_index == EXT4_XATTR_INDEX_SYSTEM &&
	    name_len == 4 &&
	    !memcmp(name, "data", 4))
		item->in_inode = true;
	else
		item->in_inode = false;

	return item;
}

static int ext4_xattr_item_alloc_data(struct ext4_xattr_item *item,
				      const void *orig_data, size_t data_size)
{
	void *data = NULL;
	ext4_assert(!item->data);
	data = malloc(data_size);
	if (!data)
		return ENOMEM;

	if (orig_data)
		memcpy(data, orig_data, data_size);

	item->data = data;
	item->data_size = data_size;
	return EOK;
}

static void ext4_xattr_item_free_data(struct ext4_xattr_item *item)
{
	ext4_assert(item->data);
	free(item->data);
	item->data = NULL;
	item->data_size = 0;
}

static int ext4_xattr_item_resize_data(struct ext4_xattr_item *item,
				       size_t new_data_size)
{
	if (new_data_size != item->data_size) {
		void *new_data;
		new_data = realloc(item->data, new_data_size);
		if (!new_data)
			return ENOMEM;

		item->data = new_data;
		item->data_size = new_data_size;
	}
	return EOK;
}

static void ext4_xattr_item_free(struct ext4_xattr_item *item)
{
	if (item->data)
		ext4_xattr_item_free_data(item);

	free(item);
}

static void *ext4_xattr_entry_data(struct ext4_xattr_ref *xattr_ref,
				   struct ext4_xattr_entry *entry,
				   bool in_inode)
{
	char *ret;
	if (in_inode) {
		struct ext4_xattr_ibody_header *header;
		struct ext4_xattr_entry *first_entry;
		int16_t inode_size =
		    ext4_get16(&xattr_ref->fs->sb, inode_size);
		header = EXT4_XATTR_IHDR(xattr_ref->inode_ref->inode);
		first_entry = EXT4_XATTR_IFIRST(header);

		ret = ((char *)first_entry + to_le16(entry->e_value_offs));
		if (ret + EXT4_XATTR_SIZE(to_le32(entry->e_value_size)) -
			(char *)xattr_ref->inode_ref->inode > inode_size)
			ret = NULL;

		return ret;

	}
	int32_t block_size = ext4_sb_get_block_size(&xattr_ref->fs->sb);
	ret = ((char *)xattr_ref->block.data + to_le16(entry->e_value_offs));
	if (ret + EXT4_XATTR_SIZE(to_le32(entry->e_value_size)) -
			(char *)xattr_ref->block.data > block_size)
		ret = NULL;
	return ret;
}

static int ext4_xattr_block_fetch(struct ext4_xattr_ref *xattr_ref)
{
	int ret = EOK;
	size_t size_rem;
	void *data;
	struct ext4_xattr_entry *entry = NULL;

	ext4_assert(xattr_ref->block.data);
	entry = EXT4_XATTR_BFIRST(&xattr_ref->block);

	size_rem = ext4_sb_get_block_size(&xattr_ref->fs->sb);
	for (; size_rem > 0 && !EXT4_XATTR_IS_LAST_ENTRY(entry);
	     entry = EXT4_XATTR_NEXT(entry),
	     size_rem -= EXT4_XATTR_LEN(entry->e_name_len)) {
		struct ext4_xattr_item *item;
		char *e_name = EXT4_XATTR_NAME(entry);

		data = ext4_xattr_entry_data(xattr_ref, entry, false);
		if (!data) {
			ret = EIO;
			goto Finish;
		}

		item = ext4_xattr_item_alloc(entry->e_name_index, e_name,
					     (size_t)entry->e_name_len);
		if (!item) {
			ret = ENOMEM;
			goto Finish;
		}
		if (ext4_xattr_item_alloc_data(
			item, data, to_le32(entry->e_value_size)) != EOK) {
			ext4_xattr_item_free(item);
			ret = ENOMEM;
			goto Finish;
		}
		RB_INSERT(ext4_xattr_tree, &xattr_ref->root, item);
		xattr_ref->ea_size += EXT4_XATTR_SIZE(item->data_size) +
				      EXT4_XATTR_LEN(item->name_len);
	}

Finish:
	return ret;
}

static int ext4_xattr_inode_fetch(struct ext4_xattr_ref *xattr_ref)
{
	void *data;
	size_t size_rem;
	int ret = EOK;
	struct ext4_xattr_ibody_header *header = NULL;
	struct ext4_xattr_entry *entry = NULL;
	uint16_t inode_size = ext4_get16(&xattr_ref->fs->sb, inode_size);

	header = EXT4_XATTR_IHDR(xattr_ref->inode_ref->inode);
	entry = EXT4_XATTR_IFIRST(header);

	size_rem = inode_size - EXT4_GOOD_OLD_INODE_SIZE -
		   xattr_ref->inode_ref->inode->extra_isize;
	for (; size_rem > 0 && !EXT4_XATTR_IS_LAST_ENTRY(entry);
	     entry = EXT4_XATTR_NEXT(entry),
	     size_rem -= EXT4_XATTR_LEN(entry->e_name_len)) {
		struct ext4_xattr_item *item;
		char *e_name = EXT4_XATTR_NAME(entry);

		data = ext4_xattr_entry_data(xattr_ref, entry, true);
		if (!data) {
			ret = EIO;
			goto Finish;
		}

		item = ext4_xattr_item_alloc(entry->e_name_index, e_name,
					     (size_t)entry->e_name_len);
		if (!item) {
			ret = ENOMEM;
			goto Finish;
		}
		if (ext4_xattr_item_alloc_data(
			item, data, to_le32(entry->e_value_size)) != EOK) {
			ext4_xattr_item_free(item);
			ret = ENOMEM;
			goto Finish;
		}
		RB_INSERT(ext4_xattr_tree, &xattr_ref->root, item);
		xattr_ref->ea_size += EXT4_XATTR_SIZE(item->data_size) +
				      EXT4_XATTR_LEN(item->name_len);
	}

Finish:
	return ret;
}

static size_t ext4_xattr_inode_space(struct ext4_xattr_ref *xattr_ref)
{
	uint16_t inode_size = ext4_get16(&xattr_ref->fs->sb, inode_size);
	uint16_t size_rem = inode_size - EXT4_GOOD_OLD_INODE_SIZE -
			    xattr_ref->inode_ref->inode->extra_isize;
	return size_rem;
}

static size_t ext4_xattr_block_space(struct ext4_xattr_ref *xattr_ref)
{
	return ext4_sb_get_block_size(&xattr_ref->fs->sb);
}

static int ext4_xattr_fetch(struct ext4_xattr_ref *xattr_ref)
{
	int ret = EOK;
	uint16_t inode_size = ext4_get16(&xattr_ref->fs->sb, inode_size);
	if (inode_size > EXT4_GOOD_OLD_INODE_SIZE) {
		ret = ext4_xattr_inode_fetch(xattr_ref);
		if (ret != EOK)
			return ret;
	}

	if (xattr_ref->block_loaded)
		ret = ext4_xattr_block_fetch(xattr_ref);

	xattr_ref->dirty = false;
	return ret;
}

static struct ext4_xattr_item *
ext4_xattr_lookup_item(struct ext4_xattr_ref *xattr_ref, uint8_t name_index,
		       const char *name, size_t name_len)
{
	struct ext4_xattr_item tmp = {
		.name_index = name_index,
		.name = (char *)name, /*RB_FIND - won't touch this string*/
		.name_len = name_len,
	};
	if (name_index == EXT4_XATTR_INDEX_SYSTEM &&
	    name_len == 4 &&
	    !memcmp(name, "data", 4))
		tmp.in_inode = true;

	return RB_FIND(ext4_xattr_tree, &xattr_ref->root, &tmp);
}

static struct ext4_xattr_item *
ext4_xattr_insert_item(struct ext4_xattr_ref *xattr_ref, uint8_t name_index,
		       const char *name, size_t name_len, const void *data,
		       size_t data_size)
{
	struct ext4_xattr_item *item;
	item = ext4_xattr_item_alloc(name_index, name, name_len);
	if (!item)
		return NULL;

	if ((xattr_ref->ea_size + EXT4_XATTR_SIZE(data_size) +
		EXT4_XATTR_LEN(item->name_len)
			>
	    ext4_xattr_inode_space(xattr_ref) -
	    	sizeof(struct ext4_xattr_ibody_header))
		&&
	    (xattr_ref->ea_size + EXT4_XATTR_SIZE(data_size) +
		EXT4_XATTR_LEN(item->name_len) >
	    ext4_xattr_block_space(xattr_ref) -
	    	sizeof(struct ext4_xattr_header))) {
		ext4_xattr_item_free(item);

		return NULL;
	}
	if (ext4_xattr_item_alloc_data(item, data, data_size) != EOK) {
		ext4_xattr_item_free(item);
		return NULL;
	}
	RB_INSERT(ext4_xattr_tree, &xattr_ref->root, item);
	xattr_ref->ea_size +=
	    EXT4_XATTR_SIZE(item->data_size) + EXT4_XATTR_LEN(item->name_len);
	xattr_ref->dirty = true;
	return item;
}

static int ext4_xattr_remove_item(struct ext4_xattr_ref *xattr_ref,
				  uint8_t name_index, const char *name,
				  size_t name_len)
{
	int ret = ENOENT;
	struct ext4_xattr_item *item =
	    ext4_xattr_lookup_item(xattr_ref, name_index, name, name_len);
	if (item) {
		if (item == xattr_ref->iter_from)
			xattr_ref->iter_from =
			    RB_NEXT(ext4_xattr_tree, &xattr_ref->root, item);

		xattr_ref->ea_size -= EXT4_XATTR_SIZE(item->data_size) +
				      EXT4_XATTR_LEN(item->name_len);

		RB_REMOVE(ext4_xattr_tree, &xattr_ref->root, item);
		ext4_xattr_item_free(item);
		xattr_ref->dirty = true;
		ret = EOK;
	}
	return ret;
}

static int ext4_xattr_resize_item(struct ext4_xattr_ref *xattr_ref,
				  struct ext4_xattr_item *item,
				  size_t new_data_size)
{
	int ret = EOK;
	size_t old_data_size = item->data_size;
	if ((xattr_ref->ea_size - EXT4_XATTR_SIZE(old_data_size) +
		EXT4_XATTR_SIZE(new_data_size)
			>
	    ext4_xattr_inode_space(xattr_ref) -
	    	sizeof(struct ext4_xattr_ibody_header))
		&&
	    (xattr_ref->ea_size - EXT4_XATTR_SIZE(old_data_size) +
		EXT4_XATTR_SIZE(new_data_size)
			>
	    ext4_xattr_block_space(xattr_ref) -
	    	sizeof(struct ext4_xattr_header))) {

		return ENOSPC;
	}
	ret = ext4_xattr_item_resize_data(item, new_data_size);
	if (ret != EOK) {
		return ret;
	}
	xattr_ref->ea_size =
	    xattr_ref->ea_size -
	    EXT4_XATTR_SIZE(old_data_size) +
	    EXT4_XATTR_SIZE(new_data_size);
	xattr_ref->dirty = true;
	return ret;
}

static void ext4_xattr_purge_items(struct ext4_xattr_ref *xattr_ref)
{
	struct ext4_xattr_item *item, *save_item;
	RB_FOREACH_SAFE(item, ext4_xattr_tree, &xattr_ref->root, save_item)
	{
		RB_REMOVE(ext4_xattr_tree, &xattr_ref->root, item);
		ext4_xattr_item_free(item);
	}
	xattr_ref->ea_size = 0;
}

static int ext4_xattr_try_alloc_block(struct ext4_xattr_ref *xattr_ref)
{
	int ret = EOK;

	ext4_fsblk_t xattr_block = 0;
	xattr_block = ext4_inode_get_file_acl(xattr_ref->inode_ref->inode,
					      &xattr_ref->fs->sb);
	if (!xattr_block) {
		ext4_fsblk_t goal =
			ext4_fs_inode_to_goal_block(xattr_ref->inode_ref);

		ret = ext4_balloc_alloc_block(xattr_ref->inode_ref,
					      goal,
					      &xattr_block);
		if (ret != EOK)
			goto Finish;

		ret = ext4_trans_block_get(xattr_ref->fs->bdev, &xattr_ref->block,
				     xattr_block);
		if (ret != EOK) {
			ext4_balloc_free_block(xattr_ref->inode_ref,
					       xattr_block);
			goto Finish;
		}

		ext4_inode_set_file_acl(xattr_ref->inode_ref->inode,
					&xattr_ref->fs->sb, xattr_block);
		xattr_ref->inode_ref->dirty = true;
		xattr_ref->block_loaded = true;
	}

Finish:
	return ret;
}

static void ext4_xattr_try_free_block(struct ext4_xattr_ref *xattr_ref)
{
	ext4_fsblk_t xattr_block;
	xattr_block = ext4_inode_get_file_acl(xattr_ref->inode_ref->inode,
					      &xattr_ref->fs->sb);
	ext4_inode_set_file_acl(xattr_ref->inode_ref->inode, &xattr_ref->fs->sb,
				0);
	ext4_block_set(xattr_ref->fs->bdev, &xattr_ref->block);
	ext4_balloc_free_block(xattr_ref->inode_ref, xattr_block);
	xattr_ref->inode_ref->dirty = true;
	xattr_ref->block_loaded = false;
}

static void ext4_xattr_set_block_header(struct ext4_xattr_ref *xattr_ref)
{
	struct ext4_xattr_header *block_header = NULL;
	block_header = EXT4_XATTR_BHDR(&xattr_ref->block);

	memset(block_header, 0, sizeof(struct ext4_xattr_header));
	block_header->h_magic = EXT4_XATTR_MAGIC;
	block_header->h_refcount = to_le32(1);
	block_header->h_blocks = to_le32(1);
}

static void
ext4_xattr_set_inode_entry(struct ext4_xattr_item *item,
			   struct ext4_xattr_ibody_header *ibody_header,
			   struct ext4_xattr_entry *entry, void *ibody_data_ptr)
{
	entry->e_name_len = (uint8_t)item->name_len;
	entry->e_name_index = item->name_index;
	entry->e_value_offs =
	    (char *)ibody_data_ptr - (char *)EXT4_XATTR_IFIRST(ibody_header);
	entry->e_value_block = 0;
	entry->e_value_size = item->data_size;
}

static void ext4_xattr_set_block_entry(struct ext4_xattr_item *item,
				       struct ext4_xattr_header *block_header,
				       struct ext4_xattr_entry *block_entry,
				       void *block_data_ptr)
{
	block_entry->e_name_len = (uint8_t)item->name_len;
	block_entry->e_name_index = item->name_index;
	block_entry->e_value_offs =
	    (char *)block_data_ptr - (char *)block_header;
	block_entry->e_value_block = 0;
	block_entry->e_value_size = item->data_size;
}

static int ext4_xattr_write_to_disk(struct ext4_xattr_ref *xattr_ref)
{
	int ret = EOK;
	bool block_modified = false;
	void *ibody_data = NULL;
	void *block_data = NULL;
	struct ext4_xattr_item *item, *save_item;
	size_t inode_size_rem, block_size_rem;
	struct ext4_xattr_ibody_header *ibody_header = NULL;
	struct ext4_xattr_header *block_header = NULL;
	struct ext4_xattr_entry *entry = NULL;
	struct ext4_xattr_entry *block_entry = NULL;

	inode_size_rem = ext4_xattr_inode_space(xattr_ref);
	block_size_rem = ext4_xattr_block_space(xattr_ref);
	if (inode_size_rem > sizeof(struct ext4_xattr_ibody_header)) {
		ibody_header = EXT4_XATTR_IHDR(xattr_ref->inode_ref->inode);
		entry = EXT4_XATTR_IFIRST(ibody_header);
	}

	if (!xattr_ref->dirty)
		goto Finish;
	/* If there are enough spaces in the ibody EA table.*/
	if (inode_size_rem > sizeof(struct ext4_xattr_ibody_header)) {
		memset(ibody_header, 0, inode_size_rem);
		ibody_header->h_magic = EXT4_XATTR_MAGIC;
		ibody_data = (char *)ibody_header + inode_size_rem;
		inode_size_rem -= sizeof(struct ext4_xattr_ibody_header);

		xattr_ref->inode_ref->dirty = true;
	}
	/* If we need an extra block to hold the EA entries*/
	if (xattr_ref->ea_size > inode_size_rem) {
		if (!xattr_ref->block_loaded) {
			ret = ext4_xattr_try_alloc_block(xattr_ref);
			if (ret != EOK)
				goto Finish;
		}
		block_header = EXT4_XATTR_BHDR(&xattr_ref->block);
		block_entry = EXT4_XATTR_BFIRST(&xattr_ref->block);
		ext4_xattr_set_block_header(xattr_ref);
		block_data = (char *)block_header + block_size_rem;
		block_size_rem -= sizeof(struct ext4_xattr_header);

		ext4_trans_set_block_dirty(xattr_ref->block.buf);
	} else {
		/* We don't need an extra block.*/
		if (xattr_ref->block_loaded) {
			block_header = EXT4_XATTR_BHDR(&xattr_ref->block);
			block_header->h_refcount =
			    to_le32(to_le32(block_header->h_refcount) - 1);
			if (!block_header->h_refcount) {
				ext4_xattr_try_free_block(xattr_ref);
				block_header = NULL;
			} else {
				block_entry =
				    EXT4_XATTR_BFIRST(&xattr_ref->block);
				block_data =
				    (char *)block_header + block_size_rem;
				block_size_rem -=
				    sizeof(struct ext4_xattr_header);
				ext4_inode_set_file_acl(
				    xattr_ref->inode_ref->inode,
				    &xattr_ref->fs->sb, 0);

				xattr_ref->inode_ref->dirty = true;
				ext4_trans_set_block_dirty(xattr_ref->block.buf);
			}
		}
	}
	RB_FOREACH_SAFE(item, ext4_xattr_tree, &xattr_ref->root, save_item)
	{
		if (EXT4_XATTR_SIZE(item->data_size) +
			EXT4_XATTR_LEN(item->name_len) <=
		    inode_size_rem) {
			ibody_data = (char *)ibody_data -
				     EXT4_XATTR_SIZE(item->data_size);
			ext4_xattr_set_inode_entry(item, ibody_header, entry,
						   ibody_data);
			memcpy(EXT4_XATTR_NAME(entry), item->name,
			       item->name_len);
			memcpy(ibody_data, item->data, item->data_size);
			entry = EXT4_XATTR_NEXT(entry);
			inode_size_rem -= EXT4_XATTR_SIZE(item->data_size) +
					  EXT4_XATTR_LEN(item->name_len);

			xattr_ref->inode_ref->dirty = true;
			continue;
		}
		if (EXT4_XATTR_SIZE(item->data_size) +
			EXT4_XATTR_LEN(item->name_len) >
		    block_size_rem) {
			ret = ENOSPC;
			goto Finish;
		}
		block_data =
		    (char *)block_data - EXT4_XATTR_SIZE(item->data_size);
		ext4_xattr_set_block_entry(item, block_header, block_entry,
					   block_data);
		memcpy(EXT4_XATTR_NAME(block_entry), item->name,
		       item->name_len);
		memcpy(block_data, item->data, item->data_size);
		block_entry = EXT4_XATTR_NEXT(block_entry);
		block_size_rem -= EXT4_XATTR_SIZE(item->data_size) +
				  EXT4_XATTR_LEN(item->name_len);

		block_modified = true;
	}
	xattr_ref->dirty = false;
	if (block_modified) {
		ext4_xattr_rehash(block_header,
				  EXT4_XATTR_BFIRST(&xattr_ref->block));
		ext4_xattr_set_block_checksum(xattr_ref->inode_ref,
					      xattr_ref->block.lb_id,
					      block_header);
		ext4_trans_set_block_dirty(xattr_ref->block.buf);
	}

Finish:
	return ret;
}

void ext4_fs_xattr_iterate(struct ext4_xattr_ref *ref,
			   int (*iter)(struct ext4_xattr_ref *ref,
				     struct ext4_xattr_item *item))
{
	struct ext4_xattr_item *item;
	if (!ref->iter_from)
		ref->iter_from = RB_MIN(ext4_xattr_tree, &ref->root);

	RB_FOREACH_FROM(item, ext4_xattr_tree, ref->iter_from)
	{
		int ret = EXT4_XATTR_ITERATE_CONT;
		if (iter)
			iter(ref, item);

		if (ret != EXT4_XATTR_ITERATE_CONT) {
			if (ret == EXT4_XATTR_ITERATE_STOP)
				ref->iter_from = NULL;

			break;
		}
	}
}

void ext4_fs_xattr_iterate_reset(struct ext4_xattr_ref *ref)
{
	ref->iter_from = NULL;
}

int ext4_fs_set_xattr(struct ext4_xattr_ref *ref, uint8_t name_index,
		      const char *name, size_t name_len, const void *data,
		      size_t data_size, bool replace)
{
	int ret = EOK;
	struct ext4_xattr_item *item =
	    ext4_xattr_lookup_item(ref, name_index, name, name_len);
	if (replace) {
		if (!item) {
			ret = ENODATA;
			goto Finish;
		}
		if (item->data_size != data_size)
			ret = ext4_xattr_resize_item(ref, item, data_size);

		if (ret != EOK) {
			goto Finish;
		}
		memcpy(item->data, data, data_size);
	} else {
		if (item) {
			ret = EEXIST;
			goto Finish;
		}
		item = ext4_xattr_insert_item(ref, name_index, name, name_len,
					      data, data_size);
		if (!item)
			ret = ENOMEM;
	}
Finish:
	return ret;
}

int ext4_fs_remove_xattr(struct ext4_xattr_ref *ref, uint8_t name_index,
			 const char *name, size_t name_len)
{
	return ext4_xattr_remove_item(ref, name_index, name, name_len);
}

int ext4_fs_get_xattr(struct ext4_xattr_ref *ref, uint8_t name_index,
		      const char *name, size_t name_len, void *buf,
		      size_t buf_size, size_t *data_size)
{
	int ret = EOK;
	size_t item_size = 0;
	struct ext4_xattr_item *item =
	    ext4_xattr_lookup_item(ref, name_index, name, name_len);

	if (!item) {
		ret = ENODATA;
		goto Finish;
	}
	item_size = item->data_size;
	if (buf_size > item_size)
		buf_size = item_size;

	if (buf)
		memcpy(buf, item->data, buf_size);

Finish:
	if (data_size)
		*data_size = item_size;

	return ret;
}

int ext4_fs_get_xattr_ref(struct ext4_fs *fs, struct ext4_inode_ref *inode_ref,
			  struct ext4_xattr_ref *ref)
{
	int rc;
	ext4_fsblk_t xattr_block;
	xattr_block = ext4_inode_get_file_acl(inode_ref->inode, &fs->sb);
	RB_INIT(&ref->root);
	ref->ea_size = 0;
	ref->iter_from = NULL;
	if (xattr_block) {
		rc = ext4_trans_block_get(fs->bdev, &ref->block, xattr_block);
		if (rc != EOK)
			return EIO;

		ref->block_loaded = true;
	} else
		ref->block_loaded = false;

	ref->inode_ref = inode_ref;
	ref->fs = fs;

	rc = ext4_xattr_fetch(ref);
	if (rc != EOK) {
		ext4_xattr_purge_items(ref);
		if (xattr_block)
			ext4_block_set(fs->bdev, &inode_ref->block);

		ref->block_loaded = false;
		return rc;
	}
	return EOK;
}

void ext4_fs_put_xattr_ref(struct ext4_xattr_ref *ref)
{
	ext4_xattr_write_to_disk(ref);
	if (ref->block_loaded) {
		ext4_block_set(ref->fs->bdev, &ref->block);
		ref->block_loaded = false;
	}
	ext4_xattr_purge_items(ref);
	ref->inode_ref = NULL;
	ref->fs = NULL;
}

struct xattr_prefix {
	const char *prefix;
	uint8_t name_index;
};

static const struct xattr_prefix prefix_tbl[] = {
    {"user.", EXT4_XATTR_INDEX_USER},
    {"system.posix_acl_access", EXT4_XATTR_INDEX_POSIX_ACL_ACCESS},
    {"system.posix_acl_default", EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT},
    {"trusted.", EXT4_XATTR_INDEX_TRUSTED},
    {"security.", EXT4_XATTR_INDEX_SECURITY},
    {"system.", EXT4_XATTR_INDEX_SYSTEM},
    {"system.richacl", EXT4_XATTR_INDEX_RICHACL},
    {NULL, 0},
};

const char *ext4_extract_xattr_name(const char *full_name, size_t full_name_len,
			      uint8_t *name_index, size_t *name_len)
{
	int i;
	ext4_assert(name_index);
	if (!full_name_len) {
		if (name_len)
			*name_len = 0;

		return NULL;
	}

	for (i = 0; prefix_tbl[i].prefix; i++) {
		size_t prefix_len = strlen(prefix_tbl[i].prefix);
		if (full_name_len >= prefix_len &&
		    !memcmp(full_name, prefix_tbl[i].prefix, prefix_len)) {
			*name_index = prefix_tbl[i].name_index;
			if (name_len)
				*name_len = full_name_len - prefix_len;

			return full_name + prefix_len;
		}
	}
	if (name_len)
		*name_len = 0;

	return NULL;
}

const char *ext4_get_xattr_name_prefix(uint8_t name_index,
				       size_t *ret_prefix_len)
{
	int i;

	for (i = 0; prefix_tbl[i].prefix; i++) {
		size_t prefix_len = strlen(prefix_tbl[i].prefix);
		if (prefix_tbl[i].name_index == name_index) {
			if (ret_prefix_len)
				*ret_prefix_len = prefix_len;

			return prefix_tbl[i].prefix;
		}
	}
	if (ret_prefix_len)
		*ret_prefix_len = 0;

	return NULL;
}

/**
 * @}
 */
