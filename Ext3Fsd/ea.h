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
 * @file  ext4_xattr.h
 * @brief Extended Attribute manipulation.
 */

#ifndef EXT4_XATTR_H_
#define EXT4_XATTR_H_

#include "ext4_config.h"
#include "ext4_types.h"
#include "misc/tree.h"
#include "misc/queue.h"

struct ext4_xattr_item {
	/* This attribute should be stored in inode body */
	bool in_inode;

	uint8_t name_index;
	char  *name;
	size_t name_len;
	void  *data;
	size_t data_size;

	RB_ENTRY(ext4_xattr_item) node;
};

struct ext4_xattr_ref {
	bool block_loaded;
	struct ext4_block block;
	struct ext4_inode_ref *inode_ref;
	bool   dirty;
	size_t ea_size;
	struct ext4_fs *fs;

	void *iter_arg;
	struct ext4_xattr_item *iter_from;

	RB_HEAD(ext4_xattr_tree,
		ext4_xattr_item) root;
};

#define EXT4_XATTR_ITERATE_CONT 0
#define EXT4_XATTR_ITERATE_STOP 1
#define EXT4_XATTR_ITERATE_PAUSE 2

int ext4_fs_get_xattr_ref(struct ext4_fs *fs, struct ext4_inode_ref *inode_ref,
			  struct ext4_xattr_ref *ref);

void ext4_fs_put_xattr_ref(struct ext4_xattr_ref *ref);

int ext4_fs_set_xattr(struct ext4_xattr_ref *ref, uint8_t name_index,
		      const char *name, size_t name_len, const void *data,
		      size_t data_size, bool replace);

int ext4_fs_remove_xattr(struct ext4_xattr_ref *ref, uint8_t name_index,
			 const char *name, size_t name_len);

int ext4_fs_get_xattr(struct ext4_xattr_ref *ref, uint8_t name_index,
		      const char *name, size_t name_len, void *buf,
		      size_t buf_size, size_t *data_size);

void ext4_fs_xattr_iterate(struct ext4_xattr_ref *ref,
			   int (*iter)(struct ext4_xattr_ref *ref,
				     struct ext4_xattr_item *item));

void ext4_fs_xattr_iterate_reset(struct ext4_xattr_ref *ref);

const char *ext4_extract_xattr_name(const char *full_name, size_t full_name_len,
			      uint8_t *name_index, size_t *name_len);

const char *ext4_get_xattr_name_prefix(uint8_t name_index,
				       size_t *ret_prefix_len);

#endif
/**
 * @}
 */
