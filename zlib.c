/*
 * Zlib interface for IPCOMP
 *
 * Copyright (C) 2014 Weihong,Xu <xuweihong.cn@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * Code Reference: btrfs
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <linux/err.h>

#include "ipcomp.h"
#include "zlib.h"

static struct kmem_cache *zlib_workspace_cache;

int zlib_workspace_cache_create()
{
	size_t workspacesize = max(zlib_deflate_workspacesize(
		-MAX_WBITS, MAX_MEM_LEVEL), zlib_inflate_workspacesize());
	zlib_workspace_cache = kmem_cache_create("zlib workspace",
		workspacesize, 0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (IS_ERR_OR_NULL(zlib_workspace_cache))
		return -ENOMEM;
	return 0;
}

void zlib_workspace_cache_destroy()
{
	kmem_cache_destroy(zlib_workspace_cache);
}

void* zlib_workspace_alloc()
{
	return kmem_cache_alloc(zlib_workspace_cache, GFP_ATOMIC);
}

void zlib_workspace_free(void *objp)
{
	kmem_cache_free(zlib_workspace_cache, objp);
}

int zlib_compress_init(struct compress_info *info,
		z_stream *zs)
{
	void *workspace = NULL;
	int err;

	workspace = zlib_workspace_alloc();
	if (IS_ERR_OR_NULL(workspace)) {
		return -ENOMEM;
	}
	zs->workspace = workspace;

	err = zlib_deflateInit2(zs, Z_DEFAULT_COMPRESSION,
			Z_DEFLATED, -15, DEF_MEM_LEVEL,
			Z_DEFAULT_STRATEGY);
	if (Z_OK != err) {
		zlib_workspace_free(workspace);
		return -EPERM;
	}

	zs->total_in = 0;
	zs->total_out = 0;
	zs->avail_in = info->in_size;
	zs->next_in = info->in_data;

	return 0;
}

int zlib_compress_begin(struct compress_info *info,
		z_stream *zs)
{
	void *buffer;
	int flush, err = 0;
	struct out_buffer *out_buffer = info->out_data;

	do {
		buffer = out_buffer_alloc();
		if (IS_ERR_OR_NULL(buffer)) {
			out_buffer_free_all(out_buffer);
			return -ENOMEM;
		}
		if (out_buffer_add(out_buffer, buffer)) {
			out_buffer_free_all(out_buffer);
			return -EPERM;
		}

		zs->avail_out = PER_BUFFER_SIZE;
		zs->next_out = buffer;

		flush = (zs->avail_in < PER_BUFFER_SIZE) ?
			Z_FINISH : Z_NO_FLUSH;

		err = zlib_deflate(zs, flush);
		if ((err != Z_OK && err != Z_STREAM_END)
				|| info->in_size <= zs->total_out + IPCOMP_HEADER_SIZE) {
			out_buffer_free_all(out_buffer);
			return -EPERM;
		}
		BUG_ON( err == Z_OK && zs->avail_out);
	} while ( err != Z_STREAM_END);

	info->out_size = zs->total_out;
	return 0;
}

void zlib_compress_end(z_stream *zs)
{
	zlib_deflateEnd(zs);
	zlib_workspace_free(zs->workspace);
}

int zlib_compress(struct compress_info *info)
{
	int err = 0;
	z_stream zs;
	err = zlib_compress_init(info, &zs);
	if (err)
		goto out;
	err = zlib_compress_begin(info, &zs);
	zlib_compress_end(&zs);
out:
	return err;
}

int zlib_decompress_init(struct compress_info *info,
		z_stream *zs)
{
	void *workspace = NULL;
	int err;

	workspace = zlib_workspace_alloc();
	if (IS_ERR_OR_NULL(workspace))
		return -ENOMEM;
	zs->workspace = workspace;

	err = zlib_inflateInit2(zs, -MAX_WBITS);
	if (Z_OK != err) {
		zlib_workspace_free(workspace);
		return -EPERM;
	}

	zs->total_in = 0;
	zs->total_out = 0;
	zs->avail_in = info->in_size;
	zs->next_in = info->in_data;

	return 0;
}

int zlib_decompress_begin(struct compress_info *info,
		z_stream *zs)
{
	void *buffer;
	int err = 0;
	struct out_buffer *out_buffer = info->out_data;

	do {
		buffer = out_buffer_alloc();
		if (IS_ERR_OR_NULL(buffer)) {
			out_buffer_free_all(out_buffer);
			return -ENOMEM;
		}
		if (out_buffer_add(out_buffer, buffer)){
			out_buffer_free_all(out_buffer);
			return -EPERM;
		}

		zs->avail_out = PER_BUFFER_SIZE;
		zs->next_out = buffer;

		err = zlib_inflate(zs, Z_NO_FLUSH);
		if (err != Z_OK
				&& err != Z_STREAM_END) {
			out_buffer_free_all(out_buffer);
			return -EPERM;
		}
		/* work around a bug in zlib, which sometimes wants to taste an extra
		 * byte when being used in the (undocumented) raw deflate mode.
		 */
		if (err == Z_OK && !zs->avail_in && zs->avail_out) {
			__u8 zerostuff = 0;
			zs->next_in = &zerostuff;
			zs->avail_in = 1;
			err = zlib_inflate(zs, Z_FINISH);
			if (err != Z_STREAM_END) {
				out_buffer_free_all(out_buffer);
				return -EPERM;
			}
		}
	} while (err !=Z_STREAM_END);

	info->out_size = zs->total_out;
	return 0;
}

void zlib_decompress_end(z_stream *zs)
{
	zlib_inflateEnd(zs);
	zlib_workspace_free(zs->workspace);
}

int zlib_decompress(struct compress_info *info)
{
	int err = 0;
	z_stream zs;
	err = zlib_decompress_init(info, &zs);
	if (err)
		goto out;
	err = zlib_decompress_begin(info, &zs);
	zlib_decompress_end(&zs);
out:
	return err;
}

struct compress_ops zlib_compress_ops = {
	.compress = zlib_compress,
	.decompress = zlib_decompress,
};
