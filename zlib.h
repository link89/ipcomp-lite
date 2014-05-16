#ifndef _IPCOMP_ZLIB_H
#define _IPCOMP_ZLIB_H


int zlib_workspace_cache_create(void);
void zlib_workspace_cache_destroy(void);
void* zlib_workspace_alloc(void);
void zlib_workspace_free(void *);
int zlib_compress_init(struct compress_info *, z_stream *);
int zlib_compress_begin(struct compress_info *, z_stream *);
void zlib_compress_end(z_stream *);
int zlib_compress(struct compress_info *);
int zlib_decompress_init(struct compress_info *, z_stream *);
int zlib_decompress_begin(struct compress_info *, z_stream *);
void zlib_decompress_end(z_stream *);
int zlib_decompress(struct compress_info *);

#endif
