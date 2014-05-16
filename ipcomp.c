/*
 * An IPCOMP like IP Payload Compression Protocol 
 * Based on  RFC 3173.
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
 * Code Reference: Openswan
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <linux/ip.h>
#include <net/ip.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/zlib.h>

#include <asm/checksum.h>

#include "ipcomp.h"
#include "zlib.h"

/* Compress Operations */
struct compress_ops *compress_ops[] = {
	&zlib_compress_ops,
};

/* Help Functions */
static struct kmem_cache *out_buffer_cache;

int out_buffer_cache_create()
{
	out_buffer_cache = kmem_cache_create("ipcomp buffer",
			PER_BUFFER_SIZE, 0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (IS_ERR_OR_NULL(out_buffer_cache))
		return -ENOMEM;
	return 0;
}

void out_buffer_cache_destroy()
{
	kmem_cache_destroy(out_buffer_cache);
}

void* out_buffer_alloc()
{
	return kmem_cache_alloc(out_buffer_cache, GFP_ATOMIC);
}

void out_buffer_init(struct out_buffer *out_buffer)
{
	out_buffer->next_buf = 0;
}

int out_buffer_add(struct out_buffer *out_buffer, void *buffer)
{
	if (out_buffer->next_buf > MAX_BUFFER_NUM)
		return -EPERM;
	out_buffer->buffer[out_buffer->next_buf++] = buffer;
	return 0;
}

void out_buffer_free(void *objp)
{
	kmem_cache_free(out_buffer_cache, objp);
}

void out_buffer_free_all(struct out_buffer *out_buffer)
{
	while (out_buffer->next_buf >0)
		out_buffer_free(
				out_buffer->buffer[--out_buffer->next_buf]);
}

void* out_buffer_cpy(void *dst, struct out_buffer *src, size_t len)
{
	int i = 0;
	size_t size;
	void *_dst = dst, *err = NULL;
	while (len) {
		if (i == src->next_buf) {
			err = ERR_PTR(-EPERM);
			break;
		}
		size = (len > PER_BUFFER_SIZE) ?
			PER_BUFFER_SIZE : len;
		err = memcpy(_dst, src->buffer[i++], size);
		if (IS_ERR(err))
			break;
		_dst += size;
		len -= size;
	}
	return err;
}

/* Netfilter hook functions */
static unsigned int compress_hf(const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	return skb_compress(skb);
}

static unsigned int decompress_hf(const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	return skb_decompress(skb);
}

unsigned int skb_compress(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct ip_comp_hdr *ipcomph;
	unsigned char nexthdr;
	size_t iphlen, delta;

	struct compress_info info;
	struct out_buffer out_data;

	int err = 0;
	unsigned int ret = NF_ACCEPT;
	out_buffer_init(&out_data);

	/* Filter Packet */
	if (!skb)
		goto out;
	skb_linearize(skb);
	iph = ip_hdr(skb);
	if (iph->version == 6)
		goto out;
	nexthdr = iph->protocol;
	if (nexthdr != IPPROTO_TCP
			&& nexthdr != IPPROTO_UDP)
		goto out;
	if (iph->frag_off & __constant_htons(IP_MF | IP_OFFSET))
		goto out;

	/* Compress IP Payload */
	iphlen = iph->ihl << 2;
	info.in_size = ntohs(iph->tot_len) - iphlen;
	info.in_data = (void *)iph + iphlen;
	info.out_data = &out_data;

	err = compress_ops[0]->compress(&info);
	if (err)
		goto out;

	/* Insert IPCOMP Header */
	ipcomph = ipcomp_hdr(skb);
	ipcomph->nexthdr = nexthdr;
	ipcomph->flags = 0;
	ipcomph->cpi = htons((__be16) 0x00000000);

	/* Update IP Header */
	iph->protocol = IPPROTO_COMP;
	iph->tot_len = htons(iphlen + sizeof(struct ip_comp_hdr) + info.out_size);
	iph->check = 0;
	iph->check = ip_fast_csum((void *)iph, iph->ihl);

	/* Copy Compressed Payload to IP Packet */
	out_buffer_cpy((void *)ipcomph + sizeof(struct ip_comp_hdr),
			info.out_data, info.out_size);

	delta = info.in_size - info.out_size;
	skb_trim(skb, skb->len - delta + sizeof(struct ip_comp_hdr));
	printk("%s: in_size=%lu, out_size=%lu\n", __FUNCTION__, info.in_size, info.out_size);
out:
	out_buffer_free_all(&out_data);
	return ret;
}

unsigned int skb_decompress(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct ip_comp_hdr *ipcomph;
	unsigned char nexthdr;
	size_t iphlen, delta;

	struct compress_info info;
	struct out_buffer out_data;

	int err = 0;
	unsigned int ret = NF_ACCEPT;
	out_buffer_init(&out_data);

	/* Filter Packet */
	if (!skb)
		goto out;
	skb_linearize(skb);
	iph = ip_hdr(skb);
	if (iph->version == 6)
		goto out;
	nexthdr = iph->protocol;
	if (nexthdr != IPPROTO_COMP)
		goto out;
	if (ntohs(iph->frag_off) & ~IP_DF)
		goto out;

	/* Decompress IP Payload */

	iphlen = iph->ihl << 2;
	info.in_size = ntohs(iph->tot_len) - iphlen - sizeof(struct ip_comp_hdr);
	info.in_data = (void *)iph + iphlen + sizeof(struct ip_comp_hdr);
	info.out_data = &out_data;

	err = compress_ops[0]->decompress(&info);

	if (err) {
		printk("%s: skb decompress error\n", __FUNCTION__);
		ret = NF_DROP;
		goto out;
	}

	/* expand skb for uncompressed payload */
	delta = info.out_size - info.in_size;
	if (delta > sizeof(struct ip_comp_hdr) + skb_tailroom(skb)) {
		err = pskb_expand_head(skb, 0,
				delta - sizeof(struct ip_comp_hdr) - skb_tailroom(skb),
				GFP_ATOMIC);
		if (err) {
			printk("%s: skb expand error\n", __FUNCTION__);
			ret = NF_DROP;
			goto out;
		}
	}
	skb_put(skb, delta - sizeof(struct ip_comp_hdr));

	/* Update IP Header */
	ipcomph = ipcomp_hdr(skb);
	iph->tot_len = htons(iphlen + info.out_size);
	iph->protocol = ipcomph->nexthdr;
	iph->check = 0;
	iph->check = ip_fast_csum((void*)iph, iph->ihl);

	/* Copy Decompressed Payload to IP Packet */
	out_buffer_cpy((void *)ipcomph,
			info.out_data, info.out_size);
	printk("%s: in_size=%lu, out_size=%lu\n", __FUNCTION__, info.in_size, info.out_size);
out:
	out_buffer_free_all(&out_data);
	return ret;
}

static struct nf_hook_ops nf_compress_hook = {
	.hook		= compress_hf,
	.pf			= PF_INET,
	.hooknum	= NF_IP_LOCAL_OUT,
	.priority	= NF_IP_PRI_FIRST,
}, nf_decompress_hook = {
	.hook		= decompress_hf,
	.pf			= PF_INET,
	.hooknum	= NF_IP_LOCAL_IN,
	.priority	= NF_IP_PRI_FIRST,
};


static int __init nf_ipcomp_init(void)
{
	int err = 0;
	err = out_buffer_cache_create();
	if (err) goto out;
	err = zlib_workspace_cache_create();
	if (err) goto out1;
	err = nf_register_hook(&nf_compress_hook);
	if (err) goto out2;
	err = nf_register_hook(&nf_decompress_hook);
	if (err) goto out3;
	return 0;
out3:
	nf_unregister_hook(&nf_compress_hook);
out2:
	zlib_workspace_cache_destroy();
out1:
	out_buffer_cache_destroy();
out:
	return err;
}

static void __exit nf_ipcomp_exit(void)
{
	nf_unregister_hook(&nf_compress_hook);
	nf_unregister_hook(&nf_decompress_hook);
	zlib_workspace_cache_destroy();
	out_buffer_cache_destroy();
}


MODULE_DESCRIPTION("Netfilter Hook for IPCOMP");
MODULE_AUTHOR("Weihong Xu <xuweihong.cn@gmail.com>");
MODULE_LICENSE("GPL");

module_init(nf_ipcomp_init);
module_exit(nf_ipcomp_exit);
