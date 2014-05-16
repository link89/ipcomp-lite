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

#include <asm/uaccess.h>
#include <asm/checksum.h>

#include "ipcomp.h"


static unsigned int compress_hf(const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	skb_compress(skb);
	return NF_ACCEPT;
}

static unsigned int decompress_hf(const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	skb_decompress(skb);
	return NF_ACCEPT;
}

int skb_compress(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct ip_comp_hdr *ipcomph;
	unsigned char nexthdr;
	unsigned int iphlen, pyldsz, cpyldsz;
	unsigned char *buffer;
	void *workspace;
	z_stream zs;
	int error = 0;

	if (!skb) {
		error = -EINVAL;
		goto out;
	}
	skb_linearize(skb);
	iph = ip_hdr(skb);
	if (iph->version == 6) {
		error = -EPROTONOSUPPORT;
		goto out;
	}

	nexthdr = iph->protocol;
	if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP) {
		error = -EPROTONOSUPPORT;
		goto out;
	}

	if (iph->frag_off & __constant_htons(IP_MF | IP_OFFSET)) {
		error = -EPROTONOSUPPORT;
		goto out;
	}

	iphlen = iph->ihl << 2;
	pyldsz = ntohs(iph->tot_len) - iphlen;
	cpyldsz = pyldsz;

	/* Compress IP Payload */
	workspace = kmalloc(zlib_deflate_workspacesize(
			-MAX_WBITS, MAX_MEM_LEVEL),
			GFP_ATOMIC);
	if (IS_ERR_OR_NULL(workspace)) {
		error = -ENOMEM;
		goto out;
	}
	zs.workspace = workspace;

	error = zlib_deflateInit2(&zs, Z_DEFAULT_COMPRESSION,
						Z_DEFLATED, -15, DEF_MEM_LEVEL,
						Z_DEFAULT_STRATEGY);
	if (Z_OK != error) {
		error = -EPERM;
		goto out1;
	}

	buffer = (char *) kmalloc(cpyldsz, GFP_ATOMIC);
	if (IS_ERR_OR_NULL(buffer)) {
		zlib_deflateEnd(&zs);
		error = -ENOMEM;
		goto out1;
	}

	zs.total_in = 0;
	zs.total_out = 0;
	zs.next_in = (char *) iph + iphlen;
	zs.next_out = buffer;
	zs.avail_in = pyldsz;
	zs.avail_out = cpyldsz;

	error = zlib_deflate(&zs, Z_FINISH);
	zlib_deflateEnd(&zs);
	if (error != Z_STREAM_END) {
		error = -EPERM;
		goto out2;
	}

	cpyldsz -= zs.avail_out;
	if (cpyldsz + sizeof(struct ip_comp_hdr) >= pyldsz) {
		error = -EPERM;
		goto out2;
	}

	/* Insert IPCOMP Header */
	ipcomph = ipcomp_hdr(skb);
	ipcomph->nexthdr = nexthdr;
	ipcomph->flags = 0;
	ipcomph->cpi = htons((__be16) 0x00000000);

	/* Update IP Header */
	iph->protocol = IPPROTO_COMP;
	iph->tot_len = htons(iphlen + sizeof(struct ip_comp_hdr) + cpyldsz);
	iph->check = 0;
	iph->check = ip_fast_csum((char *) iph, iph->ihl);

	/* Copy Compressed Payload to Packet */
	memcpy((char *) ipcomph + sizeof(struct ip_comp_hdr),
			buffer, cpyldsz);

	skb_trim (skb, skb->len - pyldsz + cpyldsz + sizeof(struct ip_comp_hdr));

out2:
	kfree(buffer);
out1:
	kfree(workspace);
out:
	return error;
}

int skb_decompress(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct ip_comp_hdr *ipcomph;
	unsigned char nexthdr;
	unsigned int iphlen, pyldsz, cpyldsz;
	unsigned char *buffer;
	void *workspace;
	z_stream zs;
	int error;

	if (!skb) {
		error = -EINVAL;
		goto out;
	}
	skb_linearize(skb);
	iph = ip_hdr(skb);
	if (iph->version == 6) {
		error = -EPROTONOSUPPORT;
		goto out;
	}
	nexthdr = iph->protocol;
	if (nexthdr != IPPROTO_COMP) {
		error = 0;
		goto out;
	}

	if (ntohs(iph->frag_off) & ~IP_DF) {
		error = -EPERM;
		goto out;
	}

	iphlen = iph->ihl << 2;
	cpyldsz = ntohs(iph->tot_len) - iphlen - sizeof(struct ip_comp_hdr);
	/* FIXME */
	pyldsz = skb->dev ? (skb->dev->mtu < 16260 ? 16260 : skb->dev->mtu)
			  : (65520 - iphlen);

	workspace = kmalloc(zlib_inflate_workspacesize(), GFP_ATOMIC);

	if (IS_ERR_OR_NULL(workspace)) {
		error = -ENOMEM;
		goto out;
	}
	zs.workspace = workspace;

	error = zlib_inflateInit2(&zs, -MAX_WBITS);
	if (Z_OK != error) {
		error = -EPERM;
		goto out1;
	}

	buffer = (char *) kmalloc(pyldsz, GFP_ATOMIC);
	if (IS_ERR_OR_NULL(buffer)) {
		zlib_inflateEnd(&zs);
		error = -ENOMEM;
		goto out1;
	}

	zs.total_in = 0;
	zs.total_out = 0;
	zs.next_in = (char *) iph + iphlen + sizeof(struct ip_comp_hdr);
	zs.avail_in = cpyldsz;
	zs.next_out = buffer;
	zs.avail_out = pyldsz;

	/* Uncompress Begin */

	error = zlib_inflate(&zs, Z_SYNC_FLUSH);
	/* work around a bug in zlib, which sometimes wants to taste an extra
	 * byte when being used in the (undocumented) raw deflate mode.
	 */
	if (error == Z_OK && !zs.avail_in && zs.avail_out) {
		__u8 zerostuff = 0;
		zs.next_in = &zerostuff;
		zs.avail_in = 1;
		error = zlib_inflate(&zs, Z_FINISH);
	}
	zlib_inflateEnd(&zs);
	if (error != Z_STREAM_END) {
		error = -EPERM;
		goto out2;
	}
	pyldsz -= zs.avail_out;

	/* expand skb for uncompressed payload */
	if (pyldsz - cpyldsz > sizeof(struct ip_comp_hdr) + skb_tailroom(skb)) {
		error = pskb_expand_head(skb, 0,
				pyldsz - cpyldsz - sizeof(struct ip_comp_hdr) - skb_tailroom(skb),
				GFP_ATOMIC);
		if (error) {
			printk("%s: skb expand error\n", __FUNCTION__);
			error = -ENOMEM;
			goto out2;
		}
	}
	skb_put(skb, pyldsz - cpyldsz - sizeof(struct ip_comp_hdr));

	/* Update IP header */
	ipcomph = ipcomp_hdr(skb);
	iph->protocol = ipcomph->nexthdr;
	iph->tot_len = htons(iphlen + pyldsz);
	iph->check = 0;
	iph->check = ip_fast_csum((char*) iph, iph->ihl);

	/* Copy Decompressed Payload to IP Packet */
	memcpy((char *) ipcomph + sizeof(struct ip_comp_hdr),
			buffer, pyldsz);

out2:
	kfree(buffer);
out1:
	kfree(workspace);
out:
	return error;
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
	int error = 0;
	error = nf_register_hook(&nf_compress_hook);
	if (error)
		goto out;
	error = nf_register_hook(&nf_decompress_hook);
	if (error)
		nf_unregister_hook(&nf_compress_hook);
out:
	return error;
}

static void __exit nf_ipcomp_exit(void)
{
	nf_unregister_hook(&nf_compress_hook);
	nf_unregister_hook(&nf_decompress_hook);
}


MODULE_DESCRIPTION("Netfilter Hook for IPCOMP");
MODULE_AUTHOR("Weihong Xu <xuweihong.cn@gmail.com>");
MODULE_LICENSE("GPL");

module_init(nf_ipcomp_init);
module_exit(nf_ipcomp_exit);
