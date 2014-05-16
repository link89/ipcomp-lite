/*
 * IPCOMP zlib interface code.
 * Copyright (C) 2000  Svenning Soerensen <svenning@post5.tele.dk>
 * Copyright (C) 2000, 2001  Richard Guy Briggs <rgb@conscoop.ottawa.on.ca>
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
 */

#ifndef _IPCOMP_H
#define _IPCOMP_H

/* IP Hooks */
/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD		2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING	4
#define NF_IP_NUMHOOKS		5

static inline struct ip_comp_hdr *ipcomp_hdr(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	return (struct ip_comp_hdr *) ((char*) iph + (iph->ihl << 2));
}

/* Function prototypes */
static unsigned int compress_hf(const struct nf_hook_ops *,
			struct sk_buff *,
			const struct net_device *,
			const struct net_device *,
			int (*)(struct sk_buff *));
static unsigned int decompress_hf(const struct nf_hook_ops *,
			struct sk_buff *,
			const struct net_device *,
			const struct net_device *,
			int (*)(struct sk_buff *));
int skb_compress(struct sk_buff *);
int skb_decompress(struct sk_buff *);

#endif /* _IPCOMP_H */
