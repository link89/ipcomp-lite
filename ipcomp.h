#ifndef _IPCOMP_H
#define _IPCOMP_H

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>


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

#define MAX_IP_PAYLOAD 65535
#define PER_BUFFER_SIZE (1 << 12)
#define MAX_BUFFER_NUM ((MAX_IP_PAYLOAD + 1) >> 12)
#define IPCOMP_HEADER_SIZE sizeof(struct ip_comp_hdr)

static inline struct ip_comp_hdr *ipcomp_hdr(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	return (struct ip_comp_hdr *) ((void*)iph + (iph->ihl << 2));
}

/* Helper data structures and functions */
struct compress_info {
	size_t in_size;
	const void *in_data;
	size_t out_size;
	struct out_buffer *out_data;
};

struct compress_ops {
	int (*compress)(struct compress_info *);
	int (*decompress)(struct compress_info *);
};


struct out_buffer {
	unsigned int next_buf;
	void *buffer[MAX_BUFFER_NUM];
};

int out_buffer_cache_create(void);
void out_buffer_cache_destroy(void);
void* out_buffer_alloc(void);
void out_buffer_init(struct out_buffer *);
int out_buffer_add(struct out_buffer *, void *);
void out_buffer_free(void *);
void out_buffer_free_all(struct out_buffer *);
void* out_buffer_cpy(void *, struct out_buffer *, size_t);

/* External Compress Operations */
extern struct compress_ops zlib_compress_ops;

/* Function Prototypes */
//static unsigned int compress_hf(const struct nf_hook_ops *,
//			struct sk_buff *,
//			const struct net_device *,
//			const struct net_device *,
//			int (*)(struct sk_buff *));
//static unsigned int decompress_hf(const struct nf_hook_ops *,
//			struct sk_buff *,
//			const struct net_device *,
//			const struct net_device *,
//			int (*)(struct sk_buff *));

unsigned int skb_compress(struct sk_buff *);
unsigned int skb_decompress(struct sk_buff *);

#endif
