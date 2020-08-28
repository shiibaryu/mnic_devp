#ifndef __NETTLPPKT_H_
#define __NETTLPPKT_H_

#include <asm/byteorder.h>
#include <arpa/inet.h>
#include <linux/types.h>

#define ETH_ALEN  6
#define ETHERTYPE_ARP 	0x0806
#define ETHERTYPE_IP 	0x0800
#define ETHERTYPE_IP6 	0x0806

#define PROTO_ICMP	1
#define PROTO_TCP	6
#define PROTO_UDP	17

#define ETHER_HDR_SIZE	14
#define ARP_HDR_SIZE	28
#define IP_HDR_SIZE	20
#define ICMP_HDR_SIZE	8
#define UDP_HDR_SIZE	8

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;

struct ethhdr{
	u8 dst_addr[ETH_ALEN];
	u8 src_addr[ETH_ALEN];
	u16 ether_type;
}__attribute__((__packed__));

struct arphdr{
	u16 ar_hdr;
	u16 ar_pro;
	u8  ar_hln;
	u8  ar_pln;
	u16 ar_op;

	u8 __ar_sha[ETH_ALEN];
	u8 __ar_sip[4];
	u8 __ar_tha[ETH_ALEN];
	u8 __ar_tip[4];
};

struct ipv4{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	__u8	 ihl:4,
		version:4;
#elif __BYTE_OESWE == __BIG_ENDIAN
	__u8  	version:4,
		ihl:4;
#else
# error "Fix endianness defines"
#endif
	__u8  	tos;
	__be16 	tot_len;
	__be16 	id;
	__be16 	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	struct in_addr src_ip;
	struct in_addr dst_ip;
};	

#define IP_V	(((ipv4)->version & 0x0f) >> 4)
#define IP_HL	((ipv4)->ihl & 0x0f)

struct udp{
	__be16	src_port;
	__be16	dst_port;
	__be16	len;
	__sum16	check;
};

#define ICMP_ECHO_BYTES	8

struct icmpv4{
	__u8	type;
	__u8	code;
	__sum16 checksum;
	union{
		struct{
			__be16	id;
			__be16	sequence;
		}echo;
		__be32	gateway;
		struct{
			__be16	unused;
			__be16	mtu;
		}frag;
	}message;
};

struct tcp{
	__u16   source;
	__u16   dest;
	__u32   seq;
	__u32   ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16   res1:4,
	   	doff:4,
      		fin:1,
      		syn:1,
      		rst:1,
 	        psh:1,
      		ack:1,
      		urg:1,
     	 	ece:1,
      		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16   doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,	
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif  
	__u16   window;
	__u16   check;
	__u16   urg_ptr;
};

union tcp_word_hdr{
	struct tcp hdr;
	__be32	words[5];
};

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3])




#endif
