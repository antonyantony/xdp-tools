#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#include <linux/ipv6.h>
#include <linux/netfilter.h>

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

struct net_device {
	int ifindex;
};

struct xdp_cpumap_stats {
	unsigned int redirect;
	unsigned int pass;
	unsigned int drop;
};

struct bpf_prog {
};

struct bpf_map {
};

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

struct net;

typedef struct {
	struct net *net;
} possible_net_t;

typedef struct {
	int counter;
} atomic_t;

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

typedef struct {} arch_spinlock_t;

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};

typedef struct spinlock spinlock_t;

typedef unsigned int __u32;

typedef __u32 u32;

typedef __u32 __be32;

typedef unsigned char __u8;

typedef short unsigned int __u16;

typedef __u16 __be16;

typedef union {
	__be32 a4;
	__be32 a6[4];
	struct in6_addr in6;
} xfrm_address_t;

struct xfrm_id {
	xfrm_address_t daddr;
	__be32 spi;
	__u8 proto;
};

typedef unsigned int __kernel_uid32_t;

struct xfrm_selector {
	xfrm_address_t daddr;
	xfrm_address_t saddr;
	__be16 dport;
	__be16 dport_mask;
	__be16 sport;
	__be16 sport_mask;
	__u16 family;
	__u8 prefixlen_d;
	__u8 prefixlen_s;
	__u8 proto;
	int ifindex;
	__kernel_uid32_t user;
};

struct xfrm_mark {
	__u32 v;
	__u32 m;
};

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

typedef __u8 u8;

struct xfrm_address_filter;

struct xfrm_state_walk {
	struct list_head all;
	u8 state;
	u8 dying;
	u8 proto;
	u32 seq;
	struct xfrm_address_filter *filter;
};

typedef __u16 u16;

typedef long long unsigned int __u64;

struct xfrm_lifetime_cfg {
	__u64 soft_byte_limit;
	__u64 hard_byte_limit;
	__u64 soft_packet_limit;
	__u64 hard_packet_limit;
	__u64 soft_add_expires_seconds;
	__u64 hard_add_expires_seconds;
	__u64 soft_use_expires_seconds;
	__u64 hard_use_expires_seconds;
};

typedef long long int __s64;

typedef __s64 time64_t;

struct xfrm_replay_state {
	__u32 oseq;
	__u32 seq;
	__u32 bitmap;
};

enum xfrm_replay_mode {
	XFRM_REPLAY_MODE_LEGACY = 0,
	XFRM_REPLAY_MODE_BMP = 1,
	XFRM_REPLAY_MODE_ESN = 2,
};

struct timer_list {
	struct hlist_node entry;
	long unsigned int expires;
	void (*function)(struct timer_list *);
	u32 flags;
};

struct xfrm_stats {
	__u32 replay_window;
	__u32 replay;
	__u32 integrity_failed;
};

struct xfrm_lifetime_cur {
	__u64 bytes;
	__u64 packets;
	__u64 add_time;
	__u64 use_time;
};

struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

typedef __s64 s64;

typedef s64 ktime_t;

struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

struct hrtimer_clock_base;

struct hrtimer {
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
};

typedef struct {} netdevice_tracker;

struct net_device;

struct xfrm_dev_offload {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct net_device *real_dev;
	long unsigned int offload_handle;
	u8 dir: 2;
	u8 type: 2;
	u8 flags: 2;
};

struct page;

struct page_frag {
	struct page *page;
	__u32 offset;
	__u32 size;
};

struct xfrm_mode {
	u8 encap;
	u8 family;
	u8 flags;
};

struct xfrm_algo_auth;

struct xfrm_algo;

struct xfrm_algo_aead;

struct xfrm_encap_tmpl;

struct sock;

struct xfrm_replay_state_esn;

struct xfrm_type;

struct xfrm_type_offload;

struct xfrm_sec_ctx;

struct xfrm_state {
	possible_net_t xs_net;
	union {
		struct hlist_node gclist;
		struct hlist_node bydst;
	};
	union {
		struct hlist_node dev_gclist;
		struct hlist_node bysrc;
	};
	struct hlist_node byspi;
	struct hlist_node byseq;
	struct hlist_node state_cache;
	struct hlist_node state_cache_input;
	refcount_t refcnt;
	spinlock_t lock;
	u32 pcpu_num;
	struct xfrm_id id;
	struct xfrm_selector sel;
	struct xfrm_mark mark;
	u32 if_id;
	u32 tfcpad;
	u32 genid;
	struct xfrm_state_walk km;
	struct {
		u32 reqid;
		u8 mode;
		u8 replay_window;
		u8 aalgo;
		u8 ealgo;
		u8 calgo;
		u8 flags;
		u16 family;
		xfrm_address_t saddr;
		int header_len;
		int trailer_len;
		u32 extra_flags;
		struct xfrm_mark smark;
	} props;
	struct xfrm_lifetime_cfg lft;
	struct xfrm_algo_auth *aalg;
	struct xfrm_algo *ealg;
	struct xfrm_algo *calg;
	struct xfrm_algo_aead *aead;
	const char *geniv;
	__be16 new_mapping_sport;
	u32 new_mapping;
	u32 mapping_maxage;
	struct xfrm_encap_tmpl *encap;
	struct sock *encap_sk;
	u32 nat_keepalive_interval;
	time64_t nat_keepalive_expiration;
	xfrm_address_t *coaddr;
	struct xfrm_state *tunnel;
	atomic_t tunnel_users;
	struct xfrm_replay_state replay;
	struct xfrm_replay_state_esn *replay_esn;
	struct xfrm_replay_state preplay;
	struct xfrm_replay_state_esn *preplay_esn;
	enum xfrm_replay_mode repl_mode;
	u32 xflags;
	u32 replay_maxage;
	u32 replay_maxdiff;
	struct timer_list rtimer;
	struct xfrm_stats stats;
	struct xfrm_lifetime_cur curlft;
	struct hrtimer mtimer;
	struct xfrm_dev_offload xso;
	long int saved_tmo;
	time64_t lastused;
	struct page_frag xfrag;
	const struct xfrm_type *type;
	struct xfrm_mode inner_mode;
	struct xfrm_mode inner_mode_iaf;
	struct xfrm_mode outer_mode;
	const struct xfrm_type_offload *type_offload;
	struct xfrm_sec_ctx *security;
	void *data;
	u8 dir;
};

typedef int __s32;
typedef __s32 s32;

struct bpf_xfrm_state_opts {
	u8 dir;
	s32 error;
	s32 netns_id;
	u32 mark;
	xfrm_address_t daddr;
	__be32 spi;
	u8 proto;
	u16 family;
};

enum xfrm_sa_dir {
	XFRM_SA_DIR_IN  = 1,
	XFRM_SA_DIR_OUT = 2
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
