/*
 * Copyright 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Niels Provos.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#ifndef _DHT_KADMELIA_
#define _DHT_KADMELIA_

#include <sha1.h>
#include "dht.h"

/* Kadmelia packet format */

struct kad_pkt {
	uint8_t src_id[SHA1_DIGESTSIZE];
	uint8_t dst_id[SHA1_DIGESTSIZE];

	uint8_t rpc_id[SHA1_DIGESTSIZE];
	uint8_t rpc_command;
} __attribute__((__packed__));

struct kad_pkt_find_node {
	uint8_t node_id[SHA1_DIGESTSIZE];
} __attribute__((__packed__));

struct kad_pkt_node_reply {
	uint8_t address[4];
	uint16_t port;
	uint8_t node_id[SHA1_DIGESTSIZE];
} __attribute__((__packed__));

#define DHT_KAD_RPC_PING	0x0001
#define DHT_KAD_RPC_FIND_NODE	0x0002
#define DHT_KAD_RPC_FIND_VALUE	0x0003
#define DHT_KAD_RPC_STORE	0x0004

#define DHT_KAD_REPLY(x)	(0x80 | (x))

/* Kadmelia internal data structures */

#define KAD_ALPHA			3	/* parallel lookups */
#define KAD_NODES_PER_BUCKET		20	/* nodes per bucket */
#define KAD_NODE_ID_RETRY		5
#define KAD_NODE_ID_TIMEOUT		60
#define KAD_MAX_PAYLOAD_LEN		1200
#define KAD_BUCKET_REFRESH_INTERVAL	3600	/* once an hour */
#define KAD_BUCKET_REFRESH_CHECK	60	/* less frequent? */

struct kad_bucket;

struct kad_node_id {
	TAILQ_ENTRY(kad_node_id) next;
	SPLAY_ENTRY(kad_node_id) node;
	SPLAY_ENTRY(kad_node_id) diff_node;

	struct addr addr;
	uint16_t port;
	
	u_char id[SHA1_DIGESTSIZE];
	u_char *diff;			/* Allows us to use a diff tree */

#define KAD_NODE_ID_DEAD	0x0001
#define KAD_NODE_SENT_RPC	0x0002	/* Send RPC to this node */
#define KAD_NODE_GOT_REPLY	0x0004  /* Got an RPC reply from this node */
#define KAD_NODE_GOT_VALUE	0x0008
	uint16_t flags;
	uint16_t timeout_retry;

	struct kad_bucket *parent;
};

TAILQ_HEAD(kad_nodeidq, kad_node_id);
SPLAY_HEAD(kad_nodeidtree, kad_node_id);
SPLAY_HEAD(kad_diffidtree, kad_node_id);

struct kad_bucket {
	int level;

	struct kad_bucket *parent;
	struct kad_bucket *child_one;
	struct kad_bucket *child_zero;

	struct kad_nodeidq nodes;
	struct kad_nodeidtree node_head;
	int num_nodes;
	int num_subtree_nodes;

	time_t last_refresh;		/* records the time of last refresh */
	int num_rpcs;			/* outstanding rpcs on this one */
};

struct dht_node;

struct kad_node {
	struct kad_node_id myself;

	struct kad_bucket *bucket_root;

	struct dht_storage *storage;	/* key value storage */
	struct dht_node *dht;		/* generic DHT handler */
	struct dht_rpcs rpcs;		/* outstanding rpcs */

#define KAD_NODE_JOINED		0x0001
	int flags;

	struct event ev_refresh;	/* refresh events */
};

/* External implementation interface data structures */

struct kad_ctx_store {
	struct kad_node *node;
	struct kad_node_id id;

	u_char keyid[SHA1_DIGESTSIZE];
	u_char *val;
	size_t vallen;

	int num_rpcs;
	int num_fails;

	void (*cb)(int, void *);
	void *cb_arg;
};

struct kad_ctx_join {
	struct kad_node *node;
	struct kad_node_id id;

	void (*cb)(int, void *);
	void *cb_arg;

	int num_retry;
};

struct kad_ctx_bucket_refresh {
	struct kad_bucket *bucket;
	struct kad_node *node;

	void (*cb)(void *);
	void *cb_arg;
};

/* Context for refreshing all buckets */

struct kad_ctx_refresh {
	struct kad_node *parent;

	int num_rpcs;
	void (*cb)(void *);
	void *cb_arg;
};


/* Context for a node lookup */

struct kad_ctx_lookup {
	u_char search_id[SHA1_DIGESTSIZE];

	struct kad_node *parent;

	struct kad_nodeidq nodes;
	struct kad_nodeidtree node_head;	/* finding presence */
	struct kad_diffidtree diff_head;	/* finding closest */

	int num_rpcs;				/* outstanding rpcs */

	int flags;
#define KAD_CTX_LOOKUP_FIND_VALUE	0x0001	/* want to find value */
#define KAD_CTX_LOOKUP_GOT_VALUE	0x0002  /* got a response */

	void (*cb)(struct kad_nodeidq *, void *);
	void *cb_arg;

	/* Used if this is a find value lookup */
	void (*cb_find)(u_char *data, size_t, void *);
	void *cb_find_arg;

	u_char *val;
	size_t vallen;
};



/* Prototypes */

/* Returns a DHT node that uses Kademlia as DHT protocol */
struct dht_node *	kad_make_dht(uint16_t port);

struct kad_node_id *	kad_node_id_new(struct addr *addr,
			    u_short port, u_char *id);
void			kad_node_id_free(struct kad_node_id *id);
struct kad_node_id *	kad_node_id_find(struct kad_node *node, u_char *id);

struct kad_bucket *	kad_bucket_new(struct kad_bucket *bucket);
void			kad_bucket_node_remove(struct kad_bucket *bucket,
			    struct kad_node_id *id);
void			kad_bucket_node_insert(struct kad_bucket *bucket,
			    struct kad_node_id *id);
void			kad_bucket_split(struct kad_bucket *bucket,
			    u_char *id);
void			kad_bucket_random_id(struct kad_bucket *bucket,
			    u_char *dst);

struct kad_bucket *	kad_node_find_bucket(struct kad_node *node,
			    u_char *diff);
int			kad_node_refresh_all_buckets(struct kad_node *node,
			    struct kad_bucket *where,
			    void (*cb)(void *), void *cb_arg);
int			kad_node_bucket_refresh(struct kad_node *node,
			    struct kad_bucket *bucket, 
			    void (*cb)(void *), void *cb_arg);
int			kad_node_lookup(struct kad_nodeidq *nodes,
			    struct kad_node *node, u_char *search_id,
			    int threshold) ;
struct kad_node *	kad_node_new(struct dht_node *dht);
int			kad_node_set_address(struct kad_node *node,
			    char *host, uint16_t port);

int			kad_node_insert(struct kad_node *node,
			    struct addr *addr, uint16_t port, u_char *id);

void			kad_read_cb(struct addr *, uint16_t, u_char *,
			    size_t, void *);
void			kad_rpc_handle_find_node(struct kad_node *node,
			    struct addr *addr, uint16_t,
			    struct kad_pkt *hdr, size_t datlen);

int			kad_send_rpc(struct kad_node *node,
			    struct kad_node_id *id,
			    uint8_t command, u_char *rpc_id,
			    u_char *payload, size_t payload_len,
			    void (*cb)(struct dht_rpc *,
				struct evbuffer *, void *),
			    void *cb_arg);

/* Implementation commands */
int			kad_impl_lookup(struct kad_node *node,
			    u_char *search_id,
			    void (*cb)(struct kad_nodeidq *, void *),
			    void *cb_arg);

int			kad_impl_join(void *node_data,
			    struct addr *addr, u_short port,
			    void (*cb)(int, void *), void *cb_arg);

int			kad_impl_store(struct kad_node *node,
			    u_char *keyid, u_char *value, size_t vallen,
			    void (*cb)(int, void *), void *cb_arg);
int			kad_impl_find_value(struct kad_node *node,
			    u_char *keyid,
			    void (*cb)(u_char *, size_t, void *),
			    void *cb_arg);

/* RPC commands */

int			kad_rpc_ping(struct kad_node *node,
			    struct kad_node_id *nod_id,
			    void (*cb)(struct dht_rpc *,
				struct evbuffer *, void *),
			    void *cb_arg);
int			kad_rpc_find_node(struct kad_node *node,
			    struct kad_node_id *id, u_char *node_id,
			    void (*cb)(struct dht_rpc *,
				struct evbuffer *, void *),
			    void *cb_arg);
int			kad_rpc_find_value(struct kad_node *node,
			    struct kad_node_id *id, u_char *node_id,
			    void (*cb)(struct dht_rpc *,
				struct evbuffer *, void *),
			    void *cb_arg);
int			kad_rpc_store(struct kad_node *node,
			    struct kad_node_id *id,
			    u_char *node_id, u_char *value, size_t vallen,
			    void (*cb)(struct dht_rpc *,
				struct evbuffer *, void *),
			    void *cb_arg);
#endif /* _DHT_KADMELIA_ */
