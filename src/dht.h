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

#ifndef _DHT_H_
#define _DHT_H_

#include <sha1.h>

#ifdef DEBUG
#define DFPRINTF(x, y) do { \
	extern int debug; \
	if (debug >= x) fprintf y; \
} while (0)
#else
#define DFPRINTF(x, y)
#endif

#ifndef __GNUC__
# define __attribute__(x)
# pragma pack(1)
#endif

/* Some stupid data structures */
struct dht_node_id {
	u_char id[SHA1_DIGESTSIZE];
	struct addr addr;
	uint16_t port;
};

typedef void (*dht_readcb)(struct addr *srcip, uint16_t port,
    u_char *data, size_t data_len, void *arg);

/*
 * Callbacks that a DHT implementation needs to provide
 *
 * node_data refers to the internal data structure of the DHT implementation.
 */

struct dht_callbacks {
	/*
	 * Callback for received data.
	 */
	dht_readcb read;

	/*
	 * Join the DHT network given one known IP:port pair.
	 */
	int (*join)(void *node_data, struct addr *dst, uint16_t port,
	    void (*cb)(int, void *arg), void *cb_arg);

	/* 
	 * Find the node ids in the internal data structure that are closest
	 * to the id argument.  If the id argument is not of the same size as
	 * the DHT id size, it is going to be hashed to the right size.
	 */
	int (*lookup)(void *node_data, u_char *id, size_t idlen,
	    struct dht_node_id **ids, size_t *numids);

	u_char *(*myid)(void *node_data);

	int (*find_id)(void *node_data, u_char *id, size_t idlen,
	    struct dht_node_id *pid);

	/* A ping - no callback but helps with expiring dead nodes */
	int (*ping)(void *node_data, u_char *id);

	int (*store)(void *node_data, u_char *keyid, size_t keylen,
	    u_char *value, size_t vallen,
	    void (*cb)(int, void *), void *cb_arg);

	int (*find)(void *node_data, u_char *keyid, size_t keylen,
	    void (*cb)(u_char *, size_t, void *), void *cb_arg);
};

/* Protocol formats */

struct dht_pkthdr {
	uint16_t version;	/* protocol version */
	uint16_t type;		/* packet type */
	uint8_t signature[SHA1_DIGESTSIZE];
} __attribute__((__packed__));

#define DHT_VERSION		0x0100	/* major 1 minor 0 */
#define DHT_TYPE_ZLIB		0x0001	/* data is compressed */
#define DHT_TYPE_KADEMLIA	0x0002  /* Kadmelia DHT */
#define DHT_TYPE_GROUP		0x0100  /* Group communication protocol */

/* A single outstanding RPC */

#define DHT_RPC_TIMEOUT		5

struct dht_rpcs;
struct kad_node;
struct dht_group;
struct dht_rpc {
	SPLAY_ENTRY(dht_rpc) node;

	uint8_t rpc_id[SHA1_DIGESTSIZE];
	uint8_t rpc_dst[SHA1_DIGESTSIZE];	/* for penalizing on timeout */
	uint8_t rpc_command;

	struct dht_rpcs *rpc_root;		/* remember root of tree */

	union {
		void *node;
		struct kad_node *kad_node;
		struct dht_group *group_node;
	} parent;

	struct event ev_cb;

	/* Callback containing reply */
	void (*cb)(struct dht_rpc *rpc, void *data, void *arg);
	void *cb_arg;
};


/* Keeps track of outstanding RPCs */

struct dht_rpcs {
	SPLAY_HEAD(dht_rpctree, dht_rpc) rpcs;

	void (*cb_timeout)(struct dht_rpc *);
};

int rpc_id_compare(struct dht_rpc *, struct dht_rpc *);
SPLAY_PROTOTYPE(dht_rpctree, dht_rpc, node, rpc_id_compare);

/* DHT internal data structures */
struct dht_message {
	TAILQ_ENTRY(dht_message) next;

	struct addr dst;
	uint16_t port;
	uint16_t type;

	u_char *data;
	size_t datlen;
};

/* Track which application layer protocols have registered callbacks */
struct dht_type_callback {
	SPLAY_ENTRY(dht_type_callback) node;

	uint16_t type;

	dht_readcb cb;
	void *cb_arg;
};

struct dht_node {
	int fd;			/* our bound socket */

	struct event ev_read;
	struct event ev_write;

	uint16_t dht_type;	/* the type of DHT we are running */

	/* The implementation of our DHT */
	const struct dht_callbacks *impl_cbs;
	void *impl_arg;

	/* A hook for validating stores */
	int (*store_cb)(u_char *key, size_t keylen, u_char *val, size_t vallen,
	    void *cb_arg);
	void *store_cb_arg;

	/* Application specific read callbacks for all possible protocols */
	SPLAY_HEAD(dht_readcb_tree, dht_type_callback) read_cbs;

	/* Messages we are waiting for to be sent */
	TAILQ_HEAD(messageq, dht_message) messages;
};

void			dht_init();

struct dht_node *	dht_new(uint16_t port);
void			dht_set_impl(struct dht_node *, uint16_t type,
			    const struct dht_callbacks *impl_cbs,
			    void *impl_arg);

char *			dht_node_id_ascii(u_char *id);
void			dht_compress(struct evbuffer *evbuf);
int			dht_decompress(struct evbuffer *evbuf);

/* RPC related functions */

void			dht_rpc_remove(struct dht_rpcs *rpcs,
			    struct dht_rpc *rpc);
struct dht_rpc *	dht_rpc_find(struct dht_rpcs *rpcs, u_char *id);
struct dht_rpc *	dht_rpc_new(struct dht_rpcs *rpcs, void *node,
			    u_char *dst_id, uint8_t command,
			    void (*cb)(struct dht_rpc *, void *, void *),
			    void *cb_arg);
void			dht_rpc_delay_callback(struct evbuffer *evbuf,
			    void (*cb)(struct dht_rpc *, void *, void *),
			    void *cb_arg);

/* Registers an application type read callback */
int			dht_register_type(struct dht_node *node,
			    uint16_t type, dht_readcb readcb, void *cb_arg);
struct dht_type_callback *dht_find_type(struct dht_node *node, uint16_t type);

int			dht_send(struct dht_node *node, uint16_t type,
			    struct addr *dst, uint16_t port,
			    u_char *data, size_t datlen);

/* Implementation shims */
int			dht_join(struct dht_node *node,
			    struct addr *dst, uint16_t port,
			    void (*cb)(int, void *arg), void *cb_arg);
int			dht_lookup(struct dht_node *node,
			    u_char *id, size_t idlen,
			    struct dht_node_id **ids, size_t *numids);
int			dht_find_id(struct dht_node *node,
			    u_char *id, size_t idlen,
			    struct dht_node_id *pid);
int			dht_ping(struct dht_node *node, u_char *id);
u_char *		dht_myid(struct dht_node *node);

#endif /* _DHT_H_ */
