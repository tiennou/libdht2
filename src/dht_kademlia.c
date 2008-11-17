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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/time.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

#include <event.h>
#include <dnet.h>

#include "dht.h"
#include "dht_bits.h"
#include "dht_kademlia.h"
#include "dht_storage.h"

/* Prototypes */
int kad_dht_impl_lookup(void *node_data, u_char *id, size_t idlen,
    struct dht_node_id **ids, size_t *numids);
u_char *kad_dht_impl_myid(void *node_data);
int kad_dht_impl_find_id(void *node_data, u_char *id, size_t idlen,
    struct dht_node_id *pid);
int kad_dht_impl_ping(void *node_data, u_char *id);
int kad_dht_impl_store(void *node_data, u_char *keyid, size_t keylen,
    u_char *value, size_t vallen, void (*cb)(int, void *), void *cb_arg);
int kad_dht_impl_find(void *node_data, u_char *keyid, size_t keylen,
    void (*cb)(u_char *, size_t, void *), void *cb_arg);

void kad_collect_ids_with_diff(struct kad_nodeidtree *collect,
    struct kad_bucket *where, u_char *diff);
void kad_rpc_timeout(struct dht_rpc *rpc);
void kad_rpc_handle_find_node(struct kad_node *node, struct addr *addr,
    uint16_t port, struct kad_pkt *hdr, size_t datlen);
void kad_rpc_handle_find_value(struct kad_node *node, struct addr *addr,
    uint16_t port, struct kad_pkt *hdr, size_t datlen);
void kad_rpc_handle_store(struct kad_node *node, struct addr *addr,
    uint16_t port, struct kad_pkt *hdr, size_t datlen);
static int kad_impl_lookup_internal(struct kad_node *node,
    struct kad_ctx_lookup *ctx);
static void kad_key_refresh(struct dht_keyvalue *kv, void *arg);
static void kad_nodeidq_to_dht_nodeids(struct dht_node_id **pids,
    size_t *pnumids, struct kad_nodeidq *nodes, int num_nodes);

/* Globals */
struct dht_callbacks kad_dht_callbacks = {
	kad_read_cb,
	kad_impl_join,
	kad_dht_impl_lookup,
	kad_dht_impl_myid,
	kad_dht_impl_find_id,
	kad_dht_impl_ping,
	kad_dht_impl_store,
	kad_dht_impl_find
};

int
node_id_compare(struct kad_node_id *a, struct kad_node_id *b)
{
	return (dht_kademlia_compare(a->id, b->id));
}

SPLAY_PROTOTYPE(kad_nodeidtree, kad_node_id, node, node_id_compare);
SPLAY_GENERATE(kad_nodeidtree, kad_node_id, node, node_id_compare);

int
node_id_diff_compare(struct kad_node_id *a, struct kad_node_id *b)
{
	u_char diff[2][SHA_DIGEST_LENGTH];

	assert(a->diff != NULL);
	assert(b->diff != NULL);

	dht_kademlia_xor(diff[0], a->id, a->diff);
	dht_kademlia_xor(diff[1], b->id, b->diff);

	return (dht_kademlia_compare(diff[0], diff[1]));
}

SPLAY_PROTOTYPE(kad_diffidtree, kad_node_id, diff_node, node_id_diff_compare);
SPLAY_GENERATE(kad_diffidtree, kad_node_id, diff_node, node_id_diff_compare);

static rand_t *kad_rand;		/* portable source of randomness */

static void
rand_init(void) {
	if (kad_rand != NULL)
		return;

	if ((kad_rand = rand_open()) == NULL)
		err(1, "rand_open");
}

/*
 * Called to mark a node as dead
 */

void
kad_node_id_timeout(struct kad_node_id *id)
{
	if (++id->timeout_retry >= KAD_NODE_ID_RETRY) {
		/* 
		 * This ID can be garbage collected next time we come around.
		 */
		id->flags |= KAD_NODE_ID_DEAD;

		DFPRINTF(2, (stderr, "%s: marked %s as dead\n",
			     __func__, dht_node_id_ascii(id->id)));
	}
}

void
kad_node_id_free(struct kad_node_id *id)
{
	if (id->parent != NULL) 
		kad_bucket_node_remove(id->parent, id);

	free(id);
}

struct kad_node_id *
kad_node_id_find(struct kad_node *node, u_char *id)
{
	u_char *diff = dht_kademlia_distance(node->myself.id, id);
	struct kad_bucket *where = kad_node_find_bucket(node, diff);
	struct kad_node_id tmp;

	memcpy(tmp.id, id, sizeof(tmp.id));
	return (SPLAY_FIND(kad_nodeidtree, &where->node_head, &tmp));
}

struct kad_node_id *
kad_node_id_new(struct addr *addr, u_short port, u_char *id)
{
	struct kad_node_id *tmp = calloc(1, sizeof(struct kad_node_id));
	if (tmp == NULL)
		return (NULL);

	memcpy(tmp->id, id, sizeof(tmp->id));
	tmp->addr = *addr;
	tmp->port = port;

	return (tmp);
}

void
kad_node_id_refresh(struct kad_bucket *bucket, struct kad_node_id *id)
{
	TAILQ_REMOVE(&bucket->nodes, id, next);
	TAILQ_INSERT_TAIL(&bucket->nodes, id, next);

	id->timeout_retry = 0;
	id->flags &= ~KAD_NODE_ID_DEAD;
}

struct kad_bucket *
kad_bucket_new(struct kad_bucket *bucket)
{
	struct kad_bucket *tmp = calloc(1, sizeof(struct kad_bucket));

	if (tmp == NULL)
		return (NULL);

	TAILQ_INIT(&tmp->nodes);

	if (bucket != NULL) {
		tmp->level = bucket->level + 1;
		tmp->parent = bucket;
	}

	return (tmp);
}

void
kad_bucket_node_remove(struct kad_bucket *bucket, struct kad_node_id *id)
{
	id->parent = NULL;

	TAILQ_REMOVE(&bucket->nodes, id, next);
	SPLAY_REMOVE(kad_nodeidtree, &bucket->node_head, id);
	bucket->num_nodes--;
}

void
kad_bucket_node_insert(struct kad_bucket *bucket, struct kad_node_id *id)
{
	id->parent = bucket;

	TAILQ_INSERT_TAIL(&bucket->nodes, id, next);
	SPLAY_INSERT(kad_nodeidtree, &bucket->node_head, id);
	bucket->num_nodes++;
	bucket->num_subtree_nodes++;
}

void
kad_bucket_split(struct kad_bucket *bucket, u_char *id)
{
	struct kad_node_id *tmp;
	int level = bucket->level;

	assert(bucket->level < SHA_DIGEST_LENGTH*8 - 1);
	assert(bucket->child_one == NULL);
	assert(bucket->child_zero == NULL);

	bucket->child_one = kad_bucket_new(bucket);
	bucket->child_zero = kad_bucket_new(bucket);

	if (bucket->child_one == NULL || bucket->child_zero == NULL)
		err(1, "%s: calloc", __func__);

	bucket->child_one->last_refresh = bucket->last_refresh;
	bucket->child_zero->last_refresh = bucket->last_refresh;

	while ((tmp = TAILQ_FIRST(&bucket->nodes)) != NULL) {
		u_char *diff = dht_kademlia_distance(tmp->id, id);
		struct kad_bucket *where = dht_bit_set(diff, level) ?
		    bucket->child_one : bucket->child_zero;

		kad_bucket_node_remove(bucket, tmp);
		kad_bucket_node_insert(where, tmp);
	}

	/* Fix up the subtree data */
	bucket->child_zero->num_subtree_nodes = bucket->child_zero->num_nodes;
	bucket->child_one->num_subtree_nodes = bucket->child_one->num_nodes;

	assert(bucket->num_nodes == 0);
}

/*
 * Finds the nodes that we know to be close to this ID.
 * Called needs to free the returned node IDs.
 */

int
kad_node_lookup(struct kad_nodeidq *nodes, struct kad_node *node,
    u_char *search_id, int threshold) 
{
	struct kad_node_id *id;
	struct kad_bucket *where;
	struct kad_nodeidtree collect;
	u_char *diff;
	int num_nodes;

	/* Let's try to find the bucket this difference belongs to */
	diff = dht_kademlia_distance(search_id, node->myself.id);
	where = kad_node_find_bucket(node, diff);

	/* Find the subtree that contains enough nodes */
	while (
		where->num_subtree_nodes < threshold &&
		where->parent != NULL )
		where = where->parent;

	/* Collect the IDs that are closest to the node id we search for */
	SPLAY_INIT(&collect);
	kad_collect_ids_with_diff(&collect, where, search_id);

	/* Now, collect the k closest ID into our reply */
	num_nodes = 0;
	while ((id = SPLAY_MIN(kad_nodeidtree, &collect)) != NULL) {
		u_char *real_id;

		SPLAY_REMOVE(kad_nodeidtree, &collect, id);

		real_id = dht_kademlia_distance(id->id, search_id);

		memcpy(id->id, real_id, sizeof(id->id));
		if (id->flags & KAD_NODE_ID_DEAD) {
			/* We do not return dead nodes */
			kad_node_id_free(id);
		} else {
			TAILQ_INSERT_TAIL(nodes, id, next);

			if (++num_nodes >= threshold)
				break;
		}
	}

	while ((id = SPLAY_ROOT(&collect)) != NULL) {
		SPLAY_REMOVE(kad_nodeidtree, &collect, id);
		kad_node_id_free(id);
	}

	return (num_nodes);
}

/*
 * Returns the number of nodes that are closer to the search ID than us.
 */

int
kad_node_num_closer_nodes(struct kad_node *node, u_char *search_id)
{
	struct kad_nodeidq nodes;
	struct kad_node_id *id;
	u_char diff[SHA_DIGEST_LENGTH];
	int node_count = 0;

	TAILQ_INIT(&nodes);

	if (kad_node_lookup(&nodes, node,
		search_id, KAD_NODES_PER_BUCKET) == -1)
		return (-1);

	/* Compute the distance to ourselves */
	dht_kademlia_xor(diff, node->myself.id, search_id);

	TAILQ_FOREACH(id, &nodes, next) {
		u_char *iddiff = dht_kademlia_distance(search_id, id->id);
		/* If our id is closer than we are done */
		if (dht_kademlia_compare(diff, iddiff) < 0)
			break;
		node_count ++;
	}

	while ((id = TAILQ_FIRST(&nodes)) != NULL) {
		TAILQ_REMOVE(&nodes, id, next);
		kad_node_id_free(id);
	}

	return (node_count);
}

/*
 * Finds the bucket with the largest prefix common to the diff id.
 */ 

struct kad_bucket *
kad_node_find_bucket(struct kad_node *node, u_char *diff)
{
	struct kad_bucket *where = node->bucket_root;
	int i, set;

	/* Maybe split this into separate function */
	for (i = 0; i < SHA_DIGEST_LENGTH*8 - 1; ++i) {
		struct kad_bucket *next_bucket;
		assert(where->level == i);

		set = dht_bit_set(diff, i);
		next_bucket =  set ? where->child_one : where->child_zero;
		if (next_bucket == NULL)
			break;

		where = next_bucket;
	}

	return (where);
}

/*
 * Returns a random ID in the range of the current bucket.
 */

void
kad_bucket_random_id(struct kad_bucket *bucket, u_char *dst)
{
	struct kad_node_id *id;
	int i;

	if (kad_rand == NULL)
		rand_init();

	for (i = 0; i < SHA_DIGEST_LENGTH; ++i)
		dst[i] = rand_uint8(kad_rand);

	if (bucket->num_subtree_nodes > 0) {
		while (bucket->child_zero != NULL) {
			if (bucket->child_zero->num_subtree_nodes > 0)
				bucket = bucket->child_zero;
			else
				bucket = bucket->child_one;
		}
		id = TAILQ_FIRST(&bucket->nodes);
		if (bucket->level)
			dht_copy_bits(dst, id->id, bucket->level);
	}
}

static void
kad_node_bucket_refresh_cb(struct kad_nodeidq *nodes, void *arg)
{
	struct kad_ctx_bucket_refresh *ctx = arg;
	struct kad_bucket *bucket = ctx->bucket;
	struct kad_node_id *id;

	bucket->num_rpcs--;
	bucket->last_refresh = time(NULL);

	/* Ignore the results, we do not care for them */
	while ((id = TAILQ_FIRST(nodes)) != NULL) {
		TAILQ_REMOVE(nodes, id, next);
		kad_node_id_free(id);
	}
	free(nodes);

	if (ctx->cb != NULL)
		(*ctx->cb)(ctx->cb_arg);

	free(ctx);
}

/*
 * Causes the current bucket to be refreshed.
 */

int
kad_node_bucket_refresh(struct kad_node *node, struct kad_bucket *bucket,
    void (*cb)(void *), void *cb_arg)
{
	struct kad_ctx_bucket_refresh *ctx;
	u_char search_id[SHA_DIGEST_LENGTH];

	if ((ctx = calloc(1, sizeof(struct kad_ctx_bucket_refresh))) == NULL) {
		warn("%s: calloc", __func__);
		return (-1);
	}

	/* Generate a random ID in our ID range */
	kad_bucket_random_id(bucket, search_id);

	ctx->bucket = bucket;
	ctx->node = node;
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	/* Do the search now */
	if (kad_impl_lookup(node, search_id,
		kad_node_bucket_refresh_cb, ctx) == -1) {
		free(ctx);
		return (-1);
	}

	/* Remember that we have a lookup on this one */
	bucket->num_rpcs++;

	return (0);
}

static void
kad_node_timer_cb(int fd, short what, void *arg)
{
	struct kad_node *node = arg;
	struct timeval tv;

	/* Try to refresh all buckets that need it */
	kad_node_refresh_all_buckets(node, NULL, NULL, NULL);

	timerclear(&tv);
	tv.tv_sec = KAD_BUCKET_REFRESH_CHECK;
	evtimer_add(&node->ev_refresh, &tv);

}

struct kad_node *
kad_node_new(struct dht_node *dht)
{
	struct kad_node *node = calloc(1, sizeof(struct kad_node));
	struct timeval tv;
	int i;
	if (node == NULL)
		return (NULL);

	if (kad_rand == NULL)
		rand_init();

	for (i = 0; i < SHA_DIGEST_LENGTH; ++i) {
		node->myself.id[i] = rand_uint8(kad_rand);
	}

	node->bucket_root = kad_bucket_new(NULL);
	if (node->bucket_root == NULL)
		err(1, "%s: calloc", __func__);

	/* RPC management */
	SPLAY_INIT(&node->rpcs.rpcs);
	node->rpcs.cb_timeout = kad_rpc_timeout;

	node->dht = dht;

	node->storage = dht_storage_new(NULL, kad_key_refresh, node);
	if (node->storage == NULL)
		err(1, "%s: calloc", __func__);

	evtimer_set(&node->ev_refresh, kad_node_timer_cb, node);
	timerclear(&tv);
	tv.tv_sec = KAD_BUCKET_REFRESH_CHECK;
	evtimer_add(&node->ev_refresh, &tv);

	return (node);
}

/*
 * Used in unittests to give nodes an idea of their own address.
 */

int
kad_node_set_address(struct kad_node *node, char *host, uint16_t port)
{
	if (addr_pton(host, &node->myself.addr) == -1)
		return (-1);
	node->myself.port = port;

	return (0);
}

int
kad_node_insert(struct kad_node *node,
    struct addr *addr, uint16_t port, u_char *id)
{
	struct kad_node_id *node_id;
	u_char *diff;
	struct kad_bucket *where;
	struct kad_node_id *tmp;

	if (dht_kademlia_compare(id, node->myself.id) == 0) {
		/* We learned about ourself */
		return (0);
	}

	if ((node_id = kad_node_id_new(addr, port, id)) == NULL)
		return (-1);

	diff = dht_kademlia_distance(node->myself.id, node_id->id);
	where = kad_node_find_bucket(node, diff);

	tmp = SPLAY_FIND(kad_nodeidtree, &where->node_head, node_id);
	if (tmp != NULL) {
		/* Mark this node as alive */
		kad_node_id_refresh(where, tmp);
		kad_node_id_free(node_id);
		return (0);
	}

	/* Simple policy that does not do the relaxed routing */
	if (where->num_nodes < KAD_NODES_PER_BUCKET) {
		kad_bucket_node_insert(where, node_id);
	} else {
		static u_char zero[SHA_DIGEST_LENGTH];
		struct kad_bucket *self = kad_node_find_bucket(node, zero);
		if (self != where) {
			kad_node_id_free(node_id);
			return (0);
		}

		kad_bucket_node_insert(where, node_id);

		/* We might have to do multiple splits */
		do {
			kad_bucket_split(where, node->myself.id);
			if (where->child_one->num_nodes
			    >= KAD_NODES_PER_BUCKET )
				where = where->child_one;
			else if (where->child_zero->num_nodes
			    >= KAD_NODES_PER_BUCKET )
				where = where->child_zero;
		} while (where->num_nodes >= KAD_NODES_PER_BUCKET);
	}

	DFPRINTF(2, (stderr, "%s: Learned about %s at %s:%d\n",
		     dht_node_id_ascii(node->myself.id),
		     dht_node_id_ascii(node_id->id),
		     addr_ntoa(&node_id->addr), node_id->port));

	/* Fix up the counts */
	while ((where = where->parent) != NULL) {
		where->num_subtree_nodes++;
	} 

	return (1);
}

/*
 * Runs the refresh algorithm on all populated buckets.
 * If where == NULL, we use the root bucket from the Kademlia node.
 */

static void
kad_node_refresh_buckets_cb(void *arg)
{
	struct kad_ctx_refresh *ctx = arg;

	if (--ctx->num_rpcs)
		return;

	if (ctx->cb != NULL)
		(*ctx->cb)(ctx->cb_arg);

	free(ctx);
}

static void
kad_node_refresh_buckets_recursive(struct kad_node *node,
    struct kad_bucket *where, struct kad_ctx_refresh *ctx)
{
	struct kad_node_id *id;

	if (where->child_zero != NULL || where->child_one != NULL) {
		kad_node_refresh_buckets_recursive(node,
		    where->child_zero, ctx);
		kad_node_refresh_buckets_recursive(node,
		    where->child_one, ctx);
		return;
	}

	/* Remove dead entries */
	while ((id = TAILQ_FIRST(&where->nodes)) != NULL) {
		if ((id->flags & KAD_NODE_ID_DEAD) == 0)
			break;

		DFPRINTF(1, (stderr, "%s: Removing dead id %s\n",
			     dht_node_id_ascii(node->myself.id),
			     dht_node_id_ascii(id->id)));

		/* Takes also care of removal */
		kad_node_id_free(id);
	}

	/* Refresh only if the bucket is old */
	if ((node->flags & KAD_NODE_JOINED) &&
	    where->last_refresh &&
	    time(NULL) - where->last_refresh < KAD_BUCKET_REFRESH_INTERVAL)
		return;

	if (kad_node_bucket_refresh(node, where,
		kad_node_refresh_buckets_cb, ctx) == -1) {
		warnx("%s: refresh of bucket at level %d failed",
		    __func__, where->level);
	} else {
		ctx->num_rpcs++;
	}
}

int
kad_node_refresh_all_buckets(struct kad_node *node, struct kad_bucket *where,
    void (*cb)(void *), void *cb_arg)
{
	struct kad_ctx_refresh *ctx;

	if ((ctx = calloc(1, sizeof(struct kad_ctx_refresh))) == NULL) {
		warn("%s: calloc", __func__);
		return (-1);
	}

	ctx->parent = node;
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	if (where == NULL)
		where = node->bucket_root;

	kad_node_refresh_buckets_recursive(node, where, ctx);

	if (!ctx->num_rpcs) {
		free(ctx);
		return (-1);
	}

	return (0);
}

/*
 * Kademlia external functionality
 */

/*
 * Find the value for a key
 */

int
kad_impl_find_value(struct kad_node *node,
    u_char *keyid, void (*cb)(u_char *, size_t, void *), void *cb_arg)
{
	struct kad_ctx_lookup *ctx =
	    calloc(1, sizeof(struct kad_ctx_lookup));

	if (ctx == NULL) {
		warn("%s: calloc", __func__);
		return (-1);
	}

	memcpy(ctx->search_id, keyid, sizeof(ctx->search_id));
	ctx->parent = node;
	ctx->cb_find = cb;
	ctx->cb_find_arg = cb_arg;
	ctx->flags |= KAD_CTX_LOOKUP_FIND_VALUE;

	return (kad_impl_lookup_internal(node, ctx));
}

/*
 * Store a key value pair.
 */

static void
kad_impl_store_stage_two_cb(struct dht_rpc *rpc,
    struct evbuffer *evbuf, void *arg)
{
	struct kad_ctx_store *ctx = arg;

	if (evbuf == NULL)
		ctx->num_fails++;

	if (--ctx->num_rpcs)
		return;

	DFPRINTF(1, (stderr, "%s: store failed on %d nodes.\n",
		     __func__, ctx->num_fails));

	if (ctx->cb != NULL)
		(*ctx->cb)(0, ctx->cb_arg);

	free(ctx);
}

static void
kad_impl_store_stage_one_cb(struct kad_nodeidq *nodes, void *arg)
{
	struct kad_ctx_store *ctx = arg;
	struct kad_node_id *id;

	while ((id = TAILQ_FIRST(nodes)) != NULL) {
		TAILQ_REMOVE(nodes, id, next);

		if (kad_rpc_store(ctx->node, id,
			ctx->keyid, ctx->val, ctx->vallen,
			kad_impl_store_stage_two_cb, ctx) != -1) {
			DFPRINTF(1, (stderr, "%s: store for %s sent to %s\n",
				     __func__,
				     dht_node_id_ascii(ctx->keyid),
				     dht_node_id_ascii(id->id)));
			ctx->num_rpcs++;
		}

		kad_node_id_free(id);
	}
	free(nodes);

	/* We no longer need the data */
	free(ctx->val);
	ctx->val = NULL;

	/* At least some RPCs were fine */
	if (ctx->num_rpcs) 
		return;

	if (ctx->cb != NULL)
		(*ctx->cb)(-1, ctx->cb_arg);
	free(ctx);
}

int
kad_impl_store(struct kad_node *node,
    u_char *keyid, u_char *value, size_t vallen,
    void (*cb)(int, void *), void *cb_arg)
{
	struct kad_ctx_store *ctx = calloc(1, sizeof(struct kad_ctx_store));
	if (ctx == NULL) {
		warn("%s: calloc", __func__);
		return (-1);
	}

	if ((ctx->val = malloc(vallen)) == NULL) {
		warn("%s: malloc", __func__);
		free(ctx);
		return (-1);
	}

	memcpy(ctx->keyid, keyid, sizeof(ctx->keyid));
	memcpy(ctx->val, value, vallen);
	ctx->vallen = vallen;

	ctx->node = node;
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	if (kad_impl_lookup(node, ctx->keyid,
		kad_impl_store_stage_one_cb, ctx) == -1) {
		free(ctx->val);
		free(ctx);
		return (-1);
	}

	return (0);
}


void
kad_impl_find_value_cb(struct evbuffer *evbuf, void *arg)
{
	struct kad_ctx_lookup *ctx = arg;
	struct kad_pkt *hdr = NULL;
	struct kad_pkt_node_reply *pkt;
	struct kad_node_id *id, tmp;
	size_t vallen;

	if (evbuf == NULL)
		goto out;

	hdr = (struct kad_pkt *)EVBUFFER_DATA(evbuf);
	pkt = (struct kad_pkt_node_reply *)(hdr + 1);

	/* Figure out who replied to this RPC */
	memcpy(tmp.id, hdr->src_id, sizeof(tmp.id));
	id = SPLAY_FIND(kad_nodeidtree, &ctx->node_head, &tmp);
	if (id == NULL) {
		DFPRINTF(1, (stderr,
			     "%s: got reply from node %s we never queried.\n",
			     __func__, dht_node_id_ascii(hdr->src_id)));
		goto out;
	} else {
		/* This is a good node; keep track of it */
		id->flags |= KAD_NODE_GOT_REPLY;
		if (hdr->rpc_command ==
		    DHT_KAD_REPLY(DHT_KAD_RPC_FIND_VALUE)) {
			DFPRINTF(1,
			    (stderr,
				"%s: got find value from node %s.\n",
				__func__, dht_node_id_ascii(hdr->src_id)));
			id->flags |= KAD_NODE_GOT_VALUE;
		} else {
			goto out;
		}
	}

	vallen = EVBUFFER_LENGTH(evbuf) - sizeof(struct kad_pkt);

	if (ctx->val != NULL) {
		/* We already got a value */
		if (ctx->vallen != vallen)
			DFPRINTF(2,
			    (stderr,
				"%s: got different values for %s\n",
				__func__, dht_node_id_ascii(ctx->search_id)));
		goto out;
	}

	ctx->flags |= KAD_CTX_LOOKUP_GOT_VALUE;

	ctx->val = malloc(vallen);
	/* On malloc error we just return nothing */
	if (ctx->val != NULL) {
		ctx->vallen = vallen;
		memcpy(ctx->val, pkt, vallen);
	}

 out:
	if (ctx->num_rpcs)
		return;

	(*ctx->cb_find)(ctx->val, ctx->vallen, ctx->cb_find_arg);

	if (ctx->val != NULL) {
		/*
		 * Find the closest node that does not have the value,
		 * and cache the value there.
		 */
		SPLAY_FOREACH(id, kad_diffidtree, &ctx->diff_head) {
			if ( (id->flags & KAD_NODE_GOT_REPLY) &&
			    !(id->flags & KAD_NODE_GOT_VALUE) ) {
				DFPRINTF(1,
				    (stderr, "%s: store for %s sent to %s\n",
					__func__,
					dht_node_id_ascii(ctx->search_id),
					dht_node_id_ascii(id->id)));
				kad_rpc_store(ctx->parent, id,
				    ctx->search_id,
				    ctx->val, ctx->vallen, NULL, NULL);
				break;
			}
		}
	}

	/* The cleanup the nodes */
	for (id = TAILQ_FIRST(&ctx->nodes); id != NULL;
	    id  = TAILQ_FIRST(&ctx->nodes)) {
		TAILQ_REMOVE(&ctx->nodes, id, next);
		kad_node_id_free(id);
	}

	if (ctx->val != NULL)
		free(ctx->val);
	free(ctx);
}


/*
 * Look up on a node ID.  The callback gets a least of nodes close
 * to the search ID.  The callback needs to free the memory for each
 * id and also the memory for the head of the queue.
 */

void
kad_impl_lookup_cb(struct dht_rpc *rpc, struct evbuffer *evbuf, void *arg)
{
	struct kad_pkt *hdr = NULL;
	struct kad_pkt_node_reply *pkt;
	struct kad_ctx_lookup *ctx = arg;
	struct kad_nodeidq *result_nodes;
	struct kad_node_id *id, tmp;
	struct kad_bucket *where;
	u_char *diff;
	size_t remaining = 0;
	int i, k;

	/* Allows us to keep track of outstanding RPCs */
	ctx->num_rpcs--;

	if ((ctx->flags & KAD_CTX_LOOKUP_FIND_VALUE) &&
	    (ctx->flags & KAD_CTX_LOOKUP_GOT_VALUE)) {
		kad_impl_find_value_cb(evbuf, arg);
		return;
	}

	/* RPC failed */
	if (evbuf == NULL)
		goto skip;

	hdr = (struct kad_pkt *)EVBUFFER_DATA(evbuf);
	pkt = (struct kad_pkt_node_reply *)(hdr + 1);
	remaining = EVBUFFER_LENGTH(evbuf) - sizeof(struct kad_pkt);

	if ((ctx->flags & KAD_CTX_LOOKUP_FIND_VALUE) &&
	    hdr->rpc_command == DHT_KAD_REPLY(DHT_KAD_RPC_FIND_VALUE)) {
		kad_impl_find_value_cb(evbuf, arg);
		return;
	}

	/* Figure out who replied to this RPC */
	memcpy(tmp.id, hdr->src_id, sizeof(tmp.id));
	id = SPLAY_FIND(kad_nodeidtree, &ctx->node_head, &tmp);
	if (id == NULL) {
		DFPRINTF(1, (stderr,
			     "%s: got reply from node %s we never queried.\n",
			     __func__, dht_node_id_ascii(hdr->src_id)));
		goto skip;
	} else {
		/* This is a good node; keep track of it */
		id->flags |= KAD_NODE_GOT_REPLY;
	}

	/* Look at all the responses */
	for (i = 0; i < remaining / sizeof(*pkt); ++i) {
		struct addr addr;
		addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS,
		    pkt[i].address, IP_ADDR_LEN);

		id = kad_node_id_new(&addr, htons(pkt[i].port),pkt[i].node_id);
		if (id == NULL) {
			warn("%s: malloc", __func__);
			break;
		}

		/* If we know about this node already, do not insert it */
		if (SPLAY_FIND(kad_nodeidtree, &ctx->node_head, id) != NULL) {
			kad_node_id_free(id);
			continue;
		}

		/* Make sure that we can enter it into the diff tree */
		id->diff = ctx->search_id;

		TAILQ_INSERT_TAIL(&ctx->nodes, id, next);
		SPLAY_INSERT(kad_nodeidtree, &ctx->node_head, id);
		SPLAY_INSERT(kad_diffidtree, &ctx->diff_head, id);
	}

 skip:	
	/* 
	 * Of the first k-nodes, pick alpha to which we did not send RPC yet.
	 */

	for (i = 0, k = 0, id = SPLAY_MIN(kad_diffidtree, &ctx->diff_head);
	    i < KAD_NODES_PER_BUCKET && k < KAD_ALPHA && id != NULL;
	    ++i, id = SPLAY_NEXT(kad_diffidtree, &ctx->diff_head, id)) {
		int res;
		if (id->flags & KAD_NODE_SENT_RPC)
			continue;

		if (ctx->flags & KAD_CTX_LOOKUP_FIND_VALUE)
			res = kad_rpc_find_value(ctx->parent, id,
			    ctx->search_id, kad_impl_lookup_cb, ctx);
		else
			res = kad_rpc_find_node(ctx->parent, id,
			    ctx->search_id, kad_impl_lookup_cb, ctx);
		if (res == -1)
			continue;

		DFPRINTF(1, (stderr, "%s: lookup for %s sent to %s\n",
			     __func__,
			     dht_node_id_ascii(ctx->search_id),
			     dht_node_id_ascii(id->id)));

		id->flags |= KAD_NODE_SENT_RPC;
		ctx->num_rpcs++;
		k++;

	}

	/* Figure out if we are done */
	if (ctx->num_rpcs)
		return;

	/* Initiate termination step */
	for (i = 0, id = SPLAY_MIN(kad_diffidtree, &ctx->diff_head);
	    i < KAD_NODES_PER_BUCKET && id != NULL;
	    id = SPLAY_NEXT(kad_diffidtree, &ctx->diff_head, id)) {
		if ( (id->flags & KAD_NODE_SENT_RPC) &&
		    !(id->flags & KAD_NODE_GOT_REPLY) )
			continue;

		++i;	/* count nodes that are alive */

		if (id->flags & KAD_NODE_GOT_REPLY)
			continue;

		/* Sends out the FIND NODE rpc */
		if (kad_rpc_find_node(ctx->parent, id, ctx->search_id,
			kad_impl_lookup_cb, ctx) == -1)
			continue;

		DFPRINTF(1, (stderr, "%s: lookup for %s sent to %s\n",
			     __func__,
			     dht_node_id_ascii(ctx->search_id),
			     dht_node_id_ascii(id->id)));

		id->flags |= KAD_NODE_SENT_RPC;
		ctx->num_rpcs++;
	}

	/* If we did not initiate any new RPCS, we are done */
	if (ctx->num_rpcs)
		return;

	/* Unfortunately, we might not have found the value */
	if (ctx->flags & KAD_CTX_LOOKUP_FIND_VALUE) {
		DFPRINTF(1, (stderr, "%s: failed to find value for %s\n",
			     __func__, dht_node_id_ascii(ctx->search_id)));
		(*ctx->cb_find)(NULL, 0, ctx->cb_find_arg);
		goto cleanup;
	}

	/* We are done */
	DFPRINTF(1, (stderr, "%s: lookup for %s DONE\n",
		    __func__, dht_node_id_ascii(ctx->search_id)));

	result_nodes = malloc(sizeof(struct kad_nodeidq));
	if (result_nodes == NULL)
		goto cleanup;
	TAILQ_INIT(result_nodes);

	for (i = 0, id = SPLAY_MIN(kad_diffidtree, &ctx->diff_head);
	    i < KAD_NODES_PER_BUCKET && id != NULL;
	    id = SPLAY_MIN(kad_diffidtree, &ctx->diff_head)) {
		SPLAY_REMOVE(kad_diffidtree, &ctx->diff_head, id);

		/* 
		 * Include only nodes that replied - this means we are not
		 * going to return ourselves when searching for ourself.
		 */
		if ((id->flags & KAD_NODE_GOT_REPLY) == 0)
			continue;

		++i;
		TAILQ_REMOVE(&ctx->nodes, id, next);
		TAILQ_INSERT_TAIL(result_nodes, id, next);
	}

	/* A lookup for a key causes the bucket to be refreshed */
	diff = dht_kademlia_distance(ctx->parent->myself.id, ctx->search_id);
	where = kad_node_find_bucket(ctx->parent, diff);
	where->last_refresh = time(NULL);

 cleanup:
	/* The diff id tree is corrupt now, but we maintined the tailq tree */
	for (id = TAILQ_FIRST(&ctx->nodes); id != NULL;
	    id  = TAILQ_FIRST(&ctx->nodes)) {
		TAILQ_REMOVE(&ctx->nodes, id, next);
		kad_node_id_free(id);
	}

	(*ctx->cb)(result_nodes, ctx->cb_arg);

	free(ctx);

	return;
}

int
kad_impl_lookup(struct kad_node *node, u_char *search_id,
    void (*cb)(struct kad_nodeidq *, void *), void *cb_arg)
{
	struct kad_ctx_lookup *ctx = calloc(1, sizeof(struct kad_ctx_lookup));

	if (ctx == NULL) {
		warn("%s: calloc", __func__);
		return (-1);
	}

	memcpy(ctx->search_id, search_id, sizeof(ctx->search_id));

	ctx->parent = node;

	/* We need to call these guys back */
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	return (kad_impl_lookup_internal(node, ctx));
}

static int
kad_impl_lookup_internal(struct kad_node *node, struct kad_ctx_lookup *ctx)
{
	struct kad_node_id *id;
	int num_nodes;

	TAILQ_INIT(&ctx->nodes);
	SPLAY_INIT(&ctx->node_head);

	/* Collect our first list of candidates */
	num_nodes = kad_node_lookup(&ctx->nodes, ctx->parent,
	    ctx->search_id, KAD_ALPHA);
	if (num_nodes == 0) {
		DFPRINTF(2, (stderr, "%s: lookup for %s but no nodes known\n",
			     __func__, dht_node_id_ascii(ctx->search_id)));
		goto error;
	}
	
	TAILQ_FOREACH(id, &ctx->nodes, next) {
		int res;

		/* Also insert into our ancillary data structures */
		id->diff = ctx->search_id;
		SPLAY_INSERT(kad_nodeidtree, &ctx->node_head, id);
		SPLAY_INSERT(kad_diffidtree, &ctx->diff_head, id);

		DFPRINTF(1, (stderr, "%s: lookup for %s sent to %s\n",
			     __func__,
			     dht_node_id_ascii(ctx->search_id),
			     dht_node_id_ascii(id->id)));
		if (ctx->flags & KAD_CTX_LOOKUP_FIND_VALUE)
			res = kad_rpc_find_value(ctx->parent, id,
			    ctx->search_id, kad_impl_lookup_cb, ctx);
		else
			res = kad_rpc_find_node(ctx->parent, id,
			    ctx->search_id, kad_impl_lookup_cb, ctx);
		if (res != -1) {
			id->flags |= KAD_NODE_SENT_RPC;
			ctx->num_rpcs++;
		}
	}

	if (!ctx->num_rpcs) {
		DFPRINTF(2, (stderr, "%s: lookup for %s failed to send rpc\n",
			     __func__, dht_node_id_ascii(ctx->search_id)));
		goto error;
	}

	return (0);

 error:
	free(ctx);
	return (-1);
}

static void
kad_impl_join_stage_three_cb(void *arg)
{
	struct kad_ctx_join *ctx = arg;
	struct kad_node *node = ctx->node;

	DFPRINTF(1, (stderr, "%s: finished join for %s\n",
		     __func__, dht_node_id_ascii(node->myself.id)));

	node->flags |= KAD_NODE_JOINED;

	(*ctx->cb)(0, ctx->cb_arg);
	free(ctx);
}

static void
kad_impl_join_stage_two_cb(struct kad_nodeidq *nodes, void *arg)
{
	struct kad_ctx_join *ctx = arg;
	struct kad_node *node = ctx->node;
	struct kad_node_id *id;
	int count;

	/* Ignore the results, we do not care for them */
	while ((id = TAILQ_FIRST(nodes)) != NULL) {
		TAILQ_REMOVE(nodes, id, next);
		kad_node_id_free(id);
		count++;
	}
	free(nodes);

	if (!count)
		goto error;

	if (kad_node_refresh_all_buckets(node, NULL,
		kad_impl_join_stage_three_cb, ctx) == -1)
		goto error;

	return;

 error:
	(*ctx->cb)(-1, ctx->cb_arg);
	free(ctx);
}

static void
kad_impl_join_stage_one_cb(struct dht_rpc *rpc,
    struct evbuffer *evbuf, void *arg)
{
	struct kad_ctx_join *ctx = arg;
	struct kad_node *node = ctx->node;

	if (evbuf == NULL) {
		/* Retry on error */
		if (++ctx->num_retry > 3)
			goto error;
		else if (kad_rpc_ping(node, &ctx->id,
			     kad_impl_join_stage_one_cb, ctx) == -1)
			goto error;

		return;
	}

	if (kad_impl_lookup(node, node->myself.id,
		kad_impl_join_stage_two_cb, ctx) == -1)
		goto error;

	return;

 error:
	(*ctx->cb)(-1, ctx->cb_arg);
	free(ctx);
}

int
kad_impl_join(void *node_data, struct addr *addr, u_short port,
    void (*cb)(int, void *), void *cb_arg)
{
	struct kad_node *node = node_data;
	struct kad_ctx_join *ctx;
	struct kad_node_id *id;

	if ((ctx = calloc(1, sizeof(struct kad_ctx_join))) == NULL) {
		warn("%s: calloc", __func__);
		return (-1);
	}

	id = &ctx->id;
	id->addr = *addr;
	id->port = port;
	/* wild card addrress */
	memset(id->id, 0, sizeof(id->id));

	ctx->node = node;
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	if (kad_rpc_ping(node, id, kad_impl_join_stage_one_cb, ctx) == -1) {
		free(ctx);
		return (-1);
	}

	return (0);
}

/*
 * Kademlia packet handling
 */

void
kad_read_cb(struct addr *addr, uint16_t port, u_char *data, size_t datlen,
    void *arg)
{
	static struct evbuffer *buf;
	struct kad_node *node = arg;
	struct kad_pkt *hdr = (struct kad_pkt *)data;
	struct dht_rpc *rpc;
	int noinsert = 0;

	if (buf == NULL) {
		buf = evbuffer_new();
		if (buf == NULL)
			err(1, "%s: calloc", __func__);
	}

	if (datlen < sizeof(struct kad_pkt)) {
		DFPRINTF(3, (stderr,
			     "%s: received short KAD packet from %s:%d\n",
			     __func__, addr_ntoa(addr), port));
		return;
	}

	if (memcmp(hdr->dst_id, node->myself.id, sizeof(hdr->dst_id))) {
		int allow = 0;

		/* 
		 * We allow a ping without the correct destination IP, so
		 * that a node can bootstrap itself.
		 */
		if (hdr->rpc_command == DHT_KAD_RPC_PING) {
			int i;
			for (i = 0; i < SHA_DIGEST_LENGTH; ++i)
				if (hdr->dst_id[i])
					break;
			if (i == SHA_DIGEST_LENGTH) {
				/*
				 * Wild card ping.  Allow it to proceed.
				 */
				allow = 1;
				noinsert = 1;
			}
		}
			
		if (!allow) {
			DFPRINTF(3,
			    (stderr,
				"%s: received packet for %s which is not me\n",
				__func__, dht_node_id_ascii(hdr->dst_id)));
			return;
		}
	}

	/* 
	 * Check if we know about this node.  If not insert into our
	 * k-bucket.
	 */
	if (!noinsert)
		kad_node_insert(node, addr, port, hdr->src_id);

	/*
	 * Now let's see if this is an RPC that we should know about.
	 */
	if (hdr->rpc_command == DHT_KAD_REPLY(hdr->rpc_command)) {
		rpc = dht_rpc_find(&node->rpcs, hdr->rpc_id);
		if (rpc != NULL &&
		    DHT_KAD_REPLY(rpc->rpc_command) == hdr->rpc_command) {
			if (rpc->cb) {
				evbuffer_drain(buf, -1);
				evbuffer_add(buf, data, datlen);
				(*rpc->cb)(rpc, buf, rpc->cb_arg);
			}
			dht_rpc_remove(&node->rpcs, rpc);
			return;
		} else {
			DFPRINTF(1, 
			    (stderr,
				"%s: cmd: %d expected %d, "
				"unknown rpc id %s from %s at %s:%d\n",
				__func__,
				hdr->rpc_command,
				DHT_KAD_REPLY(rpc->rpc_command),
				dht_node_id_ascii(rpc->rpc_id),
				dht_node_id_ascii(hdr->dst_id),
				addr_ntoa(addr), port));
		}
		return;
	}

	DFPRINTF(3, (stderr,
		     "%s: command %d from %s at %s:%d\n",
		     __func__, 
		     hdr->rpc_command,
		     dht_node_id_ascii(hdr->dst_id),
		     addr_ntoa(addr), port));

	switch (hdr->rpc_command) {
	case DHT_KAD_RPC_PING: {
		/* Easy to answer */
		struct kad_node_id tmp;
		tmp.addr = *addr;
		tmp.port = port;
		memcpy(tmp.id, hdr->src_id, sizeof(tmp.id));
		kad_send_rpc(node, &tmp,
		    DHT_KAD_REPLY(DHT_KAD_RPC_PING),
		    hdr->rpc_id,	/* quote the rpc id back */
		    NULL, 0,		/* no payload */
		    NULL, NULL		/* don't want a callback */
		    );
		break;
	case DHT_KAD_RPC_STORE:
		kad_rpc_handle_store(node, addr, port, hdr, datlen);
		break;
	case DHT_KAD_RPC_FIND_NODE:
		kad_rpc_handle_find_node(node, addr, port, hdr, datlen);
		break;
	case DHT_KAD_RPC_FIND_VALUE:
		kad_rpc_handle_find_value(node, addr, port, hdr, datlen);
		break;
	}
	default:
		DFPRINTF(1, (stderr,
			     "%s: unknown command %d from %s at %s:%d\n",
			     __func__, 
			     hdr->rpc_command,
			     dht_node_id_ascii(hdr->dst_id),
			     addr_ntoa(addr), port));
		return;
	}
}

/*
 * Kademlia RPCs
 */

int
kad_rpc_ping(struct kad_node *node, struct kad_node_id *id,
    void (*cb)(struct dht_rpc *, struct evbuffer *, void *), void *cb_arg)
{
	return (kad_send_rpc(node, id,
		    DHT_KAD_RPC_PING, 
		    NULL,    /* generate rpc id for us */
		    NULL, 0, /* no payload */
		    cb, cb_arg));
}

int
kad_rpc_find_node(struct kad_node *node, struct kad_node_id *id,
    u_char *node_id,
    void (*cb)(struct dht_rpc *, struct evbuffer *, void *), void *cb_arg)
{
	return (kad_send_rpc(node, id,
		    DHT_KAD_RPC_FIND_NODE, 
		    NULL,    /* generate rpc id for us */
		    (u_char *)node_id, SHA_DIGEST_LENGTH,
		    cb, cb_arg));
}

int
kad_rpc_find_value(struct kad_node *node, struct kad_node_id *id,
    u_char *node_id,
    void (*cb)(struct dht_rpc *, struct evbuffer *, void *), void *cb_arg)
{
	return (kad_send_rpc(node, id,
		    DHT_KAD_RPC_FIND_VALUE, 
		    NULL,    /* generate rpc id for us */
		    (u_char *)node_id, SHA_DIGEST_LENGTH,
		    cb, cb_arg));
}

int
kad_rpc_store(struct kad_node *node, struct kad_node_id *id,
    u_char *node_id, u_char *value, size_t vallen,
    void (*cb)(struct dht_rpc *, struct evbuffer *, void *), void *cb_arg)
{
	int res;
	size_t totlen = SHA_DIGEST_LENGTH + vallen;
	u_char *data;

	if (totlen > KAD_MAX_PAYLOAD_LEN) {
		warnx("%s: payload too long: %d", __func__, totlen);
		return (-1);
	}

	if ((data = malloc(totlen)) == NULL) {
		warn("%s: malloc", __func__);
		return (-1);
	}

	memcpy(data, node_id, SHA_DIGEST_LENGTH);
	memcpy(data + SHA_DIGEST_LENGTH, value, vallen);

	res = kad_send_rpc(node, id,
	    DHT_KAD_RPC_STORE, 
	    NULL,	    /* generate rpc id for us */
	    data, totlen,   /* payload */
	    cb, cb_arg);

	free(data);

	return (res);
}

/*
 * Collects all ids in the buckets below into the SPLAY.
 */

void
kad_collect_ids_with_diff(struct kad_nodeidtree *collect,
    struct kad_bucket *where, u_char *diff)
{
	struct kad_node_id *tmp, *id;
	u_char *mydiff;

	if (where->child_zero || where->child_one) {
		kad_collect_ids_with_diff(collect, where->child_one, diff);
		kad_collect_ids_with_diff(collect, where->child_zero, diff);
		return;
	}

	TAILQ_FOREACH(id, &where->nodes, next) {
		mydiff = dht_kademlia_distance(id->id, diff);
		
		/*
		 * Remember that we need to re-xor later to get the right
		 * node ids.
		 */
		tmp = kad_node_id_new(&id->addr, id->port, mydiff);
		/* Out of memory conditions cause us to terminate early */
		if (tmp == NULL)
			return;

		SPLAY_INSERT(kad_nodeidtree, collect, tmp);
	}
}

void
kad_rpc_handle_find_value(struct kad_node *node,
    struct addr *addr, uint16_t port,
    struct kad_pkt *hdr, size_t datlen)
{
	struct kad_pkt_find_node *pkt_node =
	    (struct kad_pkt_find_node *)(hdr + 1);
	struct kad_node_id tmp;
	struct dht_keyvalue *kv;

	if (datlen !=
	    sizeof(struct kad_pkt) + sizeof(struct kad_pkt_find_node)) {
		DFPRINTF(3, (stderr,
			     "%s: received short KAD packet from %s:%d\n",
			     __func__, addr_ntoa(addr), port));
		return;
	}

	kv = dht_find_keyval(node->storage,
	    pkt_node->node_id, SHA_DIGEST_LENGTH);

	/* If we cannot find the keyvalue, just treat this as find node */
	if (kv == NULL) {
		kad_rpc_handle_find_node(node, addr, port, hdr, datlen);
		return;
	}

	/* Send out reply */
	tmp.addr = *addr;
	tmp.port = port;
	memcpy(tmp.id, hdr->src_id, sizeof(tmp.id));

	kad_send_rpc(node, &tmp,
	    DHT_KAD_REPLY(DHT_KAD_RPC_FIND_VALUE),
	    hdr->rpc_id,		/* echoed rpc id */
	    kv->val, kv->vallen,	/* payload */
	    NULL, NULL);
}

void
kad_rpc_handle_find_node(struct kad_node *node,
    struct addr *addr, uint16_t port,
    struct kad_pkt *hdr, size_t datlen)
{
	struct kad_pkt_find_node *pkt_node =
	    (struct kad_pkt_find_node *)(hdr + 1);
	struct kad_pkt_node_reply *pkt_reply, *cur;
	int reply_entries;
	struct kad_node_id *id, tmp;
	struct kad_nodeidq nodes;

	if (datlen < 
	    sizeof(struct kad_pkt) + sizeof(struct kad_pkt_find_node)) {
		DFPRINTF(3, (stderr,
			     "%s: received short KAD packet from %s:%d\n",
			     __func__, addr_ntoa(addr), port));
		return;
	}

	TAILQ_INIT(&nodes);
	reply_entries = kad_node_lookup(&nodes, node,
	    pkt_node->node_id, KAD_NODES_PER_BUCKET);

	pkt_reply = malloc(reply_entries * sizeof(struct kad_pkt_node_reply));
	if (pkt_reply == NULL) {
		warn("%s: malloc", __func__);
		goto cleanup;
	}

	/* Now, collect the k closest ID into our reply */
	cur = pkt_reply;
	TAILQ_FOREACH(id, &nodes, next) {
		memcpy(cur->address, &id->addr.addr_ip, sizeof(cur->address));
		cur->port = htons(id->port);
		memcpy(cur->node_id, id->id, sizeof(cur->node_id));

		cur++;
	}

	/* Send out reply */
	tmp.addr = *addr;
	tmp.port = port;
	memcpy(tmp.id, hdr->src_id, sizeof(tmp.id));

	kad_send_rpc(node, &tmp,
	    DHT_KAD_REPLY(DHT_KAD_RPC_FIND_NODE),
	    hdr->rpc_id,
	    (u_char *)pkt_reply,
	    reply_entries * sizeof(struct kad_pkt_node_reply),
	    NULL, NULL);

	free(pkt_reply);

 cleanup:
	/* Clean up our memory */
	while ((id = TAILQ_FIRST(&nodes)) != NULL) {
		TAILQ_REMOVE(&nodes, id, next);
		kad_node_id_free(id);
	}
}

void
kad_rpc_handle_store(struct kad_node *node,
    struct addr *addr, uint16_t port,
    struct kad_pkt *hdr, size_t datlen)
{
	struct dht_node *dht = node->dht;
	struct kad_pkt_find_node *pkt_node =
	    (struct kad_pkt_find_node *)(hdr + 1);
	struct kad_node_id tmp;
	struct dht_keyvalue *kv;
	int timeout, scale;
	u_char *val;
	size_t vallen;

	if (datlen < 
	    sizeof(struct kad_pkt) + sizeof(struct kad_pkt_find_node)) {
		DFPRINTF(3, (stderr,
			     "%s: received short KAD packet from %s:%d\n",
			     __func__, addr_ntoa(addr), port));
		return;
	}

	vallen = datlen -
	    sizeof(struct kad_pkt) + sizeof(struct kad_pkt_find_node);
	if (vallen == 0) {
		DFPRINTF(3, (stderr,
			     "%s: received empty STORE from %s:%d\n",
			     __func__, addr_ntoa(addr), port));
		return;
	}
	val = (u_char *)(hdr + 1) + sizeof(struct kad_pkt_find_node);

	if (dht->store_cb != NULL) {
		if ((*dht->store_cb)(
			    pkt_node->node_id, sizeof(pkt_node->node_id),
			    val, vallen, dht->store_cb_arg) == -1) {

			DFPRINTF(1, (stderr, "%s: validation for %s failed\n",
				     dht_node_id_ascii(node->myself.id),
				     dht_node_id_ascii(pkt_node->node_id)));

			goto ack;
		}
	}

	/* let's figure out how many nodes are closer to this key id */
	scale = kad_node_num_closer_nodes(node, pkt_node->node_id);
	timeout = 24*3600 >> scale;

	if (timeout < 60) {
		/* Ack the RPC so that we do not get counted as losers */
		goto ack;
	}

	DFPRINTF(1, (stderr, "%s: storing %s for %d seconds\n",
		     dht_node_id_ascii(node->myself.id),
		     dht_node_id_ascii(pkt_node->node_id),
		     timeout));

	/* Create the key value pair */
	kv = dht_keyval_new(pkt_node->node_id, SHA_DIGEST_LENGTH,
	    val, vallen);
	if (kv == NULL) {
		DFPRINTF(2, (stderr,
			     "%s: failed to allocate keyval for %s:%d\n",
			     __func__, addr_ntoa(addr), port));
		return;
	}

	if (dht_insert_keyval(node->storage, kv, timeout) == -1) {
		dht_keyval_free(kv);
		DFPRINTF(2, (stderr,
			     "%s: failed to insert keyval for %s:%d\n",
			     __func__, addr_ntoa(addr), port));
		return;
	}

 ack:
	/* Send out reply */
	tmp.addr = *addr;
	tmp.port = port;
	memcpy(tmp.id, hdr->src_id, sizeof(tmp.id));

	kad_send_rpc(node, &tmp,
	    DHT_KAD_REPLY(DHT_KAD_RPC_STORE),
	    hdr->rpc_id,	/* quoted rpc ID */
	    NULL, 0,		/* no reply payload */
	    NULL, NULL);
}

/*
 * Sends a generic Kademlia RPC.
 */

int
kad_send_rpc(struct kad_node *node, struct kad_node_id *id,
    uint8_t command, u_char *rpc_id,
    u_char *payload, size_t payload_len,
    void (*cb)(struct dht_rpc *, struct evbuffer *, void *), void *cb_arg)
{
	struct dht_rpc *rpc;
	size_t pktlen = sizeof(struct kad_pkt) + payload_len;
	struct kad_pkt *pkt;
	int need_rpc = DHT_KAD_REPLY(command) != command;

	if (dht_kademlia_compare(id->id, node->myself.id) == 0) {
		/* Do not send RPCs to ourselves */
		return (-1);
	}

	if ((pkt = calloc(1, pktlen)) == NULL)
		return (-1);

	/* Fill in pkt header */
	memcpy(pkt->src_id, node->myself.id, sizeof(pkt->src_id));
	memcpy(pkt->dst_id, id->id, sizeof(pkt->dst_id));
	pkt->rpc_command = command;

	/* Replies do not require a waiting RPC object */
	if (need_rpc) {
		if ((rpc = dht_rpc_new(&node->rpcs, node,
			 pkt->dst_id, command,
			 (void (*)(struct dht_rpc *, void *, void *))cb,
			 cb_arg)) == NULL) {
			free(pkt);
			return (-1);
		}
		memcpy(pkt->rpc_id, rpc->rpc_id, sizeof(pkt->rpc_id));
	} else {
		/* We are a reply and need to quote the previous ID */
		assert(rpc_id != NULL);
		memcpy(pkt->rpc_id, rpc_id, sizeof(pkt->rpc_id));
	}

	if (payload_len)
		memcpy((u_char *)(pkt + 1), payload, payload_len);

	dht_send(node->dht, DHT_TYPE_KADEMLIA,
	    &id->addr, id->port, (u_char *)pkt, pktlen);

	return (0);
}

void
kad_rpc_timeout(struct dht_rpc *rpc)
{
	struct kad_node *node = rpc->parent.kad_node;
	struct kad_node_id *id = kad_node_id_find(node, rpc->rpc_dst);

	/* If we do not hear back from it - we increase the timout counter */
	if (id != NULL)
		kad_node_id_timeout(id);
}

static void
kad_key_refresh(struct dht_keyvalue *kv, void *arg)
{
	struct kad_node *node = arg;

	/*
	 * Let's be so nice and store this value again.  We do not care about
	 * the callback nor any error codes.  It's just best effort.
	 */
	kad_impl_store(node, kv->key, kv->val, kv->vallen, NULL, NULL);
}

/* Interface functions */

int
kad_dht_impl_lookup(void *node_data, u_char *id, size_t idlen,
    struct dht_node_id **ids, size_t *numids)
{
	struct kad_node *node = node_data;
	struct kad_nodeidq nodes;
	struct kad_node_id *tmp;
	int i, num_nodes;
	u_char diff[2][SHA_DIGEST_LENGTH];
	u_char search_id[SHA_DIGEST_LENGTH];

	if (idlen == sizeof(search_id)) {
		memcpy(search_id, id, sizeof(search_id));
	} else {
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, id, idlen);
		SHA1_Final(search_id, &ctx);
	}

	TAILQ_INIT(&nodes);

	/* Collect our first list of candidates */
	num_nodes = kad_node_lookup(&nodes, node,
	    search_id, KAD_NODES_PER_BUCKET);
	if (num_nodes == 0) {
		DFPRINTF(2, (stderr, "%s: lookup for %s but no nodes known\n",
			     __func__, dht_node_id_ascii(search_id)));
	}

	/* Convert them */
	kad_nodeidq_to_dht_nodeids(ids, numids, &nodes, num_nodes);

	/* Clean up the memory */
	while ((tmp = TAILQ_FIRST(&nodes)) != NULL) {
		TAILQ_REMOVE(&nodes, tmp, next);
		kad_node_id_free(tmp);
	}

	/*
	 * We return only nodes that are closer to the search term than
	 * the current node id.
	 */
	dht_kademlia_xor(diff[1], node->myself.id, search_id);
	for (i = 0; i < *numids; ++i) {
		dht_kademlia_xor(diff[0], (*ids)[i].id, search_id);
		if (dht_kademlia_compare(diff[0], diff[1]) >= 0)
			break;
	}

	*numids = i;

	return (0);
}

u_char *
kad_dht_impl_myid(void *node_data)
{
	struct kad_node *node = node_data;

	return (node->myself.id);
}

int
kad_dht_impl_find_id(void *node_data, u_char *id, size_t idlen,
    struct dht_node_id *pid)
{
	struct kad_node *node = node_data;
	struct kad_node_id *fid;
	u_char search_id[SHA_DIGEST_LENGTH];

	if (idlen == sizeof(search_id)) {
		memcpy(search_id, id, sizeof(search_id));
	} else {
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, id, idlen);
		SHA1_Final(search_id, &ctx);
	}

	fid = kad_node_id_find(node, search_id);
	if (fid == NULL)
		return (-1);

	pid->addr = fid->addr;
	pid->port = fid->port;
	memcpy(pid->id, fid->id, sizeof(pid->id));

	return (0);
}

int
kad_dht_impl_ping(void *node_data, u_char *search_id)
{
	struct kad_node *node = node_data;
	struct kad_node_id *fid;

	fid = kad_node_id_find(node, search_id);
	if (fid == NULL) {
		DFPRINTF(2, (stderr, "%s: Unknown node %s\n",
			     __func__,
			     dht_node_id_ascii(search_id)));
		return (-1);
	}

	DFPRINTF(2, (stderr, "%s: sending ping to %s at %s:%d\n",
		     __func__,
		     dht_node_id_ascii(search_id),
		     addr_ntoa(&fid->addr), fid->port));
	
	/* Just ping the node - we want to know if it's happy */
	return (kad_rpc_ping(node, fid, NULL, NULL));
}

int
kad_dht_impl_store(void *node_data, u_char *keyid, size_t keylen,
    u_char *value, size_t vallen, void (*cb)(int, void *), void *cb_arg)
{
	struct kad_node *node = node_data;
	u_char hashed_keyid[SHA_DIGEST_LENGTH];

	if (keylen == sizeof(hashed_keyid)) {
		memcpy(hashed_keyid, keyid, sizeof(hashed_keyid));
	} else {
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, keyid, keylen);
		SHA1_Final(hashed_keyid, &ctx);
	}

	return (kad_impl_store(node, hashed_keyid, value, vallen, cb, cb_arg));
}

struct kad_dht_impl_find_ctx {
	struct dht_keyvalue *kv;
	void(*cb)(u_char *, size_t, void *);
	void *cb_arg;
};

void
kad_dht_impl_find_cb(int fd, short what, void *arg)
{
	struct kad_dht_impl_find_ctx *ctx = arg;

	(*ctx->cb)(ctx->kv->val, ctx->kv->vallen, ctx->cb_arg);

	free(ctx);
}

int
kad_dht_impl_find(void *node_data, u_char *keyid, size_t keylen,
    void (*cb)(u_char *, size_t, void *), void *cb_arg)
{
	struct dht_keyvalue *kv;
	struct kad_node *node = node_data;
	u_char hashed_keyid[SHA_DIGEST_LENGTH];

	if (keylen == sizeof(hashed_keyid)) {
		memcpy(hashed_keyid, keyid, sizeof(hashed_keyid));
	} else {
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, keyid, keylen);
		SHA1_Final(hashed_keyid, &ctx);
	}

	kv = dht_find_keyval(node->storage, hashed_keyid, sizeof(hashed_keyid));
	if (kv != NULL) {
		struct timeval tv;
		struct kad_dht_impl_find_ctx *ctx = NULL;

		if ((ctx =malloc(sizeof(struct kad_dht_impl_find_ctx))) == NULL)
			err(1, "%s: malloc", __func__);

		ctx->kv = kv;
		ctx->cb = cb;
		ctx->cb_arg = cb_arg;

		timerclear(&tv);
		event_once(-1, EV_TIMEOUT, kad_dht_impl_find_cb, ctx, &tv);
		return (0);
	}

	return (kad_impl_find_value(node, hashed_keyid, cb, cb_arg));
}


static void
kad_nodeidq_to_dht_nodeids(struct dht_node_id **pids, size_t *pnumids,
    struct kad_nodeidq *nodes, int num_nodes)
{
	struct kad_node_id *id;
	struct dht_node_id *ids;
	int off;

	ids = malloc(num_nodes * sizeof(struct dht_node_id));
	if (ids == NULL)
		err(1, "%s: malloc", __func__);

	off = 0;
	TAILQ_FOREACH(id, nodes, next) {
		ids[off].addr = id->addr;
		ids[off].port = id->port;
		memcpy(ids[off].id, id->id, sizeof(ids[off].id));

		if (++off == num_nodes)
			break;
	}

	*pids = ids;
	*pnumids = off;
}

/* Return a fully instantiated DHT object */

struct dht_node *
kad_make_dht(uint16_t port)
{
	struct dht_node *dht = dht_new(port);
	struct kad_node *node = kad_node_new(dht);
	dht_set_impl(dht, DHT_TYPE_KADEMLIA, &kad_dht_callbacks, node);

	/* Usually, we do not have to do that */
	kad_node_set_address(node, "127.0.0.1", port);

	return (dht);
}
