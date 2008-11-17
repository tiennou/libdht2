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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <assert.h>
#include <sha1.h>

#include <event.h>
#include <dnet.h>

#include "dht.h"
#include "dht_bits.h"
#include "dht_kademlia.h"

static int test_one_count;

void
Test_One_Ping_Reply(struct dht_rpc *rpc, struct evbuffer *evbuf, void *arg)
{
	if (++test_one_count == 2)
		event_loopexit(NULL);
}

void
Test_One_Sub(struct kad_node *node_kad, struct kad_node *two_node_kad)
{
	test_one_count = 0;

	/* Send ping from one to two */
	kad_rpc_ping(node_kad, &two_node_kad->myself,
	    Test_One_Ping_Reply, NULL);
	kad_rpc_ping(two_node_kad, &node_kad->myself,
	    Test_One_Ping_Reply, NULL);

	event_dispatch();
}

void
Test_One(struct kad_node *node[], int num)
{
	int i, j;

	for (j = 0; j < num; ++j) {
		/* Only first 50 nodes get much learning done */
		for (i = 0; i < 50 && i < num; ++i) {
			int off = arc4random() % num;
			if (off == i)
				continue;
			Test_One_Sub(node[i], node[off]);
		}
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
Test_Two_Find_Node_Reply(struct dht_rpc *rpc, struct evbuffer *evbuf, void *arg)
{
	struct kad_node *node = arg;
	struct kad_pkt_node_reply *pkt;
	size_t remaining;
	int i, last_distance = 0;

	pkt = (struct kad_pkt_node_reply *)(
		EVBUFFER_DATA(evbuf) + sizeof(struct kad_pkt));
	remaining = EVBUFFER_LENGTH(evbuf) - sizeof(struct kad_pkt);

	assert(remaining / sizeof(*pkt) == KAD_NODES_PER_BUCKET);

	fprintf(stderr, "Got %d nodes\n", remaining / sizeof(*pkt));
	for (i = 0; i < remaining / sizeof(*pkt); ++i) {
		struct addr addr;
		int distance = dht_bits_compare(pkt[i].node_id,
		    node->myself.id, SHA1_DIGESTSIZE);
		
		/* Make sure that we are increasing in distance */
		if (last_distance)
			assert(last_distance >= distance);
		last_distance = distance;

		addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS,
		    pkt[i].address, IP_ADDR_LEN);
		fprintf(stderr, "%d: %s %s:%d %d\n",
		    i, dht_node_id_ascii(pkt[i].node_id),
		    addr_ntoa(&addr), htons(pkt[i].port),
		    distance);
	}

	event_loopexit(NULL);
}

void
Test_Two(struct kad_node *node_kad, struct kad_node *two_node_kad)
{
	fprintf(stderr, "Trying to find %s\n",
	    dht_node_id_ascii(node_kad->myself.id));

	/* Send find node from one to two */
	kad_rpc_find_node(node_kad, &two_node_kad->myself,
	    node_kad->myself.id,
	    Test_Two_Find_Node_Reply, node_kad);

	event_dispatch();

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
Test_Three_Cb(struct kad_nodeidq *nodes, void *arg)
{
	struct kad_node_id *id;
	int i = 0;
	
	TAILQ_FOREACH(id, nodes, next) {
		fprintf(stderr, "%d. %s\n", ++i, dht_node_id_ascii(id->id));
	}

	/* Leaking memory */

	event_loopexit(NULL);
}

void
Test_Three(struct kad_node *node)
{
	kad_impl_lookup(node, node->myself.id, Test_Three_Cb, NULL);

	event_dispatch();
}

void
Test_Four_Cb(void *arg)
{
	struct kad_node *node = arg;

	fprintf(stderr, "%s: %s: knows about %d node\n", 
	    __func__,
	    dht_node_id_ascii(node->myself.id),
	    node->bucket_root->num_subtree_nodes);

	assert(node->bucket_root->num_subtree_nodes > 30);

	event_loopexit(NULL);
}

/* This is almost like a join */

void
Test_Four(struct kad_node *node)
{
	kad_node_refresh_all_buckets(node, NULL, Test_Four_Cb, node);

	event_dispatch();
}

void
Test_Five_Cb(int error, void *arg)
{
	struct kad_node *node = arg;

	assert(error == 0);
	fprintf(stderr, "%s: After JOIN, %s knows about %d node\n", 
	    __func__,
	    dht_node_id_ascii(node->myself.id),
	    node->bucket_root->num_subtree_nodes);

	assert(node->bucket_root->num_subtree_nodes > 30);

	event_loopexit(NULL);
}

void
Test_Five(struct kad_node *node, struct addr *addr, uint16_t port)
{
	fprintf(stderr, "Starting join for %s\n",
	    dht_node_id_ascii(node->myself.id));

	assert(kad_impl_join(node, addr, port, Test_Five_Cb, node) != -1);

	event_dispatch();
}

void
Test_Six_Cb(int res, void *arg)
{
	event_loopexit(NULL);
}

void
Test_Six(struct kad_node *node, char *text)
{
	u_char digest[SHA1_DIGESTSIZE];
	
	SHA1_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, text, strlen(text) + 1);
	SHA1_Final(digest, &ctx);

	assert(kad_impl_store(node, digest, text, strlen(text) + 1,
		   Test_Six_Cb, NULL) != -1);

	event_dispatch();
}

void
Test_Seven_Cb(u_char *data, size_t datlen, void *arg)
{
	struct timeval tv;

	assert(data != NULL);
	fprintf(stderr, "%s: got \"%s\"\n", __func__, data);

	/* So that our caching store can make progress */
	timerclear(&tv);
	tv.tv_sec = 3;
	event_loopexit(&tv);
}

void
Test_Seven(struct kad_node *node, char *text)
{
	u_char digest[SHA1_DIGESTSIZE];
	
	SHA1_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, text, strlen(text) + 1);
	SHA1_Final(digest, &ctx);

	assert(kad_impl_find_value(node, digest, Test_Seven_Cb, NULL) != -1);

	event_dispatch();
}

struct kad_node *
new_node(uint16_t port)
{
	extern struct dht_callbacks kad_dht_callbacks;

	struct dht_node *dht = dht_new(port);
	struct kad_node *node = kad_node_new(dht);
	dht_set_impl(dht, DHT_TYPE_KADEMLIA, &kad_dht_callbacks, node);

	/* Usually, we do not have to do that */
	kad_node_set_address(node, "127.0.0.1", port);

	return (node);
}

#define KAD_NODES	500

void
refresh_all(struct kad_node *node[])
{
	struct timeval tv;
	int i, j;

	for (j = 0; j < 10; ++j) {
		fprintf(stderr, "Refreshing batch %d\n", j);
		for (i = j*20; i < (j+1)*20 && i < KAD_NODES; ++i) {
			kad_node_refresh_all_buckets(node[i], NULL,
			    NULL, NULL);
		}

		timerclear(&tv);
		tv.tv_sec = 9;
		event_loopexit(&tv);

		event_dispatch();
	}
}

int
main(int argc, char **argv)
{
	extern int debug;
	int i, port_base = 5555;
	struct kad_node *node[KAD_NODES], *new_node_one, *new_node_two;

	/* Set some reasonable debug level */
	debug = 1;

	event_init();

	dht_init();

	/* Set up the nodes */
	for (i = 0; i < KAD_NODES; ++i) {
		node[i] = new_node(port_base + i);
	}

	Test_One(node, KAD_NODES);

	/* Runs find node on the other id */
	for (i = 0; i < 5; ++i) 
		Test_Two(node[i], node[i+1]);

	debug = 2;
	/* Pick an unlearned node */
	for (i = 0; i < 5; ++i)
		Test_Three(node[50 + i]);

	debug = 1;
	/* Let's refresh all the buckets for one node */
	for (i = 0; i < 5; ++i)
		Test_Four(node[50 + i]);

	new_node_one = new_node(port_base + KAD_NODES + 1);
	new_node_two = new_node(port_base + KAD_NODES + 2);

	/* Now, let a new node join the network */
	Test_Five(new_node_one, &node[0]->myself.addr, node[0]->myself.port);
	
	/* Have a new node, join with the latest node */
	Test_Five(new_node_two,
	    &new_node_one->myself.addr, new_node_one->myself.port);

	/* At this point, we need to store stuff, so refresh all nodes */
	debug = 0;
	refresh_all(node);
	debug = 1;

	/* Let's try to store something */
	Test_Six(new_node_one, "hello, how are you");
	Test_Six(new_node_one, "you are a sore loser!");

	/* Let's try to find it */
	Test_Seven(new_node_two, "hello, how are you");
	
	/* Let's try to find it again */
	Test_Seven(node[0], "hello, how are you");
	Test_Seven(node[0], "you are a sore loser!");

	fprintf(stderr, "OK\n");

	exit(0);
}
