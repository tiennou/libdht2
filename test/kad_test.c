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

#include <event.h>
#include <dnet.h>

#include "dht_bits.h"
#include "dht_kademlia.h"

#define KAD_TEST_NODES	1000

struct kad_node_id *
id_clone(struct kad_node_id *id)
{
	return (kad_node_id_new(&id->addr, id->port, id->id));
}

/* Verify that the prefix is the same for all of them */

void
verify(struct kad_bucket *bucket)
{
	if (bucket->child_one != NULL || bucket->child_zero != NULL) {
		verify(bucket->child_one);
		verify(bucket->child_zero);
	} else {
		struct kad_node_id *first = TAILQ_FIRST(&bucket->nodes);
		struct kad_node_id *tmp;

		int count = 0;
		TAILQ_FOREACH(tmp, &bucket->nodes, next) {
			int diff = dht_bits_compare(tmp->id, first->id,
			    SHA_DIGEST_LENGTH);
			count++;
			if (!diff)
				continue;

			if (diff <= bucket->level)
				errx(1, "%s: at level %d", 
				    __func__, bucket->level);
		}

		if (count != bucket->num_nodes)
			errx(1, "%s: bad node coun: %d != %d",
			    __func__, count, bucket->num_nodes);
	}
}

void
Test_One(void)
{
	struct kad_node *nodes[KAD_TEST_NODES];
	int i, j;

	fprintf(stderr, "Node insertion: ");

	/* 
	 * Just insert the nodes as they come along, splitting buckets
	 * as we go.
	 */
	for (i = 0; i < KAD_TEST_NODES; ++i) {
		fprintf(stderr, "%d ", i);
		fflush(stderr);
		nodes[i] = kad_node_new(NULL);
		for (j = 0; j < i; ++j) {
			kad_node_insert(nodes[i],
			    &nodes[j]->myself.addr,
			    nodes[j]->myself.port,
			    nodes[j]->myself.id);
			kad_node_insert(nodes[j],
			    &nodes[i]->myself.addr,
			    nodes[i]->myself.port,
			    nodes[i]->myself.id);
		}

		verify(nodes[i]->bucket_root);
	}
	fprintf(stderr, ": OK\n");
}

int
main(int argc, char **argv)
{

	event_init();

	Test_One();

	fprintf(stderr, "OK\n");

	exit(0);
}
