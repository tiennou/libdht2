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
#include <openssl/sha.h>
#include <assert.h>

#include <event.h>
#include <dnet.h>

#include "dht.h"
#include "dht_kademlia.h"
#include "dht_group.h"
#include "dht_group_message.gen.h"

#define GROUP_SIZE	40
#define PORT_BASE	40000

static int counter;
struct dht_group *node[GROUP_SIZE];
struct addr addr;

void
part_cb_done(struct dht_rpc *rpc, struct dht_group_msg_reply *reply, void *arg)
{
	static int count;
	struct dht_group *group = arg;
	char *channel_name;
	int error_code;
	char *error_reason;

	assert(reply != NULL);

	EVTAG_GET(reply, channel_name, &channel_name);
	EVTAG_GET(reply, error_code, &error_code);
	EVTAG_GET(reply, error_reason, &error_reason);

	fprintf(stderr, "%s: channel: %s -> %d - %s\n",
	    dht_node_id_ascii(dht_myid(group->dht)),
	    channel_name, error_code, error_reason);


	if (++count == 2) {
		struct timeval tv;
		/* We have just two parts - so quit shortly after they
		 * are done */
		timerclear(&tv);
		tv.tv_sec = 5;	/* exit the loop after 5 second */

		event_loopexit(&tv);
	}
}

void
part_cb(int fd, short what, void *arg)
{
	struct dht_group *group = arg;

	fprintf(stderr, "%s: trying to part from channel\n", __func__);

	dht_group_part_channel(group, "niels", part_cb_done, group);
}

void
privmsg_done(struct dht_rpc *rpc, struct dht_group_msg_reply *reply, void *arg)
{
	struct dht_group *group = arg;
	char *channel_name;
	int error_code;
	char *error_reason;
	struct timeval tv;

	if (reply == NULL)
		return;

	assert(!EVTAG_GET(reply, channel_name, &channel_name));
	assert(!EVTAG_GET(reply, error_code, &error_code));
	assert(!EVTAG_GET(reply, error_reason, &error_reason));

	fprintf(stderr, "%s: channel: %s -> %d - %s\n",
	    dht_node_id_ascii(dht_myid(group->dht)),
	    channel_name, error_code, error_reason);

	timerclear(&tv);
	tv.tv_usec = 500000L;
	event_once(-1, EV_TIMEOUT, part_cb, arg, &tv);
}

void
join_channel_done(struct dht_rpc *rpc,
    struct dht_group_msg_reply *reply, void *arg)
{
	static int count;
	struct dht_group *group = arg;
	char *channel_name;
	int error_code;
	char *error_reason;

	if (reply == NULL)
		return;

	EVTAG_GET(reply, channel_name, &channel_name);
	EVTAG_GET(reply, error_code, &error_code);
	EVTAG_GET(reply, error_reason, &error_reason);

	fprintf(stderr, "%s: channel: %s -> %d - %s\n",
	    dht_node_id_ascii(dht_myid(group->dht)),
	    channel_name, error_code, error_reason);

	if (++count == 3) {
		char *message_one = "hello how are you? we have not seen you.";
		char *message_two = "do you know rlorp? but you are just here";
		char *message_three = "i am not subscribed";
		/* Time to sent a private message */
		dht_group_privmsg(node[1], "niels",
		    message_one, strlen(message_one) + 1,
		    privmsg_done, node[1]);

		dht_group_privmsg(node[0], "niels",
		    message_two, strlen(message_two) + 1,
		    privmsg_done, node[0]);

		dht_group_privmsg(node[3], "niels",
		    message_three, strlen(message_three) + 1, 
		    privmsg_done, node[3]);
	}
}

void
join_channel_cb(int fd, short what, void *arg)
{
	extern int debug;
	struct dht_group *group = arg;

	debug = 1;

	fprintf(stderr, "Trying to join channel....\n");

	assert(dht_group_join_channel(group, "niels",
		   join_channel_done, group) == 0);
}

void
join_done_cb(int failure, void *arg)
{
	struct dht_group *group = arg;

	if (failure)
		errx(1, "Join failed");

	fprintf(stderr, "DHT node %p joined\n", group->dht);
}

void
start_join_cb(int fd, short what, void *arg)
{
	/* Try to join the DHT network */
	dht_join(node[counter + 1]->dht, &addr, PORT_BASE + counter,
	    join_done_cb, node[counter + 1]);

	/* Make it ready for the next one */
	counter++;
}

void
TestOne(void)
{
	struct event ev_timeout[GROUP_SIZE];
	struct event ev_join[GROUP_SIZE];
	struct timeval tv, add_tv;
	int i;

	timerclear(&tv);
	timerclear(&add_tv);
	add_tv.tv_usec = 200000L;
	for (i = 0; i < GROUP_SIZE; ++i) {
		if (i == 0)
			continue;
		
		/* Make them join the DHT */
		evtimer_set(&ev_timeout[i], start_join_cb, NULL);

		timeradd(&tv, &add_tv, &tv);
		evtimer_add(&ev_timeout[i], &tv);
	}

	/* The first node will try to join a channel */
	evtimer_set(&ev_join[0], join_channel_cb, node[0]);

	/* Make it one second after everybody has joined */
	timerclear(&add_tv);
	add_tv.tv_sec = 1;
	timeradd(&tv, &add_tv, &tv);
	evtimer_add(&ev_join[0], &tv);

	/* The second node will join afterwards */
	evtimer_set(&ev_join[1], join_channel_cb, node[1]);

	/* Make it one second after everybody has joined */
	timerclear(&add_tv);
	add_tv.tv_sec = 1;
	timeradd(&tv, &add_tv, &tv);
	evtimer_add(&ev_join[1], &tv);

	/* The third node will join afterwards */
	evtimer_set(&ev_join[2], join_channel_cb, node[2]);

	timerclear(&add_tv);
	add_tv.tv_sec = 1;
	add_tv.tv_usec = 500000L;
	timeradd(&tv, &add_tv, &tv);
	evtimer_add(&ev_join[2], &tv);

	event_dispatch();
}

void
join_channel_done_illegal(struct dht_rpc *rpc,
    struct dht_group_msg_reply *reply, void *arg)
{
	struct dht_group *group = arg;
	char *channel_name;
	int error_code;
	char *error_reason;

	if (reply == NULL)
		return;

	EVTAG_GET(reply, channel_name, &channel_name);
	EVTAG_GET(reply, error_code, &error_code);
	EVTAG_GET(reply, error_reason, &error_reason);

	fprintf(stderr, "%s: channel: %s -> %d - %s\n",
	    dht_node_id_ascii(dht_myid(group->dht)),
	    channel_name, error_code, error_reason);

	assert(error_code = ERR_ILLEGALNAME);

	event_loopexit(NULL);
}

void
TestTwo(void)
{
	/* Have one node join an illegal channel name */
	assert(dht_group_join_channel(node[0], "0xillegal",
		   join_channel_done_illegal, node[0]) == 0);

	event_dispatch();
}

void
TestSeqNr(void)
{
	int i;
	char *src_id = dht_myid(node[0]->dht);
	fprintf(stderr, "Blowing away sequence numbers....");

	assert(dht_group_new_seqnr(node[1], src_id, 0) == 0);
	assert(dht_group_new_seqnr(node[1], src_id, 0) == -1);

	for (i = 1; i < 100; ++i) {
		assert(dht_group_new_seqnr(node[1], src_id, i) == 0);
	}

	for (; i < 200; i += 2) {
		assert(dht_group_new_seqnr(node[1], src_id, i + 1) == 0);
		assert(dht_group_new_seqnr(node[1], src_id, i) == 0);
	}

	assert(dht_group_new_seqnr(node[1], src_id, i + 20) == 0);
	assert(dht_group_new_seqnr(node[1], src_id, i + 17) == 0);
	assert(dht_group_new_seqnr(node[1], src_id, i + 15) == 0);
	for (; i < 215; i++) {
		assert(dht_group_new_seqnr(node[1], src_id, i) == 0);
	}

	assert(dht_group_new_seqnr(node[1], src_id, i + 5) == -1);

	/* Make the sequence number useful again */
	node[0]->seqnr = 1000;

	fprintf(stderr, "OK\n");
}

int
receive_msg(struct dht_group *group,
    char *channel_name, uint8_t *src_id,
    uint8_t *message, uint32_t message_length,
    void *cb_arg)
{
	fprintf(stderr, "%s: %s: %s\n",
	    channel_name, dht_node_id_ascii(src_id), message);

	return (1);	/* nobody else get this message */
}

int
main(int argc, char **argv)
{
	extern int debug;
	int i;

	/* Some simple debugging */
	debug = 0;

	event_init();

	dht_init();

	addr_pton("127.0.0.1", &addr);

	/* Set up the nodes */
	for (i = 0; i < GROUP_SIZE; ++i) {
		struct dht_node *dht = kad_make_dht(PORT_BASE + i);
		assert(dht != NULL);
		node[i] = dht_group_new(dht);
		dht_group_register_cb(node[i], receive_msg, NULL);
		assert(node[i] != NULL);
	}

	TestSeqNr();
	TestOne();
	TestTwo();

	fprintf(stderr, "OK\n");

	exit(0);
}
