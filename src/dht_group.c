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

#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <assert.h>

#include <dnet.h>
#include <event.h>

#include "dht.h"
#include "dht_bits.h"
#include "dht_group.h"
#include "dht_group_message.gen.h"

/* Prototypes */
int dht_group_send_rpc(struct dht_group *group,
    struct dht_node_id *id,
    u_char *rpc_id, struct dht_group_msg *msg,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *),
    void *cb_arg);

static struct evbuffer *_tmp;
static struct evbuffer *_tmp_compress;

static struct dht_group_error {
	int code;
	const char *message;
} errors[] = {
	{ ERR_INTERNAL, "internal error" },
	{ ERR_NOTSUBSCRIBED, "not subscribed to channel" },
	{ ERR_DUPLICATE, "duplicate message id" },
	{ ERR_UNKNOWNCHANNEL, "unknown channel name" },
	{ ERR_ALREADYSUBSCRIBED, "already subscribed to channel" },
	{ ERR_ILLEGALNAME, "illegal channel name" },
	{ ERR_MAX_ERRS, NULL }
};

const char *
dht_group_err(int code)
{
	struct dht_group_error *err = &errors[0];

	while (err->message != NULL) {
		if (err->code == code)
			return (err->message);
		err++;
	}

	return (NULL);
}

/* Sequence number management */
int
dht_seqnr_compare(const struct dht_group_seqnr *a,
    const struct dht_group_seqnr *b)
{
	return (memcmp(a->id, b->id, SHA_DIGEST_LENGTH));
}

SPLAY_PROTOTYPE(group_seqnr_tree, dht_group_seqnr, node, dht_seqnr_compare);
SPLAY_GENERATE(group_seqnr_tree, dht_group_seqnr, node, dht_seqnr_compare);

/*
 * Check if we have seen the sequence number from this source already.
 * This is a potential source of DoS.  We need to provide a mechanism
 * for a client to purge this information.  Maybe also propagate join
 * time?
 */

int
dht_group_new_seqnr(struct dht_group *group, u_char *src_id, uint32_t seqnr)
{
	struct dht_group_seqnr *gsq, tmp;
	int off;

	memcpy(tmp.id, src_id, sizeof(tmp.id));
	gsq = SPLAY_FIND(group_seqnr_tree, &group->root_seqnr, &tmp);
	if (gsq == NULL) {
		/* We do not know this number - maybe we need to clean up */
		gsq = calloc(1, sizeof(struct dht_group_seqnr));
		if (gsq == NULL) {
			warn("%s: calloc", __func__);
			return (-1);
		}

		memcpy(gsq->id, src_id, sizeof(gsq->id));
		gettimeofday(&gsq->tv_last_active, NULL);

		SPLAY_INSERT(group_seqnr_tree, &group->root_seqnr, gsq);
		TAILQ_INSERT_TAIL(&group->head_seqnr, gsq, next);

		gsq->last_seen = seqnr;
		return (0);
	}

	/* We already know about this one */
	if (seqnr <= gsq->last_seen)
		return (-1);

	/* Cover the case, where the next sequence number is above window */
	off = seqnr - gsq->last_seen - 1;
	if (off >= 32) {
		gsq->last_seen = seqnr;
		gsq->current_window = 0;
		goto out;
	}

	/* Well now we need to check if the bit is set already */
	if (gsq->current_window & (1 << off)) {
		return (-1);
	}

	/* OK, set the bit */
	gsq->current_window |= 1 << off;

	/* Let's catch up on the ones that we might have seen already */
	while (gsq->current_window & 0x1) {
		gsq->last_seen++;
		gsq->current_window >>= 1;
	}

 out:
	/* Update the time stamp */
	gettimeofday(&gsq->tv_last_active, NULL);

	/* Put the fresh srcid at the bottom of the stack */
	TAILQ_REMOVE(&group->head_seqnr, gsq, next);
	TAILQ_INSERT_TAIL(&group->head_seqnr, gsq, next);

	/* Wow. We are good */
	return (0);
}


/* Channel management */

int
dht_channel_compare(const struct dht_group_channel *a,
    const struct dht_group_channel *b)
{
	return (strcmp(a->channel_name, b->channel_name));
}

SPLAY_PROTOTYPE(group_channel_tree, dht_group_channel,
    node, dht_channel_compare);
SPLAY_GENERATE(group_channel_tree, dht_group_channel,
    node, dht_channel_compare);

int
dht_subscriber_compare(const struct dht_group_subscriber *a,
    const struct dht_group_subscriber *b)
{
	return (memcmp(a->id.id, b->id.id, sizeof(a->id.id)));
}

SPLAY_PROTOTYPE(subscribe_tree, dht_group_subscriber,
    node, dht_subscriber_compare);
SPLAY_GENERATE(subscribe_tree, dht_group_subscriber,
    node, dht_subscriber_compare);

/*
 * Refreshes the channel with the parents if there are still subscribers.
 */

int
dht_group_channel_refresh(struct dht_group *group,
    struct dht_group_channel *channel)
{
	DFPRINTF(2, (stderr, "%s: refreshing channel \"%s\"\n",
		     __func__, channel->channel_name));

	if (!(channel->flags & DHT_CHANNEL_SUBSCRIBED) &&
	    SPLAY_ROOT(&channel->subscribers) == NULL) {
		DFPRINTF(1, (stderr, "%s: empty channel \"%s\" on refresh?\n",
			     __func__, channel->channel_name));
		/* XXX - send a part message here? */
		dht_channel_free(channel);
		return (-1);
	}

	/* Refresh the join of this channel */
	dht_group_internal_join_channel(
		group, channel->channel_name,
		0 /* self join */,
		NULL, NULL);

	return (0);
}

void
dht_group_channel_purge(struct dht_group *group,
    struct dht_group_channel *channel)
{
	struct timeval tv, now;
	struct dht_group_subscriber *gs, *next;

	DFPRINTF(2, (stderr, "%s: remove old subscribers \"%s\"\n",
		     __func__, channel->channel_name));

	gettimeofday(&now, NULL);

	for (gs = SPLAY_MIN(subscribe_tree, &channel->subscribers);
	    gs != NULL; gs = next) {
		next = SPLAY_NEXT(subscribe_tree, &channel->subscribers, gs);

		timersub(&now, &gs->tv_last_heard, &tv);
		if (tv.tv_sec < 2*DHT_GROUP_CHANNEL_REFRESH)
			continue;

		/* This entry has expired */
		DFPRINTF(2, (stderr, "%s: removing %s from \"%s\"\n",
			     __func__,
			     dht_node_id_ascii(gs->id.id),
			     channel->channel_name));

		SPLAY_REMOVE(subscribe_tree, &channel->subscribers, gs);

		free(gs);
	}
}

void
dht_group_channel_maintain(int fd, short what, void *arg)
{
	struct dht_group_channel *channel = arg;
	struct dht_group *group = channel->parent;
	struct timeval tv;

	/* Remove old losers */
	dht_group_channel_purge(group, channel);
	
	/* Refresh our subscription */
	if (dht_group_channel_refresh(group, channel) == -1) {
		/* Channel no longer exists */
		return;
	}
	
	/* Re-add the event */
	timerclear(&tv);
	tv.tv_sec = DHT_GROUP_CHANNEL_REFRESH;
	evtimer_add(&channel->ev_refresh, &tv);
}

struct dht_group_channel *
dht_channel_find(struct dht_group *group, char *channel_name)
{
	struct dht_group_channel tmp;

	tmp.channel_name = channel_name;
	return (SPLAY_FIND(group_channel_tree, &group->channels, &tmp));
}

struct dht_group_channel *
dht_channel_new(struct dht_group *group, char *channel_name)
{
	struct dht_group_channel *channel, tmp;
	struct timeval tv;

	DFPRINTF(3, (stderr, "%s: trying to create channel \"%s\"\n",
		     __func__, channel_name));
	tmp.channel_name = channel_name;
	if (SPLAY_FIND(group_channel_tree, &group->channels, &tmp) != NULL)
		return (NULL);

	channel = calloc(1, sizeof(struct dht_group_channel));
	if (channel == NULL)
		err(1, "%s: calloc", __func__);

	channel->parent = group;
	SPLAY_INIT(&channel->subscribers);

	if ((channel->channel_name = strdup(channel_name)) == NULL)
		err(1, "%s: calloc", __func__);

	SPLAY_INSERT(group_channel_tree, &group->channels, channel);

	evtimer_set(&channel->ev_refresh, dht_group_channel_maintain, channel);

	/* We only refresh on real channel names */
	if (!strncasecmp(channel_name, "0x", 2)) {
		timerclear(&tv);
		tv.tv_sec = DHT_GROUP_CHANNEL_REFRESH;
		evtimer_add(&channel->ev_refresh, &tv);
	}

	return (channel);
}

void
dht_channel_free(struct dht_group_channel *channel)
{
	struct dht_group *group = channel->parent;
	struct dht_group_subscriber *tmp;

	event_del(&channel->ev_refresh);

	SPLAY_REMOVE(group_channel_tree, &group->channels, channel);

	/* Remove all subscribers */
	while((tmp = SPLAY_ROOT(&channel->subscribers)) != NULL) {
		SPLAY_REMOVE(subscribe_tree, &channel->subscribers, tmp);
		free(tmp);
	}

	free(channel->channel_name);
	free(channel);
}

/*
 * Initializes the global members for the group protocol
 */

void
dht_group_init()
{
	if ((_tmp = evbuffer_new()) == NULL)
		err(1, "%s: calloc", __func__);

	if ((_tmp_compress = evbuffer_new()) == NULL)
		err(1, "%s: calloc", __func__);
}

/*
 * Called by the generic DHT network layer
 */

void
dht_group_read_cb(struct addr *addr, uint16_t port,
    u_char *data, size_t datlen, void *arg)
{
	struct dht_group_msg_join *msg_join = NULL;
	struct dht_group_msg_privmsg *msg_privmsg = NULL;
	struct dht_group_msg_part *msg_part = NULL;
	struct dht_group *group = arg;
	struct dht_group_pkt *pkt = NULL;
	struct dht_group_msg *msg = NULL;
	struct dht_rpc *rpc;
	int need_msg_free = 0;
	uint8_t *dst_id;

	if ((pkt = dht_group_pkt_new()) == NULL)
		return;

	evbuffer_drain(_tmp, -1);
	evbuffer_add(_tmp, data, datlen);

	if (dht_group_pkt_unmarshal(pkt, _tmp) == -1) {
		DFPRINTF(2,
		    (stderr, "%s: received bad GROUP packet from %s:%d\n",
			__func__, addr_ntoa(addr), port));
		dht_group_pkt_free(pkt);
		return;
	}

	EVTAG_GET(pkt, dst_id, &dst_id);

	if (memcmp(dst_id, dht_myid(group->dht), SHA_DIGEST_LENGTH)) {
		DFPRINTF(3,
		    (stderr,
			"%s: received packet for %s which is not me\n",
			__func__, dht_node_id_ascii(dst_id)));
		return;
	}

	if (EVTAG_HAS(pkt, compress)) {
		uint8_t *cdata;
		uint32_t cdatalen;

		EVTAG_GET(pkt, compress, &cdata, &cdatalen);
		evbuffer_drain(_tmp_compress, -1);
		evbuffer_add(_tmp_compress, cdata, cdatalen);

		if (dht_decompress(_tmp_compress) == -1) {
			DFPRINTF(1, (stderr, "%s: failed to decompress "
				     "message from: %s:%d\n",
				     __func__, addr_ntoa(addr), port));
			goto error;
		}

		if ((msg = dht_group_msg_new()) == NULL)
			goto error;

		need_msg_free = 1;

		if (dht_group_msg_unmarshal(msg, _tmp_compress) == -1) {
			DFPRINTF(1, (stderr, "%s: failed to decode "
				     "GROUP message from: %s:%d\n",
				     __func__, addr_ntoa(addr), port));
			goto error;
		}
	} else if (EVTAG_HAS(pkt, message)) {
		EVTAG_GET(pkt, message, &msg);
	} else {
		DFPRINTF(1, (stderr,
			     "%s: message without payload from: %s:%d\n",
			     __func__, addr_ntoa(addr), port));
		goto error;
	}

	/*
	 * Now let's see if this is an RPC that we should know about.
	 */
	if (EVTAG_HAS(msg, reply)) {
		uint8_t *rpc_id;
		EVTAG_GET(pkt, rpc_id, &rpc_id);
		rpc = dht_rpc_find(&group->rpcs, rpc_id);
		if (rpc != NULL) {
			struct dht_group_msg_reply *reply;
			EVTAG_GET(msg, reply, &reply);
			if (rpc->cb)
				(*rpc->cb)(rpc, reply, rpc->cb_arg);
			dht_rpc_remove(&group->rpcs, rpc);
		} else {
			DFPRINTF(1, 
			    (stderr, "%s: unknown rpc id from %s at %s:%d\n",
				__func__, 
				dht_node_id_ascii(dst_id),
				addr_ntoa(addr), port));
		}
		dht_group_msg_free(msg);
		return;
	}

	if (EVTAG_HAS(msg, join)) {
		EVTAG_GET(msg, join, &msg_join);
		dht_group_handle_join(group, addr, port, pkt, msg_join);
	} else if (EVTAG_HAS(msg, privmsg)) {
		EVTAG_GET(msg, privmsg, &msg_privmsg);
		dht_group_handle_privmsg(group, addr, port, pkt, msg_privmsg);
	} else if (EVTAG_HAS(msg, part)) {
		EVTAG_GET(msg, part, &msg_part);
		dht_group_handle_part(group, addr, port, pkt, msg_part);
	} else {
		DFPRINTF(1, (stderr, "%s: no command in message\n", __func__));
	}

 error:
	if (pkt != NULL)
		dht_group_pkt_free(pkt);
	if (need_msg_free && msg != NULL)
		dht_group_msg_free(msg);

}

/* Registers our application layer callback with the DHT */

int
dht_group_register(struct dht_group *group)
{
	int res;

	res = dht_register_type(group->dht, DHT_TYPE_GROUP,
	    dht_group_read_cb, group);

	return (res);
}

struct dht_group *
dht_group_new(struct dht_node *dht)
{
	struct dht_group *group = NULL;
	struct dht_group_channel *channel = NULL;
	char myidasc[SHA_DIGEST_LENGTH*2+3];

	if ((group = calloc(1, sizeof(struct dht_group))) == NULL)
		err(1, "%s: calloc", __func__);

	/* XXX - Do we want to have callbacks per channel? */
	group->dht = dht;

	TAILQ_INIT(&group->callbacks);
	
	gettimeofday(&group->tv_create, NULL);

	if (dht_group_register(group) == -1) {
		dht_group_free(group);
		return (NULL);
	}

	SPLAY_INIT(&group->rpcs.rpcs);
	SPLAY_INIT(&group->channels);

	SPLAY_INIT(&group->root_seqnr);
	TAILQ_INIT(&group->head_seqnr);

	dht_bits_bin2hex(myidasc, dht_myid(group->dht), SHA_DIGEST_LENGTH);

	/*
	 * Subscribe ourselves to our own channel.  Nobody else can join
	 * this channel.  It can be used for "private" communication.
	 */
	channel = dht_channel_new(group, myidasc);
	assert(channel != NULL);
	channel->flags |= DHT_CHANNEL_SUBSCRIBED;

	return (group);
}

void
dht_group_free(struct dht_group *group)
{
    dht_free(group->dht);
    /* TODO: Free rpcs, channels, seqnrs */
	free(group);
}

void
dht_group_register_cb(struct dht_group *group, message_cb cb, void *cb_arg)
{
	struct dht_group_cb *group_cb = calloc(1, sizeof(struct dht_group_cb));
	assert(group_cb != NULL);

	group_cb->cb = cb;
	group_cb->cb_arg = cb_arg;

	TAILQ_INSERT_TAIL(&group->callbacks, group_cb, next);
}

/*
 * Callback when the internal join is done - we could tell kids here
 * if we failed to join upstream.
 */

void
dht_group_handle_join_cb(struct dht_rpc *rpc,
    struct dht_group_msg_reply *reply, void *arg)
{
	/* XXX - do something here */
}

/* Parses a join message */

void
dht_group_handle_join(struct dht_group *group,
    struct addr *addr, uint16_t port,
    struct dht_group_pkt *pkt,
    struct dht_group_msg_join *msg_join)
{
	struct dht_group_msg *msg = NULL;
	struct dht_group_msg_reply *reply = NULL;
	struct dht_group_subscriber *subscriber, stmp;
	struct dht_group_channel *channel;
	struct dht_node_id tmp;
	int error_code = 0;
	uint8_t *src_id, *rpc_id;
	char *channel_name = NULL;
	char *error_reason = "success";

	EVTAG_GET(msg_join, channel_name, &channel_name);
	DFPRINTF(1, (stderr,
		     "%s: %s got join for channel \"%s\" from %s:%d\n",
		     __func__,
		     dht_node_id_ascii(dht_myid(group->dht)),
		     channel_name, addr_ntoa(addr), port));

	channel = dht_channel_find(group, channel_name);
	if (channel == NULL) {
		/* We don't have the channel, so we need to create it */
		if (dht_group_internal_join_channel(group,
			channel_name,
			0 /* self join */,
			dht_group_handle_join_cb, NULL) == -1) {
			error_code = 1;
			error_reason = "could not join upstream";
			goto out;
		}

		channel = dht_channel_find(group, channel_name);
		assert(channel != NULL);
	}

	/* Check if this id is already subscribed */
	EVTAG_GET(pkt, src_id, &src_id);
	memcpy(stmp.id.id, src_id, sizeof(stmp.id.id));
	subscriber = SPLAY_FIND(subscribe_tree, &channel->subscribers, &stmp);

	/* This node is already subscribed */
	if (subscriber != NULL) {
		gettimeofday(&subscriber->tv_last_heard, NULL);
		error_code = 0;
		error_reason = "subscription refreshed";
		goto out;
	}

	/* This is a new client. Weeh. */
	subscriber = malloc(sizeof(struct dht_group_subscriber));
	if (subscriber == NULL) {
		error_code = 1;
		error_reason = "out of memory";
		goto out;
	}

	/*
	 * Initalize the subscriber and remember the last time we heard
	 * from it.  If we do not hear from a client in a while we kick
	 * him out.
	 */
	memcpy(subscriber->id.id, src_id, sizeof(subscriber->id.id));
	subscriber->id.addr = *addr;
	subscriber->id.port = port;
	gettimeofday(&subscriber->tv_last_heard, NULL);

	SPLAY_INSERT(subscribe_tree, &channel->subscribers, subscriber);

	error_code = 0;
	error_reason = "successfully subscribed";

 out:
	if ((msg = dht_group_msg_new()) == NULL)
		return;

	assert(!EVTAG_GET(msg, reply, &reply));
	assert(!EVTAG_ASSIGN(reply, channel_name, channel_name));
	assert(!EVTAG_ASSIGN(reply, error_code, error_code));
	assert(!EVTAG_ASSIGN(reply, error_reason, error_reason));

	/* Temporary id */
	tmp.addr = *addr;
	tmp.port = port;
	memcpy(tmp.id, src_id, sizeof(tmp.id));

	EVTAG_GET(pkt, rpc_id, &rpc_id);
	dht_group_send_rpc(group, &tmp, rpc_id,
	    msg, NULL /* cb */, NULL /* cb_arg */);

	dht_group_msg_free(msg);
}

/* Parses a priv message */

void
dht_group_handle_privmsg(struct dht_group *group,
    struct addr *addr, uint16_t port,
    struct dht_group_pkt *pkt,
    struct dht_group_msg_privmsg *msg_privmsg)
{
	struct dht_group_msg *msg = NULL;
	struct dht_group_msg_reply *reply = NULL;
	struct dht_node_id tmp;
	uint8_t *msg_src_id, *pkt_src_id, *rpc_id, *message;
	char *channel_name;
	const char *error_reason;
	int error_code;
	uint32_t seqnr, message_length, up;
	int res;

	EVTAG_GET(pkt, src_id, &pkt_src_id);
	EVTAG_GET(msg_privmsg, src_id, &msg_src_id);
	EVTAG_GET(msg_privmsg, up, &up);
	EVTAG_GET(msg_privmsg, seqnr, &seqnr);
	EVTAG_GET(msg_privmsg, channel_name, &channel_name);
	EVTAG_GET(msg_privmsg, message, &message, &message_length);
	
	DFPRINTF(2, (stderr,
		     "%s: %s got privmsg %d for channel \"%s\" from %s:%d\n",
		     __func__,
		     dht_node_id_ascii(dht_myid(group->dht)),
		     seqnr, channel_name,
		     addr_ntoa(addr), port));

	/*
	 * We just need to propagate the message to other subscribers.
	 * XXX - maybe have a callback to deal with error situations.
	 */
	res = dht_group_propagate_privmsg(group,
	    msg_src_id, pkt_src_id, up,
	    seqnr, channel_name, message, message_length,
	    NULL /* cb */, NULL /* cb_arg */);

	evbuffer_drain(_tmp, -1);
	if (res == -1) {
		error_code = ERR_INTERNAL;
		error_reason = dht_group_err(error_code);
	} else {
		error_code = 0;
		error_reason = "success";
	}

	if ((msg = dht_group_msg_new()) == NULL)
		return;

	assert(!EVTAG_GET(msg, reply, &reply));
	assert(!EVTAG_ASSIGN(reply, channel_name, channel_name));
	assert(!EVTAG_ASSIGN(reply, error_code, error_code));
	assert(!EVTAG_ASSIGN(reply, error_reason, error_reason));

	/* Temporary id */
	tmp.addr = *addr;
	tmp.port = port;
	memcpy(tmp.id, pkt_src_id, sizeof(tmp.id));

	assert(!EVTAG_GET(pkt, rpc_id, &rpc_id));
	dht_group_send_rpc(group, &tmp, rpc_id,
	    msg, NULL /* cb */, NULL /* cb_arg */);

	if (msg != NULL)
		dht_group_msg_free(msg);
}

void
dht_group_handle_part(struct dht_group *group,
    struct addr *addr, uint16_t port,
    struct dht_group_pkt *pkt,
    struct dht_group_msg_part *msg_part)
{
	struct dht_group_msg *msg = NULL;
	struct dht_group_msg_reply *reply = NULL;
	struct dht_group_subscriber *subscriber, stmp;
	struct dht_group_channel *channel;
	struct dht_node_id tmp;
	int error_code = 0;
	uint8_t *src_id, *rpc_id;
	char *channel_name = NULL;
	const char *error_reason = "success";

	EVTAG_GET(msg_part, channel_name, &channel_name);
	DFPRINTF(1, (stderr,
		     "%s: %s got part for channel \"%s\" from %s:%d\n",
		     __func__,
		     dht_node_id_ascii(dht_myid(group->dht)),
		     channel_name, addr_ntoa(addr), port));

	channel = dht_channel_find(group, channel_name);
	if (channel == NULL) {
		/* We don't have the channel, so we cant part the node */
		error_code = ERR_UNKNOWNCHANNEL;
		error_reason = dht_group_err(error_code);
		goto out;
	}

	/* Check if this id is already subscribed */
	EVTAG_GET(pkt, src_id, &src_id);
	memcpy(stmp.id.id, src_id, sizeof(stmp.id.id));
	subscriber = SPLAY_FIND(subscribe_tree, &channel->subscribers, &stmp);

	/* This node is not subscribed */
	if (subscriber == NULL) {
		error_code = ERR_NOTSUBSCRIBED;
		error_reason = dht_group_err(error_code);
		goto out;
	}

	/* Remove the subscriber from the tree */
	SPLAY_REMOVE(subscribe_tree, &channel->subscribers, subscriber);
	free(subscriber);

	/* See if we need to leave this channel */
	/* XXX - check error code? */
	dht_group_internal_part_channel(group, channel, NULL, NULL);

	error_code = 0;
	error_reason = "successfully unsubscribed";

 out:
	if ((msg = dht_group_msg_new()) == NULL)
		return;

	assert(!EVTAG_GET(msg, reply, &reply));
	assert(!EVTAG_ASSIGN(reply, channel_name, channel_name));
	assert(!EVTAG_ASSIGN(reply, error_code, error_code));
	assert(!EVTAG_ASSIGN(reply, error_reason, error_reason));

	/* Temporary id */
	tmp.addr = *addr;
	tmp.port = port;
	memcpy(tmp.id, src_id, sizeof(tmp.id));

	EVTAG_GET(pkt, rpc_id, &rpc_id);
	dht_group_send_rpc(group, &tmp, rpc_id,
	    msg, NULL /* cb */, NULL /* cb_arg */);

	if (msg != NULL)
		dht_group_msg_free(msg);
}

/*
 * Functions to join a channel.
 */

struct dht_group_join_channel_ctx {
	struct dht_group *group;
	char *channel_name;

	int num_outstanding;
	int num_success;

	void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *);
	void *cb_arg;
};

void
dht_group_rpc_join_cb(struct dht_rpc *rpc, 
    struct dht_group_msg_reply *reply, void *arg)
{
	struct dht_group_msg_reply *inner_reply = NULL;
	struct dht_group_join_channel_ctx *ctx = arg;
	struct dht_group *group = ctx->group;
	char *error_reason;
	uint32_t error_code;

	ctx->num_outstanding--;

	/* XXX - something here */
	if (reply == NULL) {
		assert(rpc != NULL);
		/* Ask for liveness test */
		dht_ping(group->dht, rpc->rpc_dst);
		goto error;
	}

	EVTAG_GET(reply, error_code, &error_code);
	EVTAG_GET(reply, error_reason, &error_reason);
	DFPRINTF(1, (stderr, "%s: got %d - %s\n", __func__,
		     error_code, error_reason));

	if (!error_code)
		ctx->num_success++;

error:
	if (ctx->num_outstanding)
		return;

	if (ctx->num_success) {
		inner_reply = dht_group_make_msg_reply(
			ctx->channel_name, 0, "success");
	} else {
		inner_reply = dht_group_make_msg_reply(
			ctx->channel_name, 1, "failure");
	}

	if (inner_reply != NULL) {
		if (ctx->cb != NULL)
			(*ctx->cb)(NULL, inner_reply, ctx->cb_arg);
		dht_group_msg_reply_free(inner_reply);
	}

	free(ctx->channel_name);
	free(ctx);
}

/* 
 * External interface:  send a message to a channel.
 */

int
dht_group_privmsg(struct dht_group *group, char *channel_name, 
    uint8_t *message, uint32_t message_length,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *),
    void *cb_arg)
{
	struct dht_group_channel *channel;

	if (group->flags & DHT_GROUP_FLAG_ENFORCE_CHANNEL) {
		channel = dht_channel_find(group, channel_name);
		if (channel == NULL ||
		    !(channel->flags & DHT_CHANNEL_SUBSCRIBED)) {
			DFPRINTF(1, (stderr,
				     "%s: not subscribed to channel \"%s\"\n",
				     __func__, channel_name));
			return (-1);
		}
	}

	return (dht_group_propagate_privmsg(group,
		    dht_myid(group->dht),
		    NULL /* relay id */,
		    1 /* up */,
		    group->seqnr++, channel_name, message, message_length,
		    cb, cb_arg));
}

void
dht_group_msg_timeout_cb(struct dht_rpc *rpc,
    struct dht_group_msg_reply *reply, void *cb_arg)
{
	struct dht_group *group = cb_arg;

	if (reply == NULL) {
		/* The message timed out */
		assert(rpc != NULL);
		
		/* Send a ping to the node to check if it's still there */
		dht_ping(group->dht, rpc->rpc_dst);
	}
}

int		       
dht_group_propagate_privmsg(struct dht_group *group,
    u_char *src_id, u_char *relay_id, uint8_t up, uint32_t seqnr,
    char *channel_name, uint8_t *message, uint32_t message_length,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *), void *cb_arg)
{
	struct dht_node_id *ids;
	struct dht_group_msg_reply *reply = NULL;
	struct dht_group_channel *channel;
	struct dht_group_subscriber *subscriber;
	size_t numids;
	int i, num_sent, num_success;

	/* First of all figure out if we received this ID already */
	if (dht_group_new_seqnr(group, src_id, seqnr) == -1) {
		DFPRINTF(2, (stderr,
			     "%s: got duplicate message id %d from %s on %s\n",
			     __func__,
			     seqnr, dht_node_id_ascii(src_id), channel_name));

		reply = dht_group_make_msg_reply(channel_name,
		    ERR_DUPLICATE, dht_group_err(ERR_DUPLICATE));
		if (reply != NULL)
			dht_group_rpc_delay_callback(reply, cb, cb_arg);
		return (0);
	}

	channel = dht_channel_find(group, channel_name);
	if (group->flags & DHT_GROUP_FLAG_ENFORCE_CHANNEL) {
		if (channel == NULL) {
			DFPRINTF(1, (stderr,
				     "%s: unknown channel name \"%s\" "
				     "from %s\n",
				     __func__,
				     channel_name, dht_node_id_ascii(src_id)));
			
			reply = dht_group_make_msg_reply(channel_name,
			    ERR_UNKNOWNCHANNEL,
			    dht_group_err(ERR_UNKNOWNCHANNEL));
			if (reply != NULL)
				dht_group_rpc_delay_callback(reply,
				    cb, cb_arg);
			return (0);
		}
	}

	/* 
	 * The relay ID should better be a subscriber if the message is
	 * travelling from the bottom to the top.
	 */
	if (relay_id != NULL && channel != NULL && up) {
		struct dht_group_subscriber stmp;

		memcpy(stmp.id.id, relay_id, sizeof(stmp.id.id));
		subscriber = SPLAY_FIND(subscribe_tree,
		    &channel->subscribers, &stmp);

		if (subscriber == NULL) {
			DFPRINTF(2, (stderr, 
				     "%s: %s not subscribed to \"%s\"\n",
				     __func__,
				     dht_node_id_ascii(relay_id),
				     channel_name));

			reply = dht_group_make_msg_reply(channel_name,
			    ERR_NOTSUBSCRIBED,
			    dht_group_err(ERR_NOTSUBSCRIBED));
			if (reply != NULL)
				dht_group_rpc_delay_callback(reply, cb,cb_arg);
			return (0);
		} else {
			/* Refresh the subscribe time */
			gettimeofday(&subscriber->tv_last_heard, NULL);
		}
	}

	if (relay_id != NULL && channel != NULL) {
		/* 
		 * This has been relayed to us, we might have a subscriber to
		 * this group.  So, check and try to deliver.
		 */
		if (channel->flags & DHT_CHANNEL_SUBSCRIBED) {
			struct dht_group_cb *group_cb;
			TAILQ_FOREACH(group_cb, &group->callbacks, next) {
				if ((*group_cb->cb)(group, channel_name,
					src_id, message, message_length,
					group_cb->cb_arg) == 1)
					break;
			}
		}
	}

	num_sent = 0;
	num_success = 0;

	if (up) {
		/* Find out how many nodes are close to this channel */
		if (dht_lookup(group->dht, (u_char*)channel_name, strlen(channel_name),
			&ids, &numids) == -1) {
			DFPRINTF(1, (stderr,
				     "%s: dht_lookup failed\n", __func__));
			return (-1);
		}

		DFPRINTF(2, (stderr, 
			     "%s: got %d nodes for privmsg to \"%s\"\n",
			     __func__, numids, channel_name));

		/* Propagate the message up the tree */
		for (i = 0; i < DHT_GROUP_ALPHA && i < numids; ++i) {
			num_sent++;
			if (dht_group_rpc_privmsg(group, &ids[i],
				src_id, 1 /* up */, seqnr, channel_name,
				message, message_length,
				dht_group_msg_timeout_cb, group) != -1)
				num_success++;
		}

		free(ids);
	}

	if (channel != NULL) {
		/* Propagate the message to our children */
		SPLAY_FOREACH(subscriber, subscribe_tree,
		    &channel->subscribers) {
			/* Do not send the message to the guy we just
			 * sent to */
			if (relay_id != NULL &&
			    memcmp(relay_id, subscriber->id.id,
				sizeof(subscriber->id.id)) == 0)
				continue;

			num_sent++;
			if (dht_group_rpc_privmsg(group, &subscriber->id,
				src_id, 0 /* down */, seqnr, channel_name,
				message, message_length,
				NULL /* cb */, NULL /* cb_arg */) != -1)
				num_success++;
		}
	}

	if (num_sent)
		DFPRINTF(1, (stderr, "%s: propagated message %d times "
			     "out of %d tries\n",
			     __func__, num_success, num_sent));

	/* If we had nothing to send we always succeed */
	if (num_sent && !num_success) {
		reply = dht_group_make_msg_reply(channel_name,
		    ERR_INTERNAL, dht_group_err(ERR_INTERNAL));
	} else {
		reply = dht_group_make_msg_reply(channel_name, 0,
		    "sent message");
	}

	if (reply != NULL)
		dht_group_rpc_delay_callback(reply, cb, cb_arg);

	return (0);
}

/* 
 * External interface:  join the named channel.
 */

int
dht_group_join_channel(struct dht_group *group,
    char *channel_name,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *), void *cb_arg)
{
	struct dht_group_msg_reply *reply = NULL;
	struct dht_group_channel *channel;

	channel = dht_channel_find(group, channel_name);
	if (channel != NULL) {
		if (channel->flags & DHT_CHANNEL_SUBSCRIBED) {
			DFPRINTF(1, (stderr,
			    "%s: already subscribed to channel \"%s\"\n",
			    __func__, channel_name));
			return (-1);
		}

		/* We can just subscribe by flipping a toggle */
		channel->flags |= DHT_CHANNEL_SUBSCRIBED;

		reply = dht_group_make_msg_reply(channel_name, 0, "success");
		if (reply != NULL)
			dht_group_rpc_delay_callback(reply, cb, cb_arg);
		
		return (0);
	}

	return (dht_group_internal_join_channel(group,
		    channel_name, 1 /* self join */, cb, cb_arg));
}

/*
 * Called both when a user wants to join a new channel, but also when
 * a node receives a channel join from a remote site.
 */

int
dht_group_internal_join_channel(struct dht_group *group,
    char *channel_name, int self_join,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *),
    void *cb_arg)
{
	int i;
	u_char *myid;
	struct dht_group_join_channel_ctx *ctx;
	struct dht_group_channel *channel;
	struct dht_node_id *ids;
	size_t numids;

	channel = dht_channel_find(group, channel_name);
	if (channel == NULL) {
		if (strncasecmp(channel_name, "0x", 2) == 0) {
			struct dht_group_msg_reply* reply = NULL;
			reply = dht_group_make_msg_reply(channel_name,
			    ERR_ILLEGALNAME, dht_group_err(ERR_ILLEGALNAME));
			if (reply != NULL)
				dht_group_rpc_delay_callback(reply,
				    cb, cb_arg);
		
			return (0);
		}
	
		channel = dht_channel_new(group, channel_name);
		assert(channel != NULL);
	}

	/* Make ourselves a subscriber of this channel */
	if (self_join)
		channel->flags |= DHT_CHANNEL_SUBSCRIBED;

	/* Find out how many nodes are close to this channel */
	if (dht_lookup(group->dht, (u_char*)channel_name, strlen(channel_name),
		&ids, &numids) == -1) {
		DFPRINTF(2, (stderr, "%s: dht_lookup failed\n", __func__));
		return (-1);
	}

	DFPRINTF(1, (stderr, "%s: got %d nodes for \"%s\"\n",
		     __func__, numids, channel_name));

	ctx = calloc(1, sizeof(struct dht_group_join_channel_ctx));
	if (ctx == NULL)
		err(1, "%s: calloc", __func__);
	if ((ctx->channel_name = strdup(channel_name)) == NULL)
		err(1, "%s: strdup", __func__);
	ctx->group = group;
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	/* Find nodes that are closer to the channel name then we are */
	myid = dht_myid(group->dht);
	for (i = 0; i < DHT_GROUP_ALPHA && i < numids; ++i) {
		ctx->num_outstanding++;

		dht_group_rpc_join(group, &ids[i], channel_name,
		    dht_group_rpc_join_cb, ctx);
	}

	free(ids);

	/* There is nobody closer to us */
	if (!ctx->num_outstanding) {
		struct dht_group_msg_reply *reply = NULL;
		reply = dht_group_make_msg_reply(channel_name, 0, "success");
		if (reply != NULL)
			dht_group_rpc_delay_callback(reply, cb, cb_arg);
		free(ctx);
	}

	return (0);
}

/*
 * Specific RPC calls
 */

int
dht_group_rpc_join(struct dht_group *group, struct dht_node_id *id,
    char *channel_name,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *), void *cb_arg)
{
	struct dht_group_msg *msg = NULL;
	struct dht_group_msg_join *join = NULL;
	int res = -1;

	DFPRINTF(2, (stderr, "%s: %s sending join \"%s\" to %s\n",
		     __func__, 
		     dht_node_id_ascii(dht_myid(group->dht)),
		     channel_name, dht_node_id_ascii(id->id)));

	if ((msg = dht_group_msg_new()) == NULL)
		goto out;

	assert(!EVTAG_GET(msg, join, &join));
	assert(!EVTAG_ASSIGN(join, channel_name, channel_name));

	res = dht_group_send_rpc(group, id,
	    NULL /* no RPC id */, msg, cb, cb_arg);

 out:
	if (msg != NULL)
		dht_group_msg_free(msg);

	return (res);
}

/* Argh.  Really long RPC message with five thousand arguments */

int
dht_group_rpc_privmsg(struct dht_group *group, struct dht_node_id *id,
    u_char *src_id, uint8_t up, uint32_t seqnr,
    char *channel_name, uint8_t *message, uint32_t message_length,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *), void *cb_arg)
{
	struct dht_group_msg *msg = NULL;
	struct dht_group_msg_privmsg *privmsg = NULL;
	int res = -1;

	DFPRINTF(2, (stderr, "%s: %s sending privmsg for \"%s\" to %s\n",
		     __func__, 
		     dht_node_id_ascii(dht_myid(group->dht)),
		     channel_name, dht_node_id_ascii(id->id)));

	if ((msg = dht_group_msg_new()) == NULL)
		goto out;

	assert(!EVTAG_GET(msg, privmsg, &privmsg));
	assert(!EVTAG_ASSIGN(privmsg, src_id, src_id));
	assert(!EVTAG_ASSIGN(privmsg, up, up));
	assert(!EVTAG_ASSIGN(privmsg, seqnr, seqnr));
	assert(!EVTAG_ASSIGN(privmsg, channel_name, channel_name));
	assert(!EVTAG_ASSIGN(privmsg, message, message, message_length));

	res = dht_group_send_rpc(group, id,
	    NULL /* no RPC id */, msg, cb, cb_arg);

 out:
	if (msg != NULL)
		dht_group_msg_free(msg);

	return (res);
}

int
dht_group_rpc_part(struct dht_group *group, struct dht_node_id *id,
    char *channel_name,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *), void *cb_arg)
{
	struct dht_group_msg *msg = NULL;
	struct dht_group_msg_part *part = NULL;
	int res = -1;

	DFPRINTF(2, (stderr, "%s: %s sending part \"%s\" to %s\n",
		     __func__, 
		     dht_node_id_ascii(dht_myid(group->dht)),
		     channel_name, dht_node_id_ascii(id->id)));

	if ((msg = dht_group_msg_new()) == NULL)
		goto out;

	assert(!EVTAG_GET(msg, part, &part));
	assert(!EVTAG_ASSIGN(part, channel_name, channel_name));

	res = dht_group_send_rpc(group, id,
	    NULL /* no RPC id */, msg, cb, cb_arg);

 out:
	if (msg != NULL)
		dht_group_msg_free(msg);

	return (res);
}

int
dht_group_part_channel(struct dht_group *group,
    char *channel_name,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *), void *cb_arg)
{
	struct dht_group_msg_reply *reply = NULL;
	struct dht_group_channel *channel;

	channel = dht_channel_find(group, channel_name);
	if (channel == NULL) {
		reply = dht_group_make_msg_reply(channel_name,
		    ERR_UNKNOWNCHANNEL, dht_group_err(ERR_UNKNOWNCHANNEL));
		if (reply != NULL)
			dht_group_rpc_delay_callback(reply, cb, cb_arg);
		
		return (0);
	}

	/* Check if we are subsribed */
	if (!(channel->flags & DHT_CHANNEL_SUBSCRIBED)) {
		reply = dht_group_make_msg_reply(channel_name,
		    ERR_NOTSUBSCRIBED,
		    dht_group_err(ERR_NOTSUBSCRIBED));
		if (reply != NULL)
			dht_group_rpc_delay_callback(reply,
			    cb, cb_arg);
		
		return (0);
	}

	/* We are no longer subscribed ourselves */
	channel->flags &= ~DHT_CHANNEL_SUBSCRIBED;

	return (dht_group_internal_part_channel(group, channel, cb, cb_arg));
}

struct dht_group_part_channel_ctx {
	struct dht_group *group;
	char *channel_name;

	int num_outstanding;
	int num_success;

	void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *);
	void *cb_arg;
};

void
dht_group_rpc_part_cb(struct dht_rpc *rpc,
    struct dht_group_msg_reply *reply, void *arg)
{
	struct dht_group_msg_reply *inner_reply = NULL;
	struct dht_group_part_channel_ctx *ctx = arg;
	char *error_reason;
	uint32_t error_code;

	ctx->num_outstanding--;

	/* XXX - something here */
	if (reply == NULL)
		goto error;

	EVTAG_GET(reply, error_code, &error_code);
	EVTAG_GET(reply, error_reason, &error_reason);
	DFPRINTF(1, (stderr, "%s: got %d - %s\n", __func__,
		     error_code, error_reason));

	if (!error_code)
		ctx->num_success++;

error:
	if (ctx->num_outstanding)
		return;

	if (ctx->num_success) {
		inner_reply = dht_group_make_msg_reply(
			ctx->channel_name, 0, "success");
	} else {
		inner_reply = dht_group_make_msg_reply(
			ctx->channel_name, 1, "failure");
	}

	if (inner_reply != NULL) {
		if (ctx->cb != NULL)
			(*ctx->cb)(NULL, inner_reply, ctx->cb_arg);
		dht_group_msg_reply_free(inner_reply);
	}

	free(ctx->channel_name);
	free(ctx);
}

int
dht_group_internal_part_channel(struct dht_group *group,
    struct dht_group_channel *channel,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *), void *cb_arg)
{
	u_char *myid;
	struct dht_node_id *ids;
	struct dht_group_part_channel_ctx *ctx = NULL;
	struct dht_group_msg_reply *reply = NULL;
	char *channel_name = channel->channel_name;
	size_t numids;
	int i;

	/* We still have subscribers - there is nothing that we need to do */
	if ((channel->flags & DHT_CHANNEL_SUBSCRIBED) ||
	    SPLAY_ROOT(&channel->subscribers) != NULL) {
		reply = dht_group_make_msg_reply(channel_name, 0, "success");
		if (reply != NULL)
			dht_group_rpc_delay_callback(reply, cb, cb_arg);
		return (0);
	}

	/* Find out how many nodes are close to this channel */
	if (dht_lookup(group->dht, (u_char*)channel_name, strlen(channel_name),
		&ids, &numids) == -1) {
		DFPRINTF(2, (stderr, "%s: dht_lookup failed\n", __func__));
		return (-1);
	}

	DFPRINTF(1, (stderr, "%s: got %d nodes for \"%s\"\n",
		     __func__, numids, channel_name));

	ctx = calloc(1, sizeof(struct dht_group_part_channel_ctx));
	if (ctx == NULL)
		err(1, "%s: calloc", __func__);
	if ((ctx->channel_name = strdup(channel_name)) == NULL)
		err(1, "%s: strdup", __func__);
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	/* Find nodes that are closer to the channel name then we are */
	myid = dht_myid(group->dht);
	for (i = 0; i < DHT_GROUP_ALPHA && i < numids; ++i) {
		ctx->num_outstanding++;

		dht_group_rpc_part(group, &ids[i], channel_name,
		    dht_group_rpc_part_cb, ctx);
	}

	free(ids);

	/* There is nobody closer to us */
	if (!ctx->num_outstanding) {
		struct dht_group_msg_reply *reply = NULL;
		reply = dht_group_make_msg_reply(channel_name, 0, "success");
		if (reply != NULL)
			dht_group_rpc_delay_callback(reply, cb, cb_arg);
		free(ctx);
	}

	DFPRINTF(1, (stderr, "%s: %s unsubscribed from \"%s\'\n",
		     __func__, dht_node_id_ascii(myid), channel_name));

	/* At this time, we need to get rid of the channel. Sniff */
	dht_channel_free(channel);

	return (0);
}


/*
 * Sends a generic Group RPC.
 */

int
dht_group_send_rpc(struct dht_group *group,
    struct dht_node_id *id,
    u_char *rpc_id, struct dht_group_msg *msg,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *),
    void *cb_arg)
{
	struct dht_rpc *rpc;
	struct dht_group_pkt *pkt;
	int need_rpc = rpc_id == NULL;
	u_char *data = NULL;
	size_t datlen;
	int msg_length;
		
	if (dht_kademlia_compare(id->id, dht_myid(group->dht)) == 0) {
		/* Do not send RPCs to ourselves */
		return (-1);
	}

	if ((pkt = dht_group_pkt_new()) == NULL) {
		return (-1);
	}

	assert(msg != NULL);
#ifdef DHT_GROUP_USE_COMPRESSION
	evbuffer_drain(_tmp_compress, -1);
	dht_group_msg_marshal(_tmp_compress, msg);
	msg_length = EVBUFFER_LENGTH(_tmp_compress);

	dht_compress(_tmp_compress);

	/* Compress only if it's worth it */
	if (EVBUFFER_LENGTH(_tmp_compress) < msg_length) {
		assert(!EVTAG_ASSIGN(pkt, compress,
			   EVBUFFER_DATA(_tmp_compress),
			   EVBUFFER_LENGTH(_tmp_compress)));
	} else {
#endif
		assert(!EVTAG_ASSIGN(pkt, message, msg));
#ifdef DHT_GROUP_USE_COMPRESSION
	}
#endif

	/* Fill in pkt header */
	assert(!EVTAG_ASSIGN(pkt, src_id, dht_myid(group->dht)));
	assert(!EVTAG_ASSIGN(pkt, dst_id, id->id));

	/* Replies do not require a waiting RPC object */
	if (need_rpc) {
		if ((rpc = dht_rpc_new(&group->rpcs, group,
			 id->id, 0,
			 (void (*)(struct dht_rpc *, void *, void *))cb,
			 cb_arg)) == NULL) {
			goto error;
		}
		assert(!EVTAG_ASSIGN(pkt, rpc_id, rpc->rpc_id));
	} else {
		/* We are a reply and need to quote the previous ID */
		assert(rpc_id != NULL);
		assert(!EVTAG_ASSIGN(pkt, rpc_id, rpc_id));
	}

	assert(dht_group_pkt_complete(pkt) == 0);
	assert(EVTAG_HAS(pkt, compress) || EVTAG_HAS(pkt, message));
	evbuffer_drain(_tmp, -1);
	dht_group_pkt_marshal(_tmp, pkt);

	/* We need to copy the data into its own memory. */
	datlen = EVBUFFER_LENGTH(_tmp);
	if ((data = malloc(datlen)) == NULL)
		goto error;
	memcpy(data, EVBUFFER_DATA(_tmp), datlen);

	dht_send(group->dht, DHT_TYPE_GROUP,
	    &id->addr, id->port, data, datlen);

	dht_group_pkt_free(pkt);

	return (0);
 error:
	if (pkt != NULL)
		dht_group_pkt_free(pkt);

	return (-1);
}

struct dht_group_msg_reply *
dht_group_make_msg_reply(
    const char *channel_name, int error_code, const char *error_reason)
{
	struct dht_group_msg_reply *reply;

	if ((reply = dht_group_msg_reply_new()) == NULL) {
		/* out of memory */
		return (NULL);
	}

	assert(!EVTAG_ASSIGN(reply, channel_name, channel_name));
	assert(!EVTAG_ASSIGN(reply, error_code, error_code));
	assert(!EVTAG_ASSIGN(reply, error_reason, error_reason));

	assert(dht_group_msg_reply_complete(reply) == 0);

	return (reply);
}

/* Delays the return callback */

struct delay_group_rpc_cb {
	struct dht_group_msg_reply *reply;
	void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *);
	void *cb_arg;
};

static void
dht_group_rpc_delay_cb(int fd, short what, void *arg)
{
	struct delay_group_rpc_cb *ctx = arg;

	(*ctx->cb)(NULL, ctx->reply, ctx->cb_arg);

	dht_group_msg_reply_free(ctx->reply);
	free(ctx);
}

/* Takes ownership of the reply object */

void
dht_group_rpc_delay_callback(struct dht_group_msg_reply *reply,
    void (*cb)(struct dht_rpc *, struct dht_group_msg_reply *, void *),
    void *cb_arg)
{
	struct delay_group_rpc_cb *ctx;
	struct timeval tv;

	if (cb == NULL)
		return;
	
	if ((ctx = malloc(sizeof(struct delay_group_rpc_cb))) == NULL) {
		warn("%s: malloc", __func__);
		return;
	}

	ctx->reply = reply;
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	timerclear(&tv);
	event_once(-1, EV_TIMEOUT, dht_group_rpc_delay_cb, ctx, &tv);
}

int
dht_group_lookup(struct dht_node *node, char *channel_name,
    struct dht_node_id **ids, size_t *numids)
{
	u_char digest[SHA_DIGEST_LENGTH];
	char *p = channel_name;
	size_t plen = strlen(channel_name);
	
	if (strncasecmp(channel_name, "0x", 2) == 0 &&
	    plen == SHA_DIGEST_LENGTH*2 + 2) {
		dht_bits_bin2hex(channel_name, digest, sizeof(digest));
		p = (char*)digest;
		plen = sizeof(digest);
	}

	return dht_lookup(node, (u_char*)p, plen, ids, numids);
}

      
