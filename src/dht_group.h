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

/*
 * Group Communication Layer
 *
 * For authentication purposes, we will create a public key.  The node
 * identifier is then the hash of the public key or maybe the hash of
 * the signed public key.  We use the Kademlia store and get
 * primitives to propagate knowledge of these keys through the
 * network.
 *
 * We somehow need to write protect the data - so that it can not be
 * erase by an adversary unless the adversary knows the private key
 * that corresponds to the public key.
 *
 * Every message is going to be signed - a participating node can
 * retrieve the public key by querying the network.
 */

#ifndef _DHT_GROUP_
#define _DHT_GROUP_

#include <openssl/sha.h>

/* Compress network packets - undefine to disable */
#define DHT_GROUP_USE_COMPRESSION	1

#define DHT_GROUP_ALPHA			3	/* propagation spread out */

struct dht_node;
struct dht_group;
struct dht_group_pkt;
struct dht_group_msg_join;
struct dht_group_msg_privmsg;
struct dht_group_msg_part;
struct dht_group_msg_reply;

/* Possible Errors */

enum group_errors {
	ERR_OK=0, ERR_INTERNAL, ERR_NOTSUBSCRIBED, ERR_DUPLICATE,
	ERR_UNKNOWNCHANNEL, ERR_ALREADYSUBSCRIBED, ERR_ILLEGALNAME,
	ERR_MAX_ERRS
};

/* Keeping track of messages that we have seen from users */
struct dht_group_seqnr {
	SPLAY_ENTRY(dht_group_seqnr) node;
	TAILQ_ENTRY(dht_group_seqnr) next;
	u_char id[SHA_DIGEST_LENGTH];
	uint32_t last_seen;
	uint32_t current_window;

	/* We can expire old entries if we feel like it */
	struct timeval tv_last_active;
};

/* Keeping track of which channels we are registered in, etc. */

struct dht_group_subscriber {
	SPLAY_ENTRY(dht_group_subscriber) node;

	struct dht_node_id id;

	/* 
	 * The last time this node was active on the channel or resubscribed
	 * to it.  We purge inactive nodes.
	 */
	struct timeval tv_last_heard;
};

struct dht_group_channel {
	SPLAY_ENTRY(dht_group_channel) node;

	char *channel_name;	/* some ascii name of the channel */
	struct dht_group *parent;

	int flags;
#define DHT_CHANNEL_SUBSCRIBED	0x0001	/* are we subscribed ourselves */

	SPLAY_HEAD(subscribe_tree, dht_group_subscriber) subscribers;
	int num_subscribers;

	struct event ev_refresh;
};

#define DHT_GROUP_CHANNEL_REFRESH	30	/* in seconds */

/* 
 * Informs the user of our group communication abstraction about a new
 * message.
 * A return value of 1 means that the message was handled and should not
 * be propagated.  A return value of 0 means that the message should be
 * passed to the next callback.
 */
typedef int (*message_cb)(struct dht_group *,
    char *channel_name, uint8_t *src_id,
    uint8_t *message, uint32_t message_length, void *cb_arg);

struct dht_group_cb {
	TAILQ_ENTRY(dht_group_cb) next;

	message_cb cb;
	void *cb_arg;
};

struct dht_group {
	struct dht_node *dht;

	struct dht_rpcs rpcs;

	/* Which channels we are aware of */
	SPLAY_HEAD(group_channel_tree, dht_group_channel) channels;

	/* Which sequence numbers have we seen */
	SPLAY_HEAD(group_seqnr_tree, dht_group_seqnr) root_seqnr;

	/* Time ordered list - active ones go to the bottom */
	TAILQ_HEAD(group_seqnr_q, dht_group_seqnr) head_seqnr;

	/* Creation time of group - locally monotonically increasing */
	struct timeval tv_create;

	/* The sequence number for messages that we generate */
	uint32_t seqnr;

	/* Our user wants to hear back from us */
	TAILQ_HEAD(group_cb_q, dht_group_cb) callbacks;

	int flags;
#define DHT_GROUP_FLAG_ENFORCE_CHANNEL	0x0001	/* need channel membership */
};

/* Public interface */

void			dht_group_init();
struct dht_group *	dht_group_new(struct dht_node *dht);
void			dht_group_register_cb(struct dht_group *group,
			    message_cb, void *);
int			dht_group_join_channel(struct dht_group *group,
			    char *channel_name, 
			    void (*cb)(struct dht_rpc *,
				struct dht_group_msg_reply *, void *),
			    void *argcb);
int			dht_group_privmsg(struct dht_group *group,
			    char *channel_name, 
			    uint8_t *message, uint32_t message_length,
			    void (*cb)(struct dht_rpc *,
				struct dht_group_msg_reply *, void *),
			    void *argcb);
int			dht_group_part_channel(struct dht_group *group,
			    char *channel_name,
			    void (*cb)(struct dht_rpc *,
				struct dht_group_msg_reply *, void *),
			    void *cb_arg);

/* Message handling */

void			dht_group_handle_join(struct dht_group *group,
			    struct addr *addr, uint16_t port,
			    struct dht_group_pkt *pkt,
			    struct dht_group_msg_join *msg_join);

int			dht_group_rpc_join(struct dht_group *group,
			    struct dht_node_id *id, char *channel_name,
			    void (*cb)(struct dht_rpc *,
				struct dht_group_msg_reply *, void *),
			    void *cb_arg);

int			dht_group_internal_join_channel(
			    struct dht_group *group, char *channel_name,
			    int self_join,
			    void (*cb)(struct dht_rpc *,
				struct dht_group_msg_reply *, void *),
			    void *cb_arg);

int			dht_group_internal_part_channel(
			    struct dht_group *group,
			    struct dht_group_channel *channel,
			    void (*cb)(struct dht_rpc *,
				struct dht_group_msg_reply *, void *),
			    void *cb_arg);

void			dht_group_handle_privmsg(struct dht_group *group,
			    struct addr *addr, uint16_t port,
			    struct dht_group_pkt *pkt,
			    struct dht_group_msg_privmsg *msg_privmsg);

int			dht_group_propagate_privmsg(struct dht_group *group,
			    u_char *src_id, u_char *relay_id, uint8_t up,
			    uint32_t seqnr, char *channel_name,
			    uint8_t *message, uint32_t message_length,
			    void (*cb)(struct dht_rpc *,
				struct dht_group_msg_reply *, void *),
			    void *cb_arg);

int			dht_group_rpc_privmsg(struct dht_group *group,
			    struct dht_node_id *id,
			    u_char *src_id, uint8_t up,
			    uint32_t seqnr, char *channel_name,
			    uint8_t *message, uint32_t message_length,
			    void (*cb)(struct dht_rpc *,
				struct dht_group_msg_reply *, void *),
			    void *cb_arg);

void			dht_group_handle_part(struct dht_group *group,
			    struct addr *addr, uint16_t port,
			    struct dht_group_pkt *pkt,
			    struct dht_group_msg_part *msg_part);

/* Misc */

/*
 * Looks up nodes that are close to the channel name.  However, if it
 * detects that a channel name starts with 0x, it converts it into a
 * binary string.
 */
int			dht_group_lookup(struct dht_node *node,
			    u_char *channel_name,
			    struct dht_node_id **ids, size_t *numids);

void			dht_group_rpc_delay_callback(
			    struct dht_group_msg_reply *reply,
			    void (*cb)(struct dht_rpc *,
				struct dht_group_msg_reply *, void *),
			    void *cb_arg);

struct dht_group_msg_reply *dht_group_make_msg_reply(
			    const char *channel_name, int error_code,
			    const char *error_reason);

void			dht_channel_free(struct dht_group_channel *channel);
struct dht_group_channel *dht_channel_new(struct dht_group *group,
			    char *channel_name);
struct dht_group_channel *dht_channel_find(struct dht_group *group,
			    char *channel_name);

int			dht_group_new_seqnr(struct dht_group *group,
			    u_char *src_id, uint32_t seqnr);
const char *		dht_group_err(int code);

#endif /* _DHT_GROUP_ */
