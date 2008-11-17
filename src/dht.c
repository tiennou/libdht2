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
#include <sys/socket.h>
#include <sys/uio.h>

#include <openssl/rsa.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <event.h>
#include <dnet.h>
#include <zlib.h>

#include "dht.h"
#include "dht_bits.h"
#include "dht_kademlia.h"
#include "dht_group.h"
#include "dht_crypto.h"

int make_socket_ai(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    struct addrinfo *ai);
int make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    char *address, uint16_t port);

void dht_read_cb(int, short, void *);
void dht_write_cb(int, short, void *);

int
dht_type_compare(struct dht_type_callback *a, struct dht_type_callback *b)
{
	if (a->type < b->type)
		return (-1);
	if (a->type > b->type)
		return (1);
	return (0);
}

SPLAY_PROTOTYPE(dht_readcb_tree, dht_type_callback, node, dht_type_compare);
SPLAY_GENERATE(dht_readcb_tree, dht_type_callback, node, dht_type_compare);

int
rpc_id_compare(struct dht_rpc *a, struct dht_rpc *b)
{
	return (dht_kademlia_compare(a->rpc_id, b->rpc_id));
}

SPLAY_GENERATE(dht_rpctree, dht_rpc, node, rpc_id_compare);

/* Globals */

int debug;				/* Debug level for debug printing */

rand_t *dht_rand;		/* portable source of randomness */

static void
dht_rand_init(void) {
	if (dht_rand != NULL)
		return;

	if ((dht_rand = rand_open()) == NULL)
		err(1, "rand_open");
}

char *
dht_node_id_ascii(u_char *id)
{
	static int off;
	static char ascii[2][SHA1_DIGESTSIZE*2+1];
	char *p = ascii[++off % 2];
	int i;

	for (i = 0; i < SHA1_DIGESTSIZE; ++i) {
		snprintf(p + 2*i, 3, "%02x", id[i]);
	}

	return (p);
}

/*
 * Associates a DHT node we a given protocol implementation
 */

void
dht_set_impl(struct dht_node *node, uint16_t type,
    const struct dht_callbacks *impl_cbs, void *impl_arg)
{
	assert(node->impl_cbs == NULL);
	assert(node->impl_arg == NULL);
	assert(dht_find_type(node, type) == NULL);

	node->dht_type = type;
	node->impl_cbs = impl_cbs;
	node->impl_arg = impl_arg;

	/* Application specific read callback */
	dht_register_type(node, type, impl_cbs->read, impl_arg);
}

struct dht_type_callback *
dht_find_type(struct dht_node *node, uint16_t type)
{
	struct dht_type_callback tmp;

	tmp.type = type;
	return (SPLAY_FIND(dht_readcb_tree, &node->read_cbs, &tmp));
}

int
dht_register_type(struct dht_node *node, uint16_t type,
    dht_readcb readcb, void *cb_arg)
{
	struct dht_type_callback *typecb;

	if (dht_find_type(node, type) != NULL)
		return (-1);

	typecb = calloc(1, sizeof(struct dht_type_callback));
	if (typecb == NULL)
		err(1, "%s: calloc", __func__);

	typecb->type = type;
	typecb->cb = readcb;
	typecb->cb_arg = cb_arg;

	SPLAY_INSERT(dht_readcb_tree, &node->read_cbs, typecb);

	return (0);
}

/*
 * Initializes global components of the DHT library.
 */

void
dht_init(void)
{
	evtag_init();
	dht_rand_init();
	dht_group_init();
	dht_crypto_init();
}

/*
 * Creates a new DHT node that is not associated with anything.
 */

struct dht_node *
dht_new(uint16_t port)
{
	struct dht_node *node = calloc(1, sizeof(struct dht_node));
	int fd;

	if (node == NULL)
		err(1, "%s: calloc", __func__);

	fd = make_socket(bind, SOCK_DGRAM, "0.0.0.0", port);
	if (fd == -1)
		err(1, "%s: make_socket", __func__);
	node->fd = fd;

	DFPRINTF(3, (stderr, "%s: bound fd %d to port %d\n",
		     __func__, fd, port));

	SPLAY_INIT(&node->read_cbs);
	TAILQ_INIT(&node->messages);

	event_set(&node->ev_write, fd, EV_WRITE, dht_write_cb, node);
	event_set(&node->ev_read, fd, EV_READ, dht_read_cb, node);
	event_add(&node->ev_read, NULL);

	return (node);
}

/* Join a DHT network */

int
dht_join(struct dht_node *node,
    struct addr *dst, uint16_t port, void (*cb)(int, void *arg), void *cb_arg)
{
	return (node->impl_cbs->join(node->impl_arg, dst, port, cb, cb_arg));
}

int
dht_lookup(struct dht_node *node,
    u_char *id, size_t idlen,
    struct dht_node_id **ids, size_t *numids)
{
	return (node->impl_cbs->lookup(node->impl_arg,
		    id, idlen, ids, numids));
}

u_char *
dht_myid(struct dht_node *node)
{
	return (node->impl_cbs->myid(node->impl_arg));
}

int
dht_find_id(struct dht_node *node,
    u_char *id, size_t idlen, struct dht_node_id *pid)
{
	return (node->impl_cbs->find_id(node->impl_arg, id, idlen, pid));
}

int
dht_ping(struct dht_node *node, u_char *id)
{
	return (node->impl_cbs->ping(node->impl_arg, id));
}

/* Callbacks */

void
dht_read_cb(int fd, short what, void *arg)
{
	static u_char buffer[4096];
	struct dht_node *node = arg;
	struct dht_pkthdr *hdr = (struct dht_pkthdr *)buffer;
	struct dht_type_callback *typecb;
	struct sockaddr_in sin;
	socklen_t sinlen = sizeof(sin);
	SHA1_CTX ctx;
	u_char digest[SHA1_DIGESTSIZE];
	ssize_t res;
	u_char *payload = (u_char *)(hdr + 1);
	ssize_t payload_len;
	struct addr addr;

	res = recvfrom(fd, buffer, sizeof(buffer), 0,
	    (struct sockaddr *)&sin, &sinlen);
	if (res == -1) {
		/* Oops, what do we do now */
		warn("%s: recvfrom", __func__);
		goto reschedule;
	}

	/* Get the IP address */
	addr_ston((struct sockaddr *)&sin, &addr);

	payload_len = res - sizeof(struct dht_pkthdr);

	if (res < sizeof(struct dht_pkthdr) || payload_len <= 0) {
		warnx("%s: short read from %s", __func__, addr_ntoa(&addr));
		goto reschedule;
	}
	
	typecb = dht_find_type(node, hdr->type);
	if (hdr->version != DHT_VERSION || typecb == NULL) {
		warnx("%s: unsupported version %d type %d from %s",
		    __func__, hdr->version, hdr->type, addr_ntoa(&addr));
		goto reschedule;
	}

	/* Let's verify the signature - this is going to be authed later */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, payload, payload_len);
	SHA1_Final(digest, &ctx);

	if (memcmp(digest, hdr->signature, sizeof(digest))) {
		warnx("%s: bad signature from %s", __func__, addr_ntoa(&addr));
		goto reschedule;
	}
	
	DFPRINTF(3, (stderr, "%s: received %d bytes from %s:%d\n",
		     __func__, (int)payload_len,
		     addr_ntoa(&addr), ntohs(sin.sin_port)));

	(*typecb->cb)(&addr, ntohs(sin.sin_port),
	    payload, payload_len, typecb->cb_arg);

 reschedule:
	event_add(&node->ev_read, NULL);
}

void
dht_write_cb(int fd, short what, void *arg)
{
	static struct dht_pkthdr pkthdr;
	struct dht_node *node = arg;
	struct dht_message *tmp = TAILQ_FIRST(&node->messages);
	struct sockaddr_in sin;
	int res;
	struct msghdr hdr;
	struct iovec io[2];
	SHA1_CTX ctx;

	addr_ntos(&tmp->dst, (struct sockaddr *)&sin);
	sin.sin_port = htons(tmp->port);

	/* Create the signature */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, tmp->data, tmp->datlen);
	SHA1_Final(pkthdr.signature, &ctx);

	pkthdr.version = DHT_VERSION;
	pkthdr.type = tmp->type;

	/* Scatter gather the header and the payload */
	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_name = &sin;
	hdr.msg_namelen = sizeof(sin);
	hdr.msg_iov = io;
	hdr.msg_iovlen = 2;

	io[0].iov_base = &pkthdr;
	io[0].iov_len = sizeof(pkthdr);
	io[1].iov_base = tmp->data;
	io[1].iov_len = tmp->datlen;

	res = sendmsg(fd, &hdr, 0);
	if (res == -1)
		warn("%s: sendmsg: %s", __func__, addr_ntoa(&tmp->dst));

	/* Remove this message */
	TAILQ_REMOVE(&node->messages, tmp, next);
	free(tmp->data);
	free(tmp);
	
	/* Schedule the send for the next message */
	if (TAILQ_FIRST(&node->messages) != NULL)
		event_add(&node->ev_write, NULL);
}

/*
 * Queues a message for delivery to the network.
 * We take ownership of the data and free it after it got sent.
 */

int
dht_send(struct dht_node *node, uint16_t type,
    struct addr *dst, uint16_t port, u_char *data, size_t datlen)
{
	struct dht_message *tmp = calloc(1, sizeof(struct dht_message));
	if (tmp == NULL)
		return (-1);

	/* make sure that we have a callback for this protocol */
	assert(dht_find_type(node, type) != NULL);

	tmp->dst = *dst;
	tmp->port = port;
	tmp->type = type;
	tmp->data = data;
	tmp->datlen = datlen;

	TAILQ_INSERT_TAIL(&node->messages, tmp, next);

	/* Schedule the event to written to the network */
	if (!event_pending(&node->ev_write, EV_WRITE, NULL))
		event_add(&node->ev_write, NULL);

	return (0);
}


/* Either connect or bind */

int
make_socket_ai(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    struct addrinfo *ai)
{
        struct linger linger;
        int fd, on = 1;

        /* Create listen socket */
        fd = socket(AF_INET, type, 0);
        if (fd == -1) {
                warn("socket");
                return (-1);
        }

        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
                warn("fcntl(O_NONBLOCK)");
                goto out;
        }

        if (fcntl(fd, F_SETFD, 1) == -1) {
                warn("fcntl(F_SETFD)");
                goto out;
        }

	if (type == SOCK_STREAM) {
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		    (void *)&on, sizeof(on));
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		    (void *) &on, sizeof(on));
#ifdef SO_REUSEPORT
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
		    (void *) &on, sizeof(on));
#endif
		linger.l_onoff = 1;
		linger.l_linger = 5;
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
	}

        if ((f)(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		if (errno != EINPROGRESS) {
			warn("%s", __func__);
			goto out;
		}
        }

	return (fd);

 out:
	close(fd);
	return (-1);
}

int
make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    char *address, uint16_t port)
{
        struct addrinfo ai, *aitop;
        char strport[NI_MAXSERV];
	int fd;
	
        memset(&ai, 0, sizeof (ai));
        ai.ai_family = AF_INET;
        ai.ai_socktype = type;
        ai.ai_flags = f != connect ? AI_PASSIVE : 0;
        snprintf(strport, sizeof (strport), "%d", port);
        if (getaddrinfo(address, strport, &ai, &aitop) != 0) {
                warn("getaddrinfo");
                return (-1);
        }
        
	fd = make_socket_ai(f, type, aitop);

	freeaddrinfo(aitop);

	return (fd);
}

static void
dht_rpc_timeout(int fd, short what, void *arg)
{
	struct dht_rpc *rpc = arg;
	struct dht_rpcs *rpcs = rpc->rpc_root;

	/* Call the callback with the timeout error */
	if (rpc->cb)
		(*rpc->cb)(rpc, NULL, rpc->cb_arg);

	/* Application specific callback hooks on timeouts */
	if (rpcs->cb_timeout)
		(*rpcs->cb_timeout)(rpc);

	dht_rpc_remove(rpcs, rpc);
}

struct dht_rpc *
dht_rpc_new(struct dht_rpcs *rpcs, void *node,
    u_char *dst_id, uint8_t command,
    void (*cb)(struct dht_rpc *, void *, void *), void *cb_arg)
{
	struct timeval tv;
	struct dht_rpc *rpc;
	int i;

	/* Try to allocate a generic RPC object */
	rpc = calloc(1, sizeof(struct dht_rpc));
	if (rpc == NULL)
		return (NULL);

	rpc->rpc_root = rpcs;

	memcpy(rpc->rpc_dst, dst_id, sizeof(rpc->rpc_dst));

	/* Generate a random RPC id */
	for (i = 0; i < SHA1_DIGESTSIZE; i++)
		rpc->rpc_id[i] = rand_uint8(dht_rand);

	rpc->rpc_command = command;
	rpc->cb = cb;
	rpc->cb_arg = cb_arg;

	rpc->parent.node = node;

	SPLAY_INSERT(dht_rpctree, &rpcs->rpcs, rpc);

	evtimer_set(&rpc->ev_cb, dht_rpc_timeout, rpc);
	timerclear(&tv);
	tv.tv_sec = DHT_RPC_TIMEOUT;
	evtimer_add(&rpc->ev_cb, &tv);

	return (rpc);
}

struct dht_rpc *
dht_rpc_find(struct dht_rpcs *rpcs, u_char *id)
{
	struct dht_rpc *rpc, tmp;

	memcpy(tmp.rpc_id, id, sizeof(tmp.rpc_id));
	rpc = SPLAY_FIND(dht_rpctree, &rpcs->rpcs, &tmp);

	return (rpc);
}

void
dht_rpc_remove(struct dht_rpcs *rpcs, struct dht_rpc *rpc)
{
	evtimer_del(&rpc->ev_cb);

	SPLAY_REMOVE(dht_rpctree, &rpcs->rpcs, rpc);
	free(rpc);
}

/* Delays the return callback */

struct delay_rpc_cb {
	struct evbuffer *evbuf;
	void (*cb)(struct dht_rpc *, void *, void *);
	void *cb_arg;
};

static void
dht_rpc_delay_cb(int fd, short what, void *arg)
{
	struct delay_rpc_cb *ctx = arg;

	(*ctx->cb)(NULL, ctx->evbuf, ctx->cb_arg);

	evbuffer_free(ctx->evbuf);
	free(ctx);
}

/* Destroys the incoming event buffer */

void
dht_rpc_delay_callback(struct evbuffer *evbuf,
    void (*cb)(struct dht_rpc *, void *, void *), void *cb_arg)
{
	struct delay_rpc_cb *ctx;
	struct timeval tv;

	if (cb == NULL)
		return;
	
	if ((ctx = malloc(sizeof(struct delay_rpc_cb))) == NULL) {
		warn("%s: malloc", __func__);
		return;
	}

	if ((ctx->evbuf = evbuffer_new()) == NULL) {
		warn("%s: malloc", __func__);
		free(ctx);
		return;
	}

	evbuffer_add_buffer(ctx->evbuf, evbuf);

	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	timerclear(&tv);
	event_once(-1, EV_TIMEOUT, dht_rpc_delay_cb, ctx, &tv);
}

/* Per packet compression */

void
dht_compress(struct evbuffer *evbuf)
{
	static struct evbuffer *tmp;
	static z_stream stream;
	static u_char buffer[2048];
	int status;
	
	/* Initialize buffer and compressor */
	if (tmp == NULL) {
		tmp = evbuffer_new();
		deflateInit(&stream, 9);
	}
	deflateReset(&stream);

	stream.next_in = EVBUFFER_DATA(evbuf);
	stream.avail_in = EVBUFFER_LENGTH(evbuf);

	do {
		stream.next_out = buffer;
		stream.avail_out = sizeof(buffer);

		status = deflate(&stream, Z_FULL_FLUSH);

		switch (status) {
		case Z_OK:
			/* Append compress data to buffer */
			evbuffer_add(tmp, buffer,
			    sizeof(buffer) - stream.avail_out);
			break;
		default:
			errx(1, "%s: deflate failed with %d",
			    __func__, status);
			/* NOTREACHED */
		}
	} while (stream.avail_out == 0);

	evbuffer_drain(evbuf, EVBUFFER_LENGTH(evbuf));
	evbuffer_add_buffer(evbuf, tmp);
}

int
dht_decompress(struct evbuffer *evbuf)
{
	static struct evbuffer *tmp;
	static z_stream stream;
	static u_char buffer[2048];
	int status, done = 0;
	
	/* Initialize buffer and compressor */
	if (tmp == NULL) {
		tmp = evbuffer_new();
		inflateInit(&stream);
	}
	inflateReset(&stream);

	stream.next_in = EVBUFFER_DATA(evbuf);
	stream.avail_in = EVBUFFER_LENGTH(evbuf);

	do {
		stream.next_out = buffer;
		stream.avail_out = sizeof(buffer);

		status = inflate(&stream, Z_FULL_FLUSH);

		switch (status) {
		case Z_OK:
			/* Append compress data to buffer */
			evbuffer_add(tmp, buffer,
			    sizeof(buffer) - stream.avail_out);
			break;

		case Z_BUF_ERROR:
			done = 1;
			break;

		default:
			warnx("%s: inflate failed with %d", __func__, status);
			return (-1);
		}
	} while (!done);

	evbuffer_drain(evbuf, EVBUFFER_LENGTH(evbuf));
	evbuffer_add_buffer(evbuf, tmp);

	return (0);
}
