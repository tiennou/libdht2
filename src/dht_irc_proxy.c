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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <event.h>
#include <dnet.h>

#include "dht.h"
#include "dht_kademlia.h"
#include "dht_group.h"
#include "dht_group_message.gen.h"
#include "dht_irc_proxy.h"

/* Callback to the user */
static struct server_request *server_req;
static struct dht_group *node;
static int num_connections;
static int server_fd = -1;
static struct event ev_accept;

static int make_socket(int (*f)(int, const struct sockaddr *, socklen_t),
    int type, char *address, uint16_t port);
static void server_request_free(struct server_request *);

static void
send_motd(struct server_request *req)
{
	struct evbuffer *tmp = evbuffer_new();

	evbuffer_add_printf(tmp,
	    ":irc.proxy 001 %s Welcome to me\n",
	    req->nick);
	evbuffer_add_printf(tmp,
	    ":irc.proxy 375 %s :- irc.proxy MOTD\n",
	    req->nick);
	evbuffer_add_printf(tmp,
	    ":irc.proxy 372 %s :This message is for you\n",
	    req->nick);
	evbuffer_add_printf(tmp,
	    ":irc.proxy 376 %s :End of /MOTD command\n",
	    req->nick);

	bufferevent_write(req->evb, EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));

	evbuffer_free(tmp);
}

static void
join_channel_done(struct dht_rpc *rpc,
    struct dht_group_msg_reply *reply, void *arg)
{
	struct server_request *req = arg;
	char *channel_name;
	int error_code;
	char *error_reason;
	struct evbuffer *tmp = evbuffer_new();

	EVTAG_GET(reply, channel_name, &channel_name);
	EVTAG_GET(reply, error_code, &error_code);
	EVTAG_GET(reply, error_reason, &error_reason);

	fprintf(stderr, "%s: channel: %s -> %d - %s\n",
	    dht_node_id_ascii(dht_myid(node->dht)),
	    channel_name, error_code, error_reason);

	evbuffer_add_printf(tmp, ":%s!~someuser@somehost JOIN %s\n",
	    req->nick, channel_name);

	bufferevent_write(req->evb, EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));

	evbuffer_free(tmp);
}

static void
part_channel_done(struct dht_rpc *rpc,
    struct dht_group_msg_reply *reply, void *arg)
{
	struct server_request *req = arg;
	char *channel_name;
	int error_code;
	char *error_reason;
	struct evbuffer *tmp = evbuffer_new();

	EVTAG_GET(reply, channel_name, &channel_name);
	EVTAG_GET(reply, error_code, &error_code);
	EVTAG_GET(reply, error_reason, &error_reason);

	fprintf(stderr, "%s: channel: %s -> %d - %s\n",
	    dht_node_id_ascii(dht_myid(node->dht)),
	    channel_name, error_code, error_reason);

	evbuffer_add_printf(tmp, ":%s!~someuser@somehost PART %s\n",
	    req->nick, channel_name);

	bufferevent_write(req->evb, EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));

	evbuffer_free(tmp);
}

static void
privmsg_done(struct dht_rpc *rpc, struct dht_group_msg_reply *reply, void *arg)
{
	char *channel_name;
	int error_code;
	char *error_reason;

	EVTAG_GET(reply, channel_name, &channel_name);
	EVTAG_GET(reply, error_code, &error_code);
	EVTAG_GET(reply, error_reason, &error_reason);

	fprintf(stderr, "%s: channel: %s -> %d - %s\n",
	    dht_node_id_ascii(dht_myid(node->dht)),
	    channel_name, error_code, error_reason);
}

static void
join_channel(struct server_request *req, char *channel)
{
	/* Let's try to do some real work */
	if (dht_group_join_channel(node, channel,
		join_channel_done, req) == -1) {
		struct evbuffer *tmp = evbuffer_new();

		evbuffer_add_printf(tmp,
		    ":irc.proxy 482 %s :could not join %s\n",
		    req->nick, channel);
		bufferevent_write(req->evb,
		    EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));
			
		evbuffer_free(tmp);
	}
}

static void
server_evb_readcb(struct bufferevent *bev, void *parameter)
{
	struct server_request *req = parameter;
	char *client_address = addr_ntoa(&req->src);
	char *buf, *line;
	int size;

	/* Check if we have received the complete request */
	if ((line = evbuffer_readline(bev->input)) != NULL) {
		fprintf(stderr, "%s >> %s\n", client_address, line);

		buf = NULL;
		size = 0;

		if (strncasecmp(line, "nick ", 5) == 0) {
			char *nick = line;

			strsep(&nick, " ");
			if ((req->nick = strdup(nick)) == NULL)
				err(1, "%s: strdup", __func__);

			buf = "NOTICE AUTH :*** Doing no checking\n";
			size = strlen(buf);
		} else if (strncasecmp(line, "user ", 5) == 0) {
			if ((req->user_info = strdup(line + 5)) == NULL)
				err(1, "%s: strdup", __func__);

			req->waiting_pong = 1;
			req->send_motd = 1;

			buf = "PING :1943689959\n";
			size = strlen(buf);
		} else if (strncasecmp(line, "pong ", 5) == 0) {
			if (req->waiting_pong)
				req->waiting_pong = 0;
			if (req->send_motd) {
				req->send_motd = 0;
				send_motd(req);
			}
		} else if (strncasecmp(line, "ping ", 5) == 0) {
			char *echo = line;
			struct evbuffer *tmp = evbuffer_new();
			strsep(&echo, " ");

			evbuffer_add_printf(tmp,
			    ":irc.proxy PONG %s :%s\n", echo, echo);
			bufferevent_write(req->evb,
			    EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));

			evbuffer_free(tmp);
		} else if (strncasecmp(line, "join ", 5) == 0) {
			char *channel, *p = line + 5;

			while ((channel = strsep(&p, ",")) != NULL) {
				join_channel(req, channel);
			}
		} else if (strncasecmp(line, "part ", 5) == 0) {
			char *channel = line + 5;

			/* Let's try to do some real work */
			if (dht_group_part_channel(node, channel,
				part_channel_done, req) == -1) {
				struct evbuffer *tmp = evbuffer_new();

				evbuffer_add_printf(tmp,
				    ":irc.proxy 482 %s :could not part %s\n",
				    req->nick, channel);
				bufferevent_write(req->evb,
				    EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));
			
				evbuffer_free(tmp);
			}
		} else if (strncasecmp(line, "privmsg ", 8) == 0) {
			char *channel = line + 8;
			char *message = channel;

			/* Makes channel null terminated */
			strsep(&message, " ");
			if (dht_group_privmsg(node, channel,
				message + 1, strlen(message + 1),
				privmsg_done, req) == -1) {
				struct evbuffer *tmp = evbuffer_new();

				evbuffer_add_printf(tmp,
				    ":irc.proxy 442 %s :could not send to %s\n",
				    req->nick, channel);
				bufferevent_write(req->evb,
				    EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));
			
				evbuffer_free(tmp);
			}
		} else if (strncasecmp(line, "quit ", 5) == 0) {
			/* We should really leave all channels here */
			free(line);
			server_request_free(req);
			return;
		}
		
		if (buf != NULL) {
			/* Write the data to the network stream and be
			 * done with it */
			bufferevent_write(req->evb, buf, size);
		}

		free(line);
	}

	return;
}

static void
server_evb_writecb(struct bufferevent *bev, void *parameter)
{
	/* 
	 * At this point, we have written all of our result data, so
	 * we just close the connection.
	 */
	struct server_request *req = parameter;
	if (req->close)
		server_request_free(req);
}

static void
server_evb_errcb(struct bufferevent *bev, short what, void *parameter)
{
	struct server_request *req = parameter;
	server_request_free(req);
}

/* Frees a request object and closes the connection */

static void
server_request_free(struct server_request *req)
{
	/* keep track of connections */
	num_connections--;

	bufferevent_free(req->evb);
	close(req->fd);
	free(req);
}

/* Creates a request object that can be used for streaming data */

static struct server_request *
server_request_new(int fd, struct addr *src)
{
	struct server_request *req = NULL;

	if ((req = calloc(1, sizeof(struct server_request))) == NULL)
		return (NULL);

	req->fd = fd;
	req->src = *src;

	if ((req->evb = bufferevent_new(fd,
		 server_evb_readcb, server_evb_writecb, server_evb_errcb,
		 req)) == NULL) {
		free(req);
		return (NULL);
	}

	/* Highest priority to UI requests */
	bufferevent_priority_set(req->evb, 0);

	/* keep track of connections */
	num_connections++;

	if (num_connections > 1) {
		char *message = "Only one connection allowed.\n";
		bufferevent_write(req->evb, message, strlen(message));
		req->close = 1;
		return (req);
	} else {
		server_req = req;
	}

	bufferevent_enable(req->evb, EV_READ);	
	return (req);
}

static void
server_accept(int fd, short what, void *arg)
{
	struct sockaddr_storage ss;
	socklen_t socklen = sizeof(ss);
	struct addr src;
	struct server_request *req = NULL;
	int newfd;

	if ((newfd = accept(fd, (struct sockaddr *)&ss, &socklen)) == -1) {
		warn("%s: accept", __func__);
		return;
	}

	addr_ston((struct sockaddr *)&ss, &src);
	fprintf(stderr, "%s: new request from %s\n",
	    __func__, addr_ntoa(&src));

	/* Create a new request structure and dispatch the request */
	if ((req = server_request_new(newfd, &src)) == NULL) {
		warn("%s: calloc", __func__);
		close(newfd);
		return;
	}
}

/*
 * Intializes a simple server.
 */

static void
server_init(char *address, int port)
{
	server_fd = make_socket(bind, SOCK_STREAM, address, port);

	if (server_fd == -1) {
		fprintf(stderr,
		    "\nA server might already be running on port %d.\n", port);
		exit(1);
	}

	if (listen(server_fd, 10) == -1)
		err(1, "%s: listen", __func__);

	fprintf(stderr, "IRC proxy listening on %s:%d\n", address, port);
	
	/* Accept connections */
	event_set(&ev_accept, server_fd, EV_READ | EV_PERSIST,
	    server_accept, NULL);

	/* Give the highest priority to the accept */
	event_priority_set(&ev_accept, 0);
	event_add(&ev_accept, NULL);
	return;
}

static int
receive_msg(struct dht_group *group,
    char *channel_name, uint8_t *src_id,
    uint8_t *message, uint32_t message_length,
    void *cb_arg)
{
	struct bufferevent *evb = server_req->evb;
	static char buffer[1024];
	struct evbuffer *tmp = evbuffer_new();

	int len = message_length;
	if (len >= sizeof(buffer) - 1)
		len = sizeof(buffer) - 1;

	memcpy(buffer, message, len);
	buffer[len] = '\0';

	evbuffer_add_printf(tmp,
	    ":%s PRIVMSG %s :%s\n",
	    dht_node_id_ascii(src_id), channel_name, buffer);

	bufferevent_write(evb, EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));

	evbuffer_free(tmp);

	return (0);	/* next person can see the message */
}

/*
 * Causes the proxy to terminate
 * Does not clean up any state.
 */

void
dht_irc_proxy_exit(void)
{
	event_del(&ev_accept);
	close(server_fd);
}

int
dht_irc_proxy_new(struct dht_group *group, uint16_t local_port)
{
	/* Start the proxy listener */
	server_init("0.0.0.0", local_port);

	dht_group_register_cb(group, receive_msg, NULL);
	
	node = group;
	
	return (0);
}

/* Either connect or bind */

static int
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

static int
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
