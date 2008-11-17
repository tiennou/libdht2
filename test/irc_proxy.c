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

int
receive_msg(struct dht_group *group,
    char *channel_name, uint8_t *src_id,
    uint8_t *message, uint32_t message_length,
    void *cb_arg)
{
	static char buffer[1024];

	int len = message_length;
	if (len >= sizeof(buffer) - 1)
		len = sizeof(buffer) - 1;

	memcpy(buffer, message, len);
	buffer[len] = '\0';

	fprintf(stderr, "%s: %s: %s\n",
	    channel_name, dht_node_id_ascii(src_id), buffer);

	return (0);	/* allow next caller to process the message */
}

static void
join_done_cb(int failure, void *arg)
{
	struct dht_group *group = arg;

	if (failure)
		errx(1, "Join failed");

	fprintf(stderr, "DHT node %p joined\n", group->dht);
}

int
main(int argc, char **argv)
{
	extern int debug;
	extern char *optarg;
	struct addr remote_addr;
	struct dht_node *dht;
	struct dht_group *group;
	int remote_addr_set = 0;
	uint16_t local_port = 9001, remote_port = 9001;
	int ch;

	while ((ch = getopt(argc, argv, "s:p:")) != -1) {
		switch (ch) {
		case 's': {
			char *address, *port = optarg;
			address = strsep(&port, ":");
			if (addr_pton(address, &remote_addr) == -1)
				errx(1, "%s: addr_pton(\"%s\")",
				    __func__, address);
			if (port == NULL || (remote_port = atoi(port)) == 0)
				errx(1, "%s: bad port specification: %s",
				    __func__, port);
			remote_addr_set = 1;
			break;
		}

		case 'p':
			if ((local_port = atoi(optarg)) == 0)
				errx(1, "%s: bad port number: %s",
				    __func__, optarg);
			break;

		default:
			errx(1, "bad argument: -%c", ch);
			break;
		}
	}
		

	/* Some simple debugging */
	debug = 2;

	event_init();

	dht_init();

	fprintf(stderr, "Listening on UDP port %d for DHT traffic\n",
	    local_port);
	dht = kad_make_dht(local_port);
	assert(dht != NULL);
	group = dht_group_new(dht);
	assert(group != NULL);
	dht_group_register_cb(group, receive_msg, NULL);

	if (remote_addr_set) {
		fprintf(stderr, "Joining existing DHT network at %s:%d\n",
		    addr_ntoa(&remote_addr), remote_port);
		dht_join(dht, &remote_addr, remote_port, join_done_cb, group);
	}

	dht_irc_proxy_new(group, local_port);
	
	event_dispatch();

	exit(0);
}
