#ifndef _DHT_IRC_PROXY_
#define _DHT_IRC_PROXY_

#define SERVER_MAX_REQUEST_SIZE  4096

struct bufferevent;
struct server_request {
    int                   fd;
    int                   close;
    struct addr           src;
    struct bufferevent *  evb;

    int                   waiting_pong;
    int                   send_motd;

    /* Some stupid state */
    char *  nick;
    char *  user_info;
};

int dht_irc_proxy_new(struct dht_group *group, uint16_t local_port);

void dht_irc_proxy_exit(void);

#endif
