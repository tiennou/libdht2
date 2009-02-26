#ifndef _IRC_PROXY_
#define _IRC_PROXY_

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

#endif
