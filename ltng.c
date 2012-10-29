#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "http-parser/http_parser.h"

#define MAX_EVENTS 1024

const int pagesize = 4096;

int or_die(char *msg, int result) {
    if (result == -1) {
        int msglen = strlen(msg);
        char *errormsg = malloc(msglen + 3);
        strcpy(errormsg, msg);
        strcpy(errormsg+msglen, ": ");
        perror(errormsg);
        free(errormsg);
        exit(EXIT_FAILURE);
    }

    return result;
}

typedef struct ltng_conn {
    http_parser *parser;
    u_char *buffer;
    const char *url;
    const char *last_header;
    const char *last_value;
    size_t url_len;
    size_t last_header_len;
    size_t last_value_len;
    size_t buffer_offset;
    int cfd;
    struct in_addr raddr;
    in_port_t rport;
    unsigned char close;
    unsigned char state; // ltng_conn_state
} ltng_conn;

typedef enum ltng_conn_state {
    HTTP_HEADER_NONE = 0,
    HTTP_HEADER_CONNECTION,
    HTTP_HEADER_ETAG, // TODO I want more than 1 enum value ;)
    HTTP_HEADER_DONTCARE,
    RESPONSE_SENT
} ltng_conn_state;

int ltng_conn_new(int lfd, int epfd) {
    // will static speed this up? I suspect it will just cause page faults.
    struct epoll_event ev = {.events = EPOLLIN | EPOLLET | EPOLLRDHUP};
    ltng_conn *c;
    http_parser *p;
    struct sockaddr_in raddr;
    socklen_t raddr_len = sizeof(raddr);

    c = malloc(sizeof(ltng_conn) + sizeof(http_parser));
    p = (http_parser*) (c+1);
    http_parser_init(p, HTTP_REQUEST);
    c->parser = p;
    p->data = c;
    ev.data.ptr = c;

    c->buffer = malloc(pagesize);
    c->buffer_offset = 0;
    c->url = c->last_header = c->last_value = NULL;
    c->url_len = c->last_header_len = c->last_value_len = -1;
    c->close = 0;
    c->state = HTTP_HEADER_NONE;

    c->cfd = or_die("accept", accept4(lfd, (struct sockaddr*) &raddr, &raddr_len, SOCK_NONBLOCK));
    c->raddr = raddr.sin_addr;
    c->rport = ntohs(raddr.sin_port);
    or_die("epoll_ctl accept", epoll_ctl(epfd, EPOLL_CTL_ADD, c->cfd, &ev));

#ifndef NDEBUG
    printf("Accepted connection from: %s:%hu\n", inet_ntoa(c->raddr), c->rport);
#endif
    return 0;
}

int ltng_conn_destroy(ltng_conn *c, int epfd) {
    or_die("epoll_ctl hup", epoll_ctl(epfd, EPOLL_CTL_DEL, c->cfd, NULL));
    or_die("close", close(c->cfd));
#ifndef NDEBUG
    printf("Closed connection from %s:%hu\n", inet_ntoa(c->raddr), c->rport);
#endif
    free(c->buffer);
    free(c);
    return 0;
}

int http_url_cb(http_parser *p, const char *at, size_t length) {
    ltng_conn *c = p->data;
    c->url = at;
    c->url_len = length;
#ifndef NDEBUG
    printf("Parsed url chunk: %.*s\n", length, at);
#endif
    return 0;
}

int http_header_cb(http_parser *p, const char *at, size_t length) {
    ltng_conn *c = p->data;
    c->last_header = at;
    c->last_header_len = length;

    if (c->state && c->state != HTTP_HEADER_DONTCARE) {
        switch (c->state) {
        case HTTP_HEADER_CONNECTION:
            if (strncasecmp(c->last_value, "keep-alive", c->last_value_len) == 0) {
                c->close = 0;
            } else {
                c->close = 1;
            }
            break;
        }
    }
    c->state = HTTP_HEADER_NONE;

#ifndef NDEBUG
    printf("Parsed header field chunk: %.*s\n", length, at);
#endif
    return 0;
}

int http_value_cb(http_parser *p, const char *at, size_t length) {
    ltng_conn *c = p->data;
    c->last_value = at;
    c->last_value_len = length;

    if (c->state == HTTP_HEADER_NONE) {
        if (strncasecmp(c->last_header, "Connection", c->last_header_len) == 0) {
            c->state = HTTP_HEADER_CONNECTION;
        } else if (strncasecmp(c->last_header, "ETag", c->last_header_len) == 0) {
            c->state = HTTP_HEADER_ETAG;
        } else {
            c->state = HTTP_HEADER_DONTCARE;
        }
    }

#ifndef NDEBUG
    printf("Parsed header value chunk: %.*s\n", length, at);
#endif
    return 0;
}

int http_headers_complete_cb(http_parser *p) {
    ltng_conn *c = p->data;
    if (c->state && c->state != HTTP_HEADER_DONTCARE) {
        switch (c->state) {
        case HTTP_HEADER_CONNECTION:
            if (strncasecmp(c->last_value, "keep-alive", c->last_value_len) == 0) {
                c->close = 0;
            } else {
                c->close = 1;
            }
            break;
        }
    }
#ifndef NDEBUG
    printf("Got connection %s request: %.*s\n", c->close ? "close" : "keep-alive", c->url_len, c->url);
#endif

    return 0;
}

int ltng_conn_execute(ltng_conn *c, int epfd) {
    http_parser_settings parser_settings = {
        .on_url = http_url_cb,
        .on_header_field = http_header_cb,
        .on_header_value = http_value_cb,
        .on_headers_complete = http_headers_complete_cb
    }; // FIXME this is weird.

    int len, nparsed;
    http_parser *p = c->parser;

    while (1) {
        len = recv(c->cfd, c->buffer + c->buffer_offset, pagesize - c->buffer_offset, 0);
        if (len == -1 && errno == EAGAIN) {
            return 0;
        }
        or_die("recv", len);
        c->buffer_offset += len;

        nparsed = http_parser_execute(p, &parser_settings, c->buffer, len);
        if (nparsed == 0 || nparsed != len) {
            ltng_conn_destroy(c, epfd);
            return 0;
        }

        if (c->state == RESPONSE_SENT) {
            // if Connection: close then just close connection, else restart the buffer
            if (c->close) {
                ltng_conn_destroy(c, epfd);
            } else {
                c->buffer_offset = 0;
            }
        }
    }
}

int main(int argc, char **argv) {
    int lfd, epfd, nfds, i, len, nparsed;
    ltng_conn *c;
    struct epoll_event listen_ev, events[MAX_EVENTS];

    struct sockaddr_in laddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(argc > 1 ? atoi(argv[1]) : 4242)
    };
    socklen_t laddr_len = sizeof(laddr);


    int so_reuseaddr_optval = 1;
    
    lfd = or_die("socket", socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));
    or_die("setsockopt SO_REUSEADDR", setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr_optval, sizeof(so_reuseaddr_optval)));
    or_die("bind", bind(lfd, (struct sockaddr*) &laddr, laddr_len));
    or_die("listen", listen(lfd, 5));
#ifndef NDEBUG
    printf("Listening on: %s:%hu\n", inet_ntoa(laddr.sin_addr), ntohs(laddr.sin_port));
#endif

    listen_ev.events = EPOLLIN;
    listen_ev.data.ptr = NULL;
    epfd = or_die("epoll_create", epoll_create1(0));
    or_die("epoll_ctl listen", epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &listen_ev));

    while (1) {
        nfds = or_die("epoll_wait", epoll_wait(epfd, events, MAX_EVENTS, -1));

        for (i = 0; i < nfds; ++i) {
            c = (ltng_conn*) events[i].data.ptr;

            if (c == NULL) {
                ltng_conn_new(lfd, epfd);
            } else {
                ltng_conn_execute(c, epfd);
            }
        }
    }

    return 1;
}
