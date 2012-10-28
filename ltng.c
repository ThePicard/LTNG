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

struct conn_data {
    int fd;
    struct in_addr addr;
    in_port_t port;
    http_parser *parser;
};

struct parse_data {
    const char *url_at;
    size_t urllen;
    int complete;
};

int http_url_cb(http_parser *p, const char *at, size_t length) {
    struct parse_data *d = p->data;
    d->url_at = at;
    d->urllen = length;
    d->complete = 0;
    printf("Parsed url chunk of len: %d\n", d->urllen);
    return 0;
}

int http_headers_complete_cb(http_parser *p) {
    struct parse_data *d = p->data;
    d->complete = 1;
    puts("Finished full header");
    return 0;
}

int main(int argc, char **argv) {
    int lfd, epfd, nfds, i, cfd, offset, len, nparsed;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    struct epoll_event ev, events[MAX_EVENTS];
    struct conn_data *cd;
    struct parse_data *pd;
    int so_reuseaddr_optval = 1;
    const int pagesize = getpagesize();
    http_parser_settings parser_settings;
    parser_settings.on_url = http_url_cb;
    parser_settings.on_headers_complete = http_headers_complete_cb;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(argc > 1 ? atoi(argv[1]) : 4242);
    u_char *buffer = malloc(pagesize);
    
    lfd = or_die("socket", socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));
    or_die("setsockopt SO_REUSEADDR", setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr_optval, sizeof(so_reuseaddr_optval)));
    or_die("bind", bind(lfd, (struct sockaddr*) &addr, addrlen));
    or_die("listen", listen(lfd, 5));

    ev.events = EPOLLIN;
    cd = malloc(sizeof(struct conn_data));
    memset(cd, 0, sizeof(struct conn_data));
    cd->fd = lfd;
    ev.data.ptr = cd;
    epfd = or_die("epoll_create", epoll_create(1));
    or_die("epoll_ctl listen", epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &ev));

    while (1) {
        nfds = or_die("epoll_wait", epoll_wait(epfd, events, MAX_EVENTS, -1));
        for (i = 0; i < nfds; ++i) {
            cd = (struct conn_data*) events[i].data.ptr;
            printf("event on fd %d (%d) with conn_data address %x\n", cd->fd, lfd, cd);
            if (cd->fd == lfd) {
                cfd = or_die("accept", accept4(lfd, (struct sockaddr*) &addr, &addrlen, SOCK_NONBLOCK));
                ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                cd = malloc(sizeof(struct conn_data)+sizeof(http_parser)+sizeof(struct parse_data));
                cd->parser = (http_parser*) (cd+1);
                http_parser_init(cd->parser, HTTP_REQUEST);
                pd = (struct parse_data*) (cd->parser+1);
                memset(pd, 0, sizeof(pd));
                pd->complete = 0;
                cd->parser->data = pd;
                cd->fd = cfd;
                cd->addr = addr.sin_addr;
                cd->port = ntohs(addr.sin_port);
                ev.data.ptr = cd;
                or_die("epoll_ctl accept", epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev));
                printf("Accepted connection from: %s:%hu\n", inet_ntoa(cd->addr), cd->port);
            } else {
                offset = 0;
                while (1) {
                    len = recv(cd->fd, buffer + offset, pagesize - offset, 0);
                    if (len == -1 && errno == EAGAIN) {
                        break;
                    }
                    or_die("recv", len);
                    offset += len;
                    nparsed = http_parser_execute(cd->parser, &parser_settings, buffer, len);
                    if (nparsed == 0 || nparsed != len) {
                        or_die("epoll_ctl hup", epoll_ctl(epfd, EPOLL_CTL_DEL, cd->fd, NULL));
                        or_die("close", close(cd->fd));
                        printf("Closed connection from %s:%hu\n", inet_ntoa(cd->addr), cd->port);
                        free(cd);
                        break;
                    }
                    pd = cd->parser->data;
                    if (pd->complete) {
                        printf("Got a request for: %.*s\n", pd->urllen, pd->url_at);
                    }
                }
            }
        }
    }

    return 1;
}
