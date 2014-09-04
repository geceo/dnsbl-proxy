#ifndef OSPOW_TYPES_H
#define OSPOW_TYPES_H

#include <glib.h>
#include <sys/types.h>
#include <sys/time.h>

typedef struct {
	char *name;
	char *server;
	gboolean listed;
	time_t ctime;
} record_t;

struct dnsbl_server_t {
    char *name;
    char *fmt;
    struct evdns_base *evdnsBase;
} dnsbl_server_t;

struct config_t {
    int s;
    int port;
    struct event_base *event_base;
    struct event *timer_ev;
    char *zone;
    GRegex *zone_regex;
    char *logging;
    void (*logger) (int, const char *, va_list);
    int timeout;
    time_t cache_timeout;
    int nb_srv;
    int loglevel;
    char *server_list;
    struct dnsbl_server_t **servers;
    short debug;
} config_t;

struct result_t {
    struct dnsbl_server_t *server;
    gboolean listed; 
} result_t;

struct pending_request_t {
    struct evdns_server_request *r;
    char *client;
    char *original_ip;
    int pending_srv;
    gboolean listed;
    char **srv;
    int srv_idx;
    struct timespec timestamp;
    char msg[255];
} pending_request_t;

struct cb_datas_t {
    struct pending_request_t *req;
    struct dnsbl_server_t *srv;
} cb_datas_t;
    

#endif
