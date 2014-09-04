#ifndef OSPOW_TOOL_H
#define OSPOW_TOOL_H

void config_init(const char *path);


struct sockaddr_in **get_domain_ns(char *domain);
int config_dnsbl_server(struct dnsbl_server_t *s, struct event_base *base);

void logevent_logger(int severity, const char *msg);
void dns_log(int severity, const char *fmt, ...);
int resolve_facility(char *facility);
void log2stdout(int severity, const char *fmt, va_list list);
void log2syslog(int severity, const char *fmt, va_list list);

record_t *get_cached_name(const char *name);
void cache_cleanup(struct event *);
void set_cache_name(char *name, gboolean listed, char *server);
void cache_init(time_t timeout);
void cache_destroy();


float get_timespent(struct timespec b, struct timespec e);
int send_answer(struct evdns_server_request *r, int ret, void *value, struct timespec *timestamp);


#include <syslog.h>

#define message(fmt, ...) dns_log(LOG_INFO, fmt, ##__VA_ARGS__)
#define notice(fmt, ...) dns_log(LOG_NOTICE, fmt, ##__VA_ARGS__)
#define warning(fmt, ...) dns_log(LOG_WARNING, fmt, ##__VA_ARGS__)
#define error(fmt, ...) dns_log(LOG_ERR, fmt, ##__VA_ARGS__)
#define fatal(fmt, ...) do { dns_log(LOG_ERR, fmt, ##__VA_ARGS__); exit(EXIT_FAILURE); }while(0)
#define debug(fmt, ...) dns_log(LOG_DEBUG, fmt, ##__VA_ARGS__)

#endif
