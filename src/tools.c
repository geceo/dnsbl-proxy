#define _BSD_SOURCE
#include <netinet/ip.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


#include <arpa/nameser.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>

#include <event2/event-config.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/util.h>

#include "types.h"
#include "tools.h"

#define rdata_to_long(rdata) do { } while(0);

/* Taken "as is" from syslog.h */
#define INTERNAL_NOPRI  0x10


#ifndef TEST
extern struct config_t *config;
#endif

typedef struct _code {
        char    *c_name;
        int     c_val;
} CODE;

CODE prioritynames[] =
  {
    { "alert", LOG_ALERT },
    { "crit", LOG_CRIT },
    { "debug", LOG_DEBUG },
    { "emerg", LOG_EMERG },
    { "err", LOG_ERR },
    { "error", LOG_ERR },               /* DEPRECATED */
    { "info", LOG_INFO },
    { "none", INTERNAL_NOPRI },         /* INTERNAL */
    { "notice", LOG_NOTICE },
    { "panic", LOG_EMERG },             /* DEPRECATED */
    { "warn", LOG_WARNING },            /* DEPRECATED */
    { "warning", LOG_WARNING },
    { NULL, -1 }
  };

int resolve_facility(char *facility)
{
	GString *string = g_string_new(facility);
	g_string_ascii_down(string);
	char *f = (char *)string->str;
	if (!strcmp("mail", f))
		return LOG_MAIL;
	if (!strcmp("daemon", f))
		return LOG_DAEMON;
	if (!strcmp("syslog", f))
		return LOG_SYSLOG;
	if (!strcmp("local0", f))
		return LOG_LOCAL0;
	if (!strcmp("local1", f))
		return LOG_LOCAL1;
	if (!strcmp("local2", f))
		return LOG_LOCAL2;
	if (!strcmp("local3", f))
		return LOG_LOCAL3;
	if (!strcmp("local4", f))
		return LOG_LOCAL4;
	if (!strcmp("local5", f))
		return LOG_LOCAL5;
	if (!strcmp("local6", f))
		return LOG_LOCAL6;
	if (!strcmp("local7", f))
		return LOG_LOCAL7;
	g_string_free(string, TRUE);
	return (-1);
}

void logevent_logger(int severity, const char *msg)
{
	debug("libevent(%d): %s", severity, msg);
}


void log2stdout(int severity, const char *fmt, va_list list)
{
	char *fmt2;
	int i=0;
	CODE *sname;

	sname = prioritynames;
	while(sname[i].c_val != severity)
		i++;
	fmt2 = malloc(sizeof(char) * (strlen(fmt) + 50));
	sprintf(fmt2,"[%s] %s\n",
			sname[i].c_name ? sname[i].c_name : "UNKNOWN",
			fmt);

	vprintf(fmt2,list);
	free(fmt2);
}

void log2syslog(int severity, const char *fmt, va_list list)
{
	vsyslog(severity,fmt,list);
}

void dns_log(int severity, const char *fmt, ...)
{
	va_list list;
	va_start(list, fmt);
#ifndef TEST
	if (!config->loglevel || severity > config->loglevel)
		goto end;
	if (config->logger)
		config->logger(severity,fmt,list);
	else
#endif
	log2stdout(severity,fmt,list);
end:
	va_end(list);
	return;
}




struct sockaddr_in **get_domain_ns_fallback(char *domain)
{
	unsigned char answer[8192];
	struct sockaddr_in **ns = NULL;
	int ii, i = 0, j = 0, ret = 0, nb_servers = 0;

	ns_msg parser;
	ns_rr rr;


	debug("In %s(%s)", __FUNCTION__, domain);

	ret = res_query(domain, C_IN, T_A, answer, 8192);
	if (ret < 0) {
		debug(" Got no result for %s", domain);
		return (NULL);
	}

	if (ns_initparse(answer, ret, &parser) < 0) {
		debug(" Failed to ns_initparse() for %s", domain);
		return (NULL);
	}

	for (ii = 0; ii < 3; ii++) {
		ret = ns_msg_count(parser, ns_s_an);
		if (ret < 0) {
			debug(" Failed to ns_msg_count() for %s", domain);
			return (NULL);
		}

		/* We limit to 5 servers ... */
		debug(" Got %d records", ret);
		nb_servers = (ret > 5) ? 5 : ret;
		ns = calloc(nb_servers + 1, sizeof(struct sockaddr *));

		j = 0;
		for (i = 0; i < nb_servers; i++) {
			char rName[MAXDNAME];

			ns_parserr(&parser, ns_s_an, i, &rr);
			debug(" ns_rr_type is %d", ns_rr_type(rr));
			if (ns_rr_type(rr) == ns_t_ns) {
				if (ns_name_uncompress(ns_msg_base(parser), ns_msg_end(parser),
						       ns_rr_rdata(rr), rName, MAXDNAME) >= 0) {
					/* Code below seems to create problem in a static binary :( */
					int rv;
					struct addrinfo *r;
					struct addrinfo hint;
					hint.ai_family = AF_INET;
					hint.ai_socktype = SOCK_DGRAM;
					hint.ai_protocol = 0;
					hint.ai_flags = AI_NUMERICSERV;
					/* XXX: Here, an array may be returned (Round Robin, ...) but we only deal with first element */
					if (!(rv = getaddrinfo(rName, "53", &hint, &r))) {
						struct sockaddr_in *addr;
						addr = (struct sockaddr_in *)r->ai_addr;
						ns[j] = malloc(sizeof(struct sockaddr_in));
						memcpy(ns[j], addr, sizeof(struct sockaddr_in));
						debug(" addr is %s", inet_ntoa(ns[j]->sin_addr));
						j++;
						freeaddrinfo(r);
					} else {
						debug("error while resolving %s : %s\n", rName, gai_strerror(rv));
					}
				}
			} else if (ns_rr_type(rr) == ns_t_a) {
				struct in_addr tmp;
				memcpy(&(tmp.s_addr), ns_rr_rdata(rr), ns_rr_rdlen(rr));
				debug(" addr is %s", inet_ntoa(tmp));

			}
		}
		ns[j] = 0;
	}
	return (ns);
}

/*
 * TODO: review this code.
 */
struct sockaddr_in **get_domain_ns(char *domain)
{
	unsigned char answer[81920];
	struct sockaddr_in **ns = NULL;
	int i = 0, j = 0, ret = 0, nb_servers = 0;

	ns_msg parser;
	ns_rr rr;

	res_init();

	ret = res_query(domain, C_IN, T_NS, answer, 81920);
	if (ret < 0) {
		debug(" Got no result for %s", domain);
		return (NULL);
	}

	if (ns_initparse(answer, ret, &parser) < 0) {
		debug(" Failed to ns_initparse() for %s", domain);
		return (NULL);
	}

	ret = ns_msg_count(parser, ns_s_an);
	if (ret < 0) {
		debug(" Failed to ns_msg_count() for %s", domain);
		return (NULL);
	}

	/* We limit to 5 servers ... */
	debug(" Got %d records", ret);
	nb_servers = (ret > 5) ? 5 : ret;
	ns = calloc(nb_servers + 1, sizeof(struct sockaddr *));

	j = 0;
	for (i = 0; i < nb_servers; i++) {
		char rName[MAXDNAME];

		ns_parserr(&parser, ns_s_an, i, &rr);
		if (ns_rr_type(rr) == ns_t_ns) {
			if (ns_name_uncompress(ns_msg_base(parser), ns_msg_end(parser),
					       ns_rr_rdata(rr), rName, MAXDNAME) >= 0) {
				/* Code below seems to create problem in a static binary :( */
				int rv;
				struct addrinfo *r;
				struct addrinfo hint;
				hint.ai_family = AF_INET;
				hint.ai_socktype = SOCK_DGRAM;
				hint.ai_protocol = 0;
				hint.ai_flags = AI_NUMERICSERV;
				/* XXX: Here, an array may be returned (Round Robin, ...) but we only deal with first element */
				if (!(rv = getaddrinfo(rName, "53", &hint, &r))) {
					struct sockaddr_in *addr;
					addr = (struct sockaddr_in *)r->ai_addr;
					ns[j] = malloc(sizeof(struct sockaddr_in));
					memcpy(ns[j], addr, sizeof(struct sockaddr_in));
					debug(" addr is %s", inet_ntoa(ns[j]->sin_addr));
					j++;
					freeaddrinfo(r);
				} else {
					debug(" error while resolving %s : %s\n", rName, gai_strerror(rv));
				}
			} else {
				debug(" ns_name_uncompres() failed");
			}

		} else {
			debug("ns record isn't in good type");
		}
	}
	ns[j] = 0;
	return (ns);
}

int config_dnsbl_server(struct dnsbl_server_t *s, struct event_base *base)
{
	struct sockaddr_in **nameservers, **ptr;

	ptr = nameservers = get_domain_ns(s->name);
	if (!nameservers || !(*nameservers)) {
		debug(" Failed while configuring %s.", s->name);
		return (-1);
	}
	s->evdnsBase = evdns_base_new(base, 0);
	evdns_base_search_clear(s->evdnsBase);
	while (ptr && *ptr) {
		if (!
		    (evdns_base_nameserver_sockaddr_add
		     (s->evdnsBase, (const struct sockaddr *)*ptr, sizeof(struct sockaddr_in), 0))) {
			debug(" registered %s successfuly.", inet_ntoa((*ptr)->sin_addr));
		} else {
			debug(" failed to register %s.", inet_ntoa((*ptr)->sin_addr));
		}
		free(*ptr);
		ptr++;
	}
	free(nameservers);
	return (0);
}

#ifdef TEST_TOOLS
int main(int ac, char **av)
{
	if (ac == 2) {
		message("Resolving %s", av[1]);
		get_domain_ns(av[1]);
		get_domain_ns_fallback(av[1]);
	} else {
		printf("usage: %s <domain>", av[0]);
	}
	return (0);

}
#endif
