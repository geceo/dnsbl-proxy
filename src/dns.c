#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib.h>
#include <glib/gprintf.h>

#include <event2/event-config.h>
#include <event2/event.h>
#include <event2/dns_struct.h>
#include <event2/dns.h>
#include <event2/util.h>

#include "types.h"
#include "config.h"
#include "tools.h"

GSList *questions;

long int localhost = 0x0100007F;

float get_timespent(struct timespec b, struct timespec e)
{
	float ret = 0;
#ifdef TIMEMEASURE
	int tmp;

	ret = (e.tv_nsec * .000001) - (b.tv_nsec * .000001);

	tmp = (int)(e.tv_sec - b.tv_sec) * 1000;


	ret += tmp;

#endif
	return (ret);
}


int send_answer(struct evdns_server_request *r, int ret, void *value, struct timespec *timestamp)
{
	struct timespec end;
	/* TTL hardcoded to 10 */
	if (value) {
		if (r->questions[0]->type == EVDNS_TYPE_A)
			evdns_server_request_add_a_reply(r, r->questions[0]->name, 1, (int *)value, 10);
		else if (strcmp(value, "")) {
			char *tmp = g_strdup(value);
			char *tmp2 = tmp;

			do {
				if (*tmp2 == '.')
					*tmp2 = '_';
			} while (*(++tmp2));

			tmp2 = g_malloc(sizeof(char) * 63);
			snprintf(tmp2, 63, "dnsbl: %s", tmp);
			evdns_server_request_add_reply(r, EVDNS_ANSWER_SECTION, r->questions[0]->name, EVDNS_TYPE_TXT,
						       EVDNS_CLASS_INET, 10, -1, 1, tmp2);
			g_free(tmp2);
			g_free(tmp);
		}
	}
	if (evdns_server_request_respond(r, ret) < 0)
		return (-1);
	if (timestamp) {
#ifdef TIMEMEASURE
		clock_gettime(CLOCK_REALTIME, &end);
#endif
		debug("time elapse after sending response: %f", get_timespent(*timestamp, end));
	}
	return (0);
}

void dns_question_callback(int result, char type, int count, int ttl, void *addresses, void *arg)
{

	struct pending_request_t *pr;
	struct dnsbl_server_t *srv;

	struct cb_datas_t *cb_data;
	cb_data = (struct cb_datas_t *)arg;

	pr = cb_data->req;
	srv = cb_data->srv;
	pr->pending_srv--;
	debug("%p %p %p %p\n",pr->client,pr->original_ip,pr->srv,pr);

	switch (result) {
		case DNS_ERR_NONE:
			if (count > 0) {
				pr->listed = TRUE;
				debug("[%s] %s is listed by %s", pr->client, pr->original_ip, srv->name);
				pr->srv[pr->srv_idx] = srv->name;
				pr->srv_idx++;
				break;
			}
		case DNS_ERR_NOTEXIST:
			debug("[%s] %s is not listed by %s", pr->client, pr->original_ip, srv->name);
			break;
		default:
			notice("[%s] %s failed to resolv with %s [ret:%d|type:%d|count:%d|ttl:%d]",
				  pr->client, pr->original_ip, srv->name, result, type, count, ttl);
	}

	/* We aren't waiting for any result anymore, so let's answer and cache it ! */
	if (pr->pending_srv <= 0) {
		char status[255] = "not listed";
		void *tmp = NULL;
		char *name;
		int type = pr->r->questions[0]->type;
		int err = DNS_ERR_NONE;
#ifdef TIMEMEASURE
		struct timespec end;
#endif
		if (pr->listed) {
			if (pr->srv_idx <= 1) {
				g_strlcpy(status, pr->srv[0], 255);
			} else {
				char *tmp1;
				tmp1 = g_strjoinv("/", pr->srv);
				/* Max length for a TXT record is 255 bytes */
				g_snprintf(status, 254, "%s", tmp1);
				g_free(tmp1);
			}
			if (type == EVDNS_TYPE_TXT) {
				tmp = (void *)status;
			} else {
				tmp = &localhost;
			}
		} else {
			err = DNS_ERR_NOTEXIST;
		}
		/* Make answer authoritative */
		name = g_strdup(pr->r->questions[0]->name);
		/* Answer */
#ifdef TIMEMEASURE
		clock_gettime(CLOCK_REALTIME, &end);
#endif
		if (send_answer(pr->r, err, tmp, &pr->timestamp) < 0)
			error("Got a pb while sending answer !");
		else
#ifdef TIMEMEASURE
			message("[%s] response sent in %4fsec : %s is %s%s", pr->client,
				  get_timespent(pr->timestamp, end),
				  name, pr->listed ? "listed on " : "not listed", pr->listed ? status : "");
#else
			message("[%s] response sent: %s is %s%s", pr->client,
				  name, pr->listed ? "listed on " : "not listed", pr->listed ? status : "");
#endif
		/* Then we cache */
		debug("[%s] Adding answer to cache", pr->client);
		set_cache_name(name, pr->listed, status);

		debug("%p %p %p %p\n",pr->client,pr->original_ip,pr->srv,pr);
		g_free(pr->client);
		g_free(pr->original_ip);
		g_free(pr->srv);
		g_free(pr);
	}
	g_free(cb_data);
}

void dns_server_callback(struct evdns_server_request *r, void *data)
{
	int i;
	struct sockaddr_in client_sa;
	GMatchInfo *match = NULL;
	char *client = NULL;

	/* Fetch client IP */
	evdns_server_request_get_requesting_addr(r, (struct sockaddr *)&client_sa, sizeof(struct sockaddr_in));
	client = g_strdup(inet_ntoa(client_sa.sin_addr));

	/* Won't handle multiple questions this time ... */
	//    for (i=0;i<r->nquestions;i++)
	i = 0;
	do {
		record_t *cache;
		int j = 0;
		unsigned char ip[4] = { 0, 0, 0, 0 };
		struct dnsbl_server_t **ptr;
		struct pending_request_t *req;

		message("[%s] request for %s", client, r->questions[i]->name);

		/* Send back error if request isn't A or TXT field */
		if (r->questions[i]->type != EVDNS_TYPE_A && r->questions[i]->type != EVDNS_TYPE_TXT) {
			debug("[%s] Request type not supported %d", client, r->questions[i]->type);
			goto error;
		}
		/* Is the name ever cached ? Serve as it if it is ! */
		cache = get_cached_name(r->questions[i]->name);
		if (cache) {
			message("[%s] request hit cache ( %s %s )", client, cache->listed ? "listed by" : "unlisted",
				  cache->server);
			send_answer(r, cache->listed ? DNS_ERR_NONE : DNS_ERR_NOTEXIST,
				    r->questions[i]->type == EVDNS_TYPE_A ? (void *)&localhost : (void *)cache->server,
				    NULL);
			return;
		}


		/* Apply a "our served zone" regexp to r->questions[i]->name, 
		 * if it doesn't, send error */
		if (!g_regex_match(config->zone_regex, r->questions[i]->name, 0, &match)) {
			debug("[%s] Don't know what to do with name %s !", client, r->questions[i]->name);
			g_match_info_free(match);
			goto error;;
		}

		/* Retrieve 4 bytes of queried IP adress */
		while (g_match_info_matches(match)) {
			for (j = 1; j <= 4; j++) {
				char *tmp;
				tmp = g_match_info_fetch(match, j);
				ip[j - 1] = atoi(tmp);
				g_free(tmp);
			}
			g_match_info_next(match, NULL);
		}
		g_match_info_free(match);

		/* Building context struct to pass to callback */
		req = g_new0(struct pending_request_t,1);
		req->r = r;
		req->client = client;
		req->original_ip = g_new0(char,16);
		req->pending_srv = config->nb_srv;
		req->srv = g_new0(char *,config->nb_srv + 1);
		req->srv_idx = 0;
		req->listed = FALSE;
		debug("%p %p %p %p\n",req->client,req->original_ip,req->srv,req);
		g_snprintf(req->original_ip, 15, "%u.%u.%u.%u", ip[3], ip[2], ip[1], ip[0]);

#ifdef TIMEMEASURE
		clock_gettime(CLOCK_REALTIME, &(req->timestamp));
#endif

		message("[%s] Dispatching query %s for %s!", client,
			  r->questions[i]->type == EVDNS_TYPE_TXT ? "TXT" : "A", req->original_ip);

		/* Now, query this is on each dnsbl servers */
		ptr = config->servers;
		do {
			char *name;
			/* prepare datas for callback */
			struct cb_datas_t *datas;
			datas = g_malloc(sizeof(struct cb_datas_t));
			datas->req = req;
			datas->srv = *ptr;
			name = g_malloc(strlen((*ptr)->fmt) + 13);
			g_sprintf(name, (*ptr)->fmt, ip[0], ip[1], ip[2], ip[3]);
			evdns_base_resolve_ipv4((*ptr)->evdnsBase, name, DNS_QUERY_NO_SEARCH,
						dns_question_callback, datas);
			g_free(name);
		} while (*(++ptr));

	} while (0);		// Only one question ...
	return;
error:
	g_free(match);
	if (evdns_server_request_respond(r, DNS_ERR_REFUSED) < 0)
		error("Failed sending response !");
	g_free(client);
	return;
}
