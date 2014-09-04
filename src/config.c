#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>

#include <glib.h>
#include <glib/gprintf.h>
#include <event2/event-config.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/util.h>

#include "types.h"
#include "config.h"
#include "tools.h"
#include "dns.h"

void free_config()
{
	struct dnsbl_server_t **ptr;

	/* Allocated stuff */
	g_free(config->zone);
	g_free(config->logging);
	g_free(config->server_list);
	g_regex_unref(config->zone_regex);

	/* Free dnsbl servers */
	ptr = config->servers;
	while (*ptr) {
		struct dnsbl_server_t *srv = *ptr;
		free(srv->name);
		free(srv->fmt);
		/* free srv->evdnsBase */
		evdns_base_free(srv->evdnsBase,0);
		free(srv);
		ptr++;
	}

	/* Finish with event base */
	if( event_base_loopexit(config->event_base,NULL) < 0)
		error("abortion of event base failed !");

	event_base_free(config->event_base);
	g_free(config);
	cache_destroy();

	return;
}


void sig_handler(int signum)
{
	error("In cleanup function !");
	free_config();
}



int initialize_servers(char *value)
{
	char **ptr, **ptrr;
	int nb_srv = 0, i = 0;

	ptr = ptrr = g_strsplit(value, ",", 30);

	while (*(ptrr++))
		nb_srv++;

	notice("Configuring %d servers...", nb_srv);
	config->servers = g_new0(struct dnsbl_server_t *,nb_srv + 1);

	ptrr = ptr;
	while (ptrr && *ptrr) {
		char *tmp = "%d.%d.%d.%d.";
		struct dnsbl_server_t *s;
		g_strstrip(*ptrr);
		s = config->servers[i] = g_malloc(sizeof(struct dnsbl_server_t));
		s->name = g_strdup(*ptrr);
		s->fmt = g_malloc(strlen(s->name) + strlen(tmp) + 1);
		g_sprintf(s->fmt, "%s%s", tmp, s->name);
		s->evdnsBase = NULL;
		if (config_dnsbl_server(s, config->event_base) < 0) {
			warning("NS record can't be found, server %s ignored !", s->name);
			g_free(s->fmt);
			g_free(s->name);
			g_free(s);
		} else {
			message("%s OK.", s->name);

			i++;
		}
		ptrr++;
	}
	config->servers[i] = 0;
	config->nb_srv = i;
	notice("%d/%d DNSBL servers configured.", config->nb_srv, nb_srv);
	g_strfreev(ptr);
	return (config->nb_srv);
}

void configure_logging(char *logging)
{
	char **log;
	log = g_strsplit(logging, ":", 2);
	if (!strcmp(log[0], "syslog") && log[1]) {
		int facility;
		facility = resolve_facility(log[1]);
		if (facility < 0) {
			error("syslog facility %s isn't supported: \
                    choose between mail/daemon/syslog or \
                    local0 to local7", log[1]);
			exit(0);
		}
		message("Logging to syslog (facility %s)\n", log[1]);
		close(0);
		close(1);
		close(2);
		openlog("ospow-dnsbl-proxy", LOG_PID, facility);
		config->logger = log2syslog;
	} else {
		message("Other logging than syslog not supported yet logging to console.");
		config->logger = log2stdout;

	}
	free(log);
}

void config_init(const char *path)
{
	GKeyFile *kfile =NULL;
	gchar **keys = NULL;
	struct sockaddr_in sa;
	struct passwd *nobody;
	struct timeval tv;
	int i, ii = 0;

	config = g_new0(struct config_t, 1);
	/* Set defaults that differs from NULL/0 ... */
	config->timeout = 1;
	/* We set this temporary, to get logs ... */
	config->logger = log2stdout;
	config->logging = "syslog:daemon";
	config->cache_timeout = 3600;
	config->port = 53;
	config->loglevel = G_LOG_LEVEL_INFO;

	/* Parse our files */
	kfile = g_key_file_new();
	debug("Parsing %s", path);
	/* Load file */
	if (!g_key_file_load_from_file(kfile, path, G_KEY_FILE_NONE, NULL)) {
		error("Error while loading %s, is it a correct .ini file ?", path);
		goto cleanExit;
	}
	/* Check if general section is available */
	if (!g_key_file_has_group(kfile, "general")) {
		error("%s doesn't have [general] section, skipping ...", path);
		goto cleanExit;
	}
	/* Retrieve all keys ... */
	if (!(keys = g_key_file_get_keys(kfile, "general", NULL, NULL))) {
		error("Failed to load keys from %s", path);
		goto cleanExit;
	}
	/* Now, read the conf and store important parts */
	while (keys[ii]) {
		char *value;
		value = g_key_file_get_value(kfile, "general", keys[ii], NULL);
		if (!strcmp(keys[ii], "log"))
			config->logging = g_strdup(value);

		/* Parse Timeout */
		else if (!strcmp(keys[ii], "timeout")) {
			config->timeout = atoi(value);
			debug("timeout is %d sec", config->timeout);
		}
		/* Parse Cache Timeout */
		else if (!strcmp(keys[ii], "cache_timeout")) {
			config->cache_timeout = atof(value);
			debug("cache timeout is %d sec", config->cache_timeout);
				
		}
		/* Parse Zone */
		else if (!strcmp(keys[ii], "zone")) {
			char *begin = "(\\d{0,3}).(\\d{0,3}).(\\d{0,3}).(\\d{0,3}).";
			gchar *pattern;
			config->zone = g_strdup(value);
			pattern = g_malloc(strlen(begin) + strlen(config->zone) + 3);
			g_sprintf(pattern, "^%s%s$", begin, config->zone);
			debug("Pattern for zone is %s", pattern);
			config->zone_regex = g_regex_new(pattern, G_REGEX_CASELESS, 0, NULL);
			g_free(pattern);
		}
		/* Debug mode ?? */
		else if (!strcmp(keys[ii], "debug")) {
			config->debug = atoi(value);
		}
		/* Server list... we'll parse later ! */
		else if (!strcmp(keys[ii], "server_list")) {
			config->server_list = g_strdup(value);
		}
		/* UDP port to listen to ... */
		else if (!strcmp(keys[ii], "port")) {
			config->port = atoi(value);
			if (config->port < 0 || config->port > 65535)
				error("%d isn't a valid UDP port number.", config->port);
		} else if (!strcmp(keys[ii], "loglevel")) {
			if (!strcmp("ERROR", value)) {
				config->loglevel = LOG_ERR;
			} else if (!strcmp("WARNING", value)) {
				config->loglevel = LOG_WARNING;
			} else if (!strcmp("NOTICE", value)) {
				config->loglevel = LOG_NOTICE;
			} else if (!strcmp("INFO", value)) {
				config->loglevel = LOG_INFO;
			} else if (!strcmp("DEBUG", value)) {
				config->loglevel = LOG_DEBUG;

			} else {
				error("Loglevel %s not supported, choose (verbosity increasing) ERROR, WARNING, NOTICE, INFO or DEBUG",
					value);
				exit(EXIT_FAILURE);
			}
			message("Logging to level %s", value);
		}
		ii++;
		g_key_file_remove_key(kfile,"general",keys[ii],NULL);
		g_free(value);
	}
	g_key_file_remove_group(kfile,"general",NULL);
	g_strfreev(keys);
	g_key_file_free(kfile);


	/* Binding signal */
	signal(SIGSTOP,sig_handler);
	signal(SIGTERM,sig_handler);
	signal(SIGINT,sig_handler);

	/* If we aren't in mode debug, daemonize */
	if (!config->debug) {
		int pid;
		/* First, change working dir */
		if (chdir("/") < 0)
			error("Failed while chdir()-ing: %s", strerror(errno));
		/* The fork() and setsid() */
		pid = fork();
		if (pid < 0)
			error("Failed while fork()-ing ... ");
		else if (pid > 0) {
			exit(0);
		}
		/* We're in child */
		if (setsid() < 0)
			error("Failed while setsid()-ing ... ");
		/* Configure logging ... */
		configure_logging(config->logging);
		event_set_log_callback(logevent_logger);
		evdns_set_log_fn(logevent_logger);
	}else{
		notice("Skipping daemonization process (debug mode activated)");
	}
	/* Create event base */
	if (!(config->event_base = event_base_new()))
		error("Failed while creating event base, fatal !");

	/* Now we initialize servers */
	if (initialize_servers(config->server_list) < 0)
		error("We don't have any working DNSBL server configured (all of them failed) ... exiting !");

	/* Here we must have timeout and servers list set , so we can now set timeout on evdns_base */
	for (i = 0; i < config->nb_srv; i++) {
		char timeout[256];
		g_snprintf(timeout, 255, "%i", config->timeout);
		evdns_base_set_option(config->servers[i]->evdnsBase, "timeout", timeout);
		evdns_base_set_option(config->servers[i]->evdnsBase, "initial-probe-timeout", timeout);
		evdns_base_set_option(config->servers[i]->evdnsBase, "max-timeouts:", "1");
	}

	/* Open UDP port, bind it and give it to libevent */
	if ((config->s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fatal("Failed to create socket: %s", strerror(errno));
	}
	evutil_make_socket_nonblocking(config->s);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(config->port);
	sa.sin_addr.s_addr = INADDR_ANY;

	if (bind(config->s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fatal("Failed to bind socket: %s", strerror(errno));
	}
	evdns_add_server_port_with_base(config->event_base, config->s, 0, dns_server_callback, NULL);

	/* Add a timer for cache cleanup */
	config->timer_ev = event_new(config->event_base, -1, EV_PERSIST, (event_callback_fn) cache_cleanup, NULL);
	tv.tv_sec = config->cache_timeout;
	tv.tv_usec = 0;
	evtimer_add(config->timer_ev, &tv);
	/* Change user, security, security ... */
	if (config->debug == 0) {
		if (!(nobody = getpwnam("nobody"))) {
			fatal("User nobody doesn't exist, can't set{e,}uid() ! Fatal !");
		}
		if (!setegid(nobody->pw_gid) && !seteuid(nobody->pw_uid)) {
			message("Successfuly changed user to nobody");
		} else {
			fatal("Failed changing user to nobody, fatal");
		}

	}

	notice("DNSBL Proxy successfully launched !");
	return;
cleanExit:
	exit(0);
}
