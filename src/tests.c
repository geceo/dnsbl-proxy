#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>

#include <syslog.h>

#include <event2/event-config.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns_struct.h>
#include <event2/dns.h>
#include <event2/util.h>

#include "types.h"
#include "config.h"
#include "tools.h"
#include "dns.h"


int test_cache()
{
	struct timeval timeout;
	printf("Test cache");
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	cache_init(&timeout);
	debug("t = 0\n");
	set_cache_name("Test 1", TRUE, "test.org");
	set_cache_name("Test 2", FALSE, NULL);
	set_cache_name("Test 3", TRUE, "google.fr");
	cache_dump();
	sleep(3);
	debug("t = 3\n");
	set_cache_name("Test 4", FALSE, NULL);
	set_cache_name("Test 5", FALSE, NULL);
	sleep(2);
	debug("t = 5\n");
	cache_cleanup();
	cache_dump();
	sleep(10);
	debug("t = 15\n");
	cache_cleanup();
	cache_dump();
	return (0);
}

int test_config()
{
	debug("%d debug", G_LOG_LEVEL_DEBUG);
	message("%d info", G_LOG_LEVEL_INFO);
	error("%d error", G_LOG_LEVEL_ERROR);
	config_init("/etc/ospow/dnsbl-proxy.conf");
	debug("%d debug", G_LOG_LEVEL_DEBUG);
	message("%d info", G_LOG_LEVEL_INFO);
	error("%d error", G_LOG_LEVEL_ERROR);
	return (0);
}



int main(int ac, char **av)
{
	printf("taille d'1 enregistrement %d\n", sizeof(record_t));
	test_config();
	test_cache();
}
