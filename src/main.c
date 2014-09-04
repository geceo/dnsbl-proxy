#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>

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

int sighandler(int signum, void *a)
{

}


/*
 * TODO: 
 *      _ Implement signal catching to stop server
 *      _ Implement pidfile.
 *      _ 
 */
int main(int ac, char **av)
{
	if (ac == 2)
		config_init(av[1]);
	else
		config_init("/etc/ospow/dnsbl-proxy.conf");

	cache_init(config->cache_timeout);

	/* Set logging callback */
	//event_set_log_callback(logevent_logger);
	event_base_dispatch(config->event_base);

	/* Ending ... */
	message("Event loop stopped ... exiting !");
	cache_destroy();
	exit(EXIT_SUCCESS);
}
