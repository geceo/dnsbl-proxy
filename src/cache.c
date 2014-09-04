#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <time.h>
#include <sys/time.h>
#include <event2/event_struct.h>
#include <event2/event.h>
#include <event2/util.h>

#include "types.h"
#include "tools.h"

/*
 * TODO: 
 *      Thread Safe IT !!!!
 *      Add a function for freeing memory when item removed
 *
 */
GHashTable *cache;
time_t cache_timeout;


record_t *get_cached_name(const char *name)
{
	return ((record_t *) g_hash_table_lookup(cache, name));
}

void set_cache_name(char *name, gboolean listed, char *server)
{
	record_t *c;
	c = g_new0(record_t,1);
	c->listed = listed;
	c->name = g_strdup(name);
	c->server = g_strdup(server);
	c->ctime = time(NULL);
	g_hash_table_insert(cache, name , c);
}


gboolean checkCacheItem(gpointer name, gpointer value, gpointer data)
{
	record_t *item = value;
    struct timeval *now,lifetime;
    now = (struct timeval *) data;
    timersub(now,item->ctime,&lifetime);
	if(!timercmp(&lifetime,cacheTimeout,<=)){
        g_debug("Purging entry %s %p",(char *) name,&name);
        return(TRUE);
	}
	return (FALSE);
}

void dumpCacheItem(gpointer name, gpointer value, gpointer data)
{
	record_t *item = value;
	if (item->listed)
		debug("%s on (%s).", (char *)name, item->server);
	else
		debug("%s clear.", (char *)name);
}


void cache_cleanup(struct event *timer)
{
	int deleted = 0;
	time_t now;
	debug("Cleaning cache");
	now = time(NULL);
	deleted = g_hash_table_foreach_remove(cache, (GHRFunc) checkCacheItem, &now);
	notice("Removed %d keys (%d in cache)", deleted, g_hash_table_size(cache));
}


void cache_dump()
{
	g_hash_table_foreach(cache, dumpCacheItem, NULL);
}

void free_value(gpointer data)
{
	record_t *r = (record_t *) data;
	if(r->name)
	   g_free(r->name);
	if (r->server)
	   g_free(r->server);
	g_free(r);					
}

void free_key(gpointer data)
{
	if (data)
		g_free(data);
}

void cache_init(time_t timeout)
{
	cache = g_hash_table_new_full(g_str_hash, g_str_equal, free_key, free_value);
	cache_timeout = timeout;
}

void cache_destroy()
{
	g_hash_table_destroy(cache);
}

#ifdef TEST_CACHE
int main(int ac, char **av)
{
	int i,j;
	cache_init(1);
	for (j=0; j<4 ; j++){
		for (i=0; i< 500000; i++) {
			char *pouet;
			pouet = g_malloc(16);
			sprintf(pouet,"%.5d",i);
			set_cache_name(pouet,1,pouet);
		}
		printf("Sleeping before cleanup !\n");
		sleep(3);
		cache_cleanup(NULL);
		printf("Sleeping after cleanup !\n");
		sleep(3);
	}
	printf("Sleeping a bit again !\n");
	sleep(10);
	return(0);

}
#endif
