sbin_PROGRAMS=dnsbl-proxy
noinst_PROGRAMS=test_cache test_tools

dnsbl_proxy_SOURCES = cache.c config.c tools.c dns.c main.c 
test_cache_SOURCES = cache.c tools.c 
test_cache_CFLAGS = ${CFLAGS} -DTEST -DTEST_CACHE

test_tools_SOURCES = cache.c tools.c
test_tools_CFLAGS = ${CFLAGS} -DTEST -DTEST_TOOLS

