[general]
zone = @@ZONE@@
port = 53
# timeout in seconds
timeout = 1
# logfile or syslog:facility
log = syslog:daemon
# loglevel 
loglevel = INFO
# Server list, coma separeted
server_list = sbl-xbl.spamhaus.org, cbl.abuseat.org, dnsbl.sorbs.net, spam.spam-rbl.fr,rbl.jp,dul.ru
# cache_timeout for cachelifetime (in seconds ...)
cache_timeout = 3600
# Debug = 1 for avoiding background launch ...
debug = 0
