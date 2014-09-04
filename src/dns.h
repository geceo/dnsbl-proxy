
void dns_question_callback(int result,char type, int count, int ttl, void *addresses, void *arg);
void dns_server_callback(struct evdns_server_request *r, void *data);
