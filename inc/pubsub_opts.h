#ifndef PUBSUB_OPTS_H
#define PUBSUB_OPTS_H

struct pubsub_opts
{
	/* debug app options */
	int publisher;  /* publisher app? */
	int quiet;
	int verbose;
	int tracelevel;
	char* delimiter;
	int maxdatalen;
	/* message options */
	char* message;
	char* filename;
	int stdin_lines;
	int stdlin_complete;
	int null_message;
	/* MQTT options */
	int MQTTVersion;
	char* topic;
	char* clientid;
	int qos;
	int retained;
	char* username;
	char* password;
	char* host;
	char* port;
	char* connection;
	int keepalive;
	/* will options */
	char* will_topic;
	char* will_payload;
	int will_qos;
	int will_retain;
	/* TLS options */
	int insecure;
	char* capath;
	char* cert;
	char* cafile;
	char* key;
	char* keypass;
	char* ciphers;
	char* psk_identity;
	char* psk;
	/* MQTT V5 options */
	int message_expiry;
	struct {
		char *name;
		char *value;
	} user_property;
	/* websocket HTTP proxies */
	char* http_proxy;
	char* https_proxy;
};

typedef struct
{
	const char* name;
	const char* value;
} pubsub_opts_nameValue;

#endif
