#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>
#include <libpq-fe.h>
#include <math.h>
#include <signal.h>
#include <time.h>

#include <errno.h>

#include <ulfius.h>

#include "gateway_protocol.h"
#include "gateway_telemetry_protocol.h"
#include "base64.h"
#include "task_queue.h"
#include "jansson.h"
#include "aes.h"
#include "gw_stat_linked_list.h"


#define TIMEDATE_LENGTH			32
#define PEND_SEND_RETRIES_MAX		5
#define GATEWAY_PROTOCOL_APP_KEY_SIZE	8
#define DEVICE_DATA_MAX_LENGTH		256
#define GATEWAY_SECURE_KEY_SIZE		16
#define GATEWAY_ID_SIZE			6


typedef struct {
	char 		db_addr[15+1];
	uint16_t 	db_port;
	char 		db_name[32];
	char 		db_user_name[32];
	char 		db_user_pass[32];
	uint32_t	telemetry_send_period;
} dynamic_conf_t;

typedef struct {
	uint8_t 	gw_id[GATEWAY_ID_SIZE];
	uint8_t 	gw_secure_key[GATEWAY_SECURE_KEY_SIZE];
	uint16_t 	gw_port;
	char 		db_type[20];
	char 		platform_gw_manager_ip[20];
	uint16_t 	platform_gw_manager_port;
	uint8_t 	thread_pool_size;
} static_conf_t;

typedef struct {
	static_conf_t  static_conf;
	dynamic_conf_t dynamic_conf;
} gw_conf_t;

typedef struct {
	uint32_t utc;
	char timedate[TIMEDATE_LENGTH];

	uint8_t data[DEVICE_DATA_MAX_LENGTH];
	uint8_t data_length;
} sensor_data_t;

typedef struct {
	gateway_protocol_conf_t gwp_conf;
	int server_desc;
	int client_desc;
	struct sockaddr_in server;
	struct sockaddr_in client;
	unsigned int sock_len;
} gcom_ch_t; // gateway communication channel

typedef struct {
	gcom_ch_t gch;	
	gateway_protocol_packet_type_t packet_type;
	uint8_t packet[DEVICE_DATA_MAX_LENGTH];
	uint8_t packet_length;
} gcom_ch_request_t;

typedef struct {
	uint64_t errors_count;
} gw_stat_t;

static const char * static_conf_file  = "conf/static.conf";
static const char * dynamic_conf_file = "conf/dynamic.conf";
static int read_static_conf (const char *static_conf_file_path,  gw_conf_t *gw_conf);
static int read_dynamic_conf(const char *dynamic_conf_file_path, gw_conf_t *gw_conf);
static void process_static_conf (json_t* value, static_conf_t  *static_conf);
static void process_dynamic_conf(json_t* value, dynamic_conf_t *dynamic_conf);
static json_t * read_json_conf(const char *file_path);

void process_packet(void *request);

uint8_t gateway_auth(const gw_conf_t *gw_conf, const char *dynamic_conf_file_path);
void	*gateway_mngr(void *gw_conf);

void gateway_protocol_data_send_payload_decode(
	sensor_data_t *sensor_data, 
	const uint8_t *payload, 
	const uint8_t payload_length);

uint8_t gateway_protocol_checkup_callback(gateway_protocol_conf_t *gwp_conf);

static int callback_get_epoch(
	const struct _u_request *request, 
	struct _u_response *response,
	void *user_data);
static int callback_post_data(
	const struct _u_request *request, 
	struct _u_response *response,
	void *user_data);

void ctrc_handler (int sig);

pthread_mutex_t mutex;
pthread_mutex_t gw_stat_mutex;
PGconn *conn;
	
task_queue_t *tq;

gw_stat_t gw_stat;

static volatile uint8_t finished = 0;

int main (int argc, char **argv) {
	gw_conf_t *gw_conf = (gw_conf_t *)malloc(sizeof(gw_conf_t));
	char *db_conninfo = (char *)malloc(512);
	pthread_t gw_mngr;
	struct _u_instance instance;
	sigset_t sigset;
	
	gw_stat.errors_count = 0;

	sigemptyset(&sigset);
	/* block SIGALRM for gateway manager thread */
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	signal(SIGINT, ctrc_handler);
	
	if (read_static_conf(static_conf_file, gw_conf)) {
		fprintf(stderr, "Static configuration loading failure.");
		return EXIT_FAILURE;
	}
	
	gateway_telemetry_protocol_init(gw_conf->static_conf.gw_id, gw_conf->static_conf.gw_secure_key);

	if (!gateway_auth(gw_conf, dynamic_conf_file)) {
		fprintf(stderr, "Gateway authentication failure.");
		return EXIT_FAILURE;
	}

	if (read_dynamic_conf(dynamic_conf_file, gw_conf)) {
		fprintf(stderr, "Read dynamic configuration failure.");
		return EXIT_FAILURE;
	}
	
	snprintf(db_conninfo, 512, 
			"hostaddr=%s port=%d dbname=%s user=%s password=%s", 
			gw_conf->dynamic_conf.db_addr,
			gw_conf->dynamic_conf.db_port,
			gw_conf->dynamic_conf.db_name,
			gw_conf->dynamic_conf.db_user_name,
			gw_conf->dynamic_conf.db_user_pass);
	
	printf("db_conf : '%s'\n", db_conninfo);

	conn = PQconnectdb(db_conninfo);
	
	snprintf(db_conninfo, 512, 
			"id=%s secure_key=%s port=%d type=%s thread_pool_size=%d telemetry_send_period=%d\n", 
			gw_conf->static_conf.gw_id,
			gw_conf->static_conf.gw_secure_key,
			gw_conf->static_conf.gw_port,
			gw_conf->static_conf.db_type,
			gw_conf->static_conf.thread_pool_size,
			gw_conf->dynamic_conf.telemetry_send_period);
	printf("gw_conf : '%s'\n", db_conninfo);
	free(db_conninfo);

	if (PQstatus(conn) == CONNECTION_BAD) {
		fprintf(stderr,"connection to db error: %s\n", PQerrorMessage(conn));
		free(gw_conf);
		exit(EXIT_FAILURE);
	}
	
	if (ulfius_init_instance(&instance, gw_conf->static_conf.gw_port, NULL, NULL) != U_OK) {
		fprintf(stderr,"ulfius initialization failure.\n");
		free(gw_conf);
		exit(EXIT_FAILURE);
	}

	ulfius_add_endpoint_by_val(&instance, "GET", "/get_epoch", NULL, 0, &callback_get_epoch, NULL);

	if (ulfius_start_framework(&instance) != U_OK) {
		fprintf(stderr,"ulfius starting framework failure.\n");
		free(gw_conf);
		exit(EXIT_FAILURE);
	} else {
		printf("Starting ulfius on port %d\n", instance.port);
	}

	if (pthread_create(&gw_mngr, NULL, gateway_mngr, gw_conf)) {
		fprintf(stderr, "Failed to create gateway manager thread.");
		free(gw_conf);
		exit(EXIT_FAILURE);
	}

	if(!(tq = task_queue_create(gw_conf->static_conf.thread_pool_size))) {
		perror("task_queue creation error");
		free(gw_conf);
		exit(EXIT_FAILURE);
	}

	pthread_mutex_init(&mutex, NULL);
	pthread_mutex_init(&gw_stat_mutex, NULL);

	gateway_protocol_set_checkup_callback(gateway_protocol_checkup_callback);

	gw_stat_linked_list_init();
	
	while(!finished);

	ulfius_stop_framework(&instance);
	ulfius_clean_instance(&instance);

	free(gw_conf);
	pthread_mutex_destroy(&mutex);
	pthread_mutex_destroy(&gw_stat_mutex);
	PQfinish(conn);

	return EXIT_SUCCESS;
}

void ctrc_handler (int sig) {
	finished = 1;
}

void process_packet(void *request) {
	gcom_ch_request_t *req = (gcom_ch_request_t *)request;
	uint8_t payload[DEVICE_DATA_MAX_LENGTH];
	uint8_t payload_length;	
	PGresult *res;

	if (gateway_protocol_packet_decode(
		&(req->gch.gwp_conf),
		&(req->packet_type),
		&payload_length, payload,
		req->packet_length, req->packet))
	{
		if (req->packet_type == GATEWAY_PROTOCOL_PACKET_TYPE_DATA_SEND) {
			sensor_data_t sensor_data;
			time_t t;
			// DEVICE_DATA_MAX_LENGTH*2 {hex} + 150
			char db_query[662];

			printf("DATA SEND received\n");
			gateway_protocol_data_send_payload_decode(&sensor_data, payload, payload_length);
			
			if (sensor_data.utc == 0) {
				struct timeval tv;
				gettimeofday(&tv, NULL);
				t = tv.tv_sec;
			} else {
				t = sensor_data.utc;
			}
			
			strftime(sensor_data.timedate, TIMEDATE_LENGTH, "%d/%m/%Y %H:%M:%S", localtime(&t));
			snprintf(db_query, sizeof(db_query), 
				"INSERT INTO dev_%s_%d VALUES (%lu, '%s', $1)", 
				(char *)req->gch.gwp_conf.app_key, req->gch.gwp_conf.dev_id, t, sensor_data.timedate
			);
			
			const char *params[1];
			int paramslen[1];
			int paramsfor[1];
			params[0] = (char *) sensor_data.data;
			paramslen[0] = sensor_data.data_length;
			paramsfor[0] = 1; // format - binary

			pthread_mutex_lock(&gw_stat_mutex);
			gw_stat_linked_list_add((char *)req->gch.gwp_conf.app_key, req->gch.gwp_conf.dev_id);
			pthread_mutex_unlock(&gw_stat_mutex);

			pthread_mutex_lock(&mutex);
			res = PQexecParams(conn, db_query, 1, NULL, params, paramslen, paramsfor, 0);
			pthread_mutex_unlock(&mutex);

			if (PQresultStatus(res) != PGRES_COMMAND_OK) {
				fprintf(stderr, "database error : %s\n", PQerrorMessage(conn));
				gw_stat.errors_count++;
			}
			PQclear(res);
		} else {
			printf("weired packet type : %02X\n", req->packet_type);
		}	
	} else {
		fprintf(stderr, "payload decode error\n");
		gw_stat.errors_count++;
	}
		
	free(request);
}

uint8_t gateway_auth(const gw_conf_t *gw_conf, const char *dynamic_conf_file_path) {
	int sockfd;
	struct sockaddr_in platformaddr;
	uint8_t buffer[1024];
	uint16_t buffer_length = 0;
	uint8_t payload_buffer[1024];
	uint16_t payload_buffer_length = 0;
	FILE *fp;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return 0;
	}

	memset(&platformaddr, 0x0, sizeof(platformaddr));

	platformaddr.sin_family = AF_INET;
	platformaddr.sin_addr.s_addr = inet_addr(gw_conf->static_conf.platform_gw_manager_ip);
	platformaddr.sin_port = htons(gw_conf->static_conf.platform_gw_manager_port);
	
	if (connect(sockfd, (struct sockaddr *)&platformaddr, sizeof(platformaddr))) {
		return 0;
	}

	gateway_telemetry_protocol_encode_packet(buffer, 0, GATEWAY_TELEMETRY_PROTOCOL_AUTH, buffer, &buffer_length);
	write(sockfd, buffer, buffer_length);
	
	buffer_length = read(sockfd, buffer, sizeof(buffer));
	gateway_telemetry_protocol_packet_type_t pt;
	if (!gateway_telemetry_protocol_decode_packet(payload_buffer, &payload_buffer_length, &pt, buffer, buffer_length)) {
		return 0;
	}

	// write db_conf into file
	fp = fopen(dynamic_conf_file_path, "w");
	fwrite(payload_buffer, payload_buffer_length, 1, fp);
	fclose(fp);

	return 1;
}

#define GW_MNGR_BUF_LEN		1024
#define GW_MNGR_QBUF_LEN	1136
void * gateway_mngr(void *gw_cnf) {
	struct itimerval tval;
	gw_conf_t *gw_conf = (gw_conf_t *) gw_cnf;
	sigset_t alarm_msk;
	int sig;
	struct timeval tv;
	char buf[GW_MNGR_BUF_LEN];
	char qbuf[GW_MNGR_QBUF_LEN];
	char b64_gwid[12];
	PGresult *res;
	

	sigemptyset(&alarm_msk);
	sigaddset(&alarm_msk, SIGALRM);

	tval.it_value.tv_sec = gw_conf->dynamic_conf.telemetry_send_period;
	tval.it_value.tv_usec = 0;
	tval.it_interval.tv_sec = gw_conf->dynamic_conf.telemetry_send_period;
	tval.it_interval.tv_usec = 0;

	if (setitimer(ITIMER_REAL, &tval, NULL)) {
		perror("Failed to set itimer");
		return NULL;
	}

	base64_encode(gw_conf->static_conf.gw_id, GATEWAY_ID_SIZE, b64_gwid);
	
	while (1) {
		// get utc
		gettimeofday(&tv, NULL);

		// create applications and devices serving log
		pthread_mutex_lock(&gw_stat_mutex);
		gw_stat_linked_list_flush(buf, 0);
		pthread_mutex_unlock(&gw_stat_mutex);

		// flush utc and log into a query
		snprintf(qbuf, GW_MNGR_QBUF_LEN, "UPDATE gateways SET num_errors = %lld, last_keep_alive = %d, last_report = '%s' WHERE id = '%s'",
				gw_stat.errors_count, (uint32_t) tv.tv_sec, buf, b64_gwid );

		pthread_mutex_lock(&mutex);
		res = PQexec(conn, qbuf);
		pthread_mutex_unlock(&mutex);
	
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			fprintf(stderr, "gateway manager db update failed!\n");
		} else {
			printf("stats updated : %s\n", buf);
		}

		buf[0] = '\0';
		qbuf[0] = '\0';
		sigwait(&alarm_msk, &sig);
	}
}

/* HTTP-related */
static int callback_get_epoch(
	const struct _u_request *request, 
	struct _u_response *response,
	void *user_data)
{
	gateway_protocol_conf_t gwp_conf;
	uint8_t buf[64];
	uint8_t buf_len = 0;
	char bufb64[90];

	memcpy(gwp_conf.app_key, u_map_get(request->map_header, "X-Auth-Token"), GATEWAY_PROTOCOL_APP_KEY_SIZE);
	gwp_conf.app_key[GATEWAY_PROTOCOL_APP_KEY_SIZE] = '\0';
	// never repeat that!
	gwp_conf.dev_id = atoi(&u_map_get(request->map_header, "X-Auth-Token")[GATEWAY_PROTOCOL_APP_KEY_SIZE+1]);

	if (gateway_protocol_checkup_callback(&gwp_conf)) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		printf("epoch : %d\n", (uint32_t)tv.tv_sec);
		gateway_protocol_packet_encode (
			&gwp_conf,
			GATEWAY_PROTOCOL_PACKET_TYPE_TIME_SEND,
			sizeof(uint32_t), (uint8_t *)&tv.tv_sec,
			&buf_len, buf
		);
		base64_encode(buf, buf_len, bufb64);
		printf("b64 res : %s\n", bufb64);	
		ulfius_set_string_body_response(response, 200, bufb64);
	} else {
		response->status = 404;
	}
	
	return U_CALLBACK_CONTINUE;
}

static int callback_post_data(
	const struct _u_request *request, 
	struct _u_response *response,
	void *user_data)
{

	return U_CALLBACK_CONTINUE;
}


/* Gateway-protocol-related */
void gateway_protocol_data_send_payload_decode(
	sensor_data_t *sensor_data, 
	const uint8_t *payload, 
	const uint8_t payload_length) 
{
	uint8_t p_len = 0;

	memcpy(&sensor_data->utc, &payload[p_len], sizeof(sensor_data->utc));
	p_len += sizeof(sensor_data->utc);

	memcpy(sensor_data->data, &payload[p_len], payload_length - p_len);
	sensor_data->data_length = payload_length - p_len;
}

uint8_t gateway_protocol_checkup_callback(gateway_protocol_conf_t *gwp_conf) {
	uint8_t ret = 0;
	PGresult *res;
	char db_query[200];
	
	snprintf(db_query, sizeof(db_query), 
		"SELECT secure_key, secure FROM applications WHERE app_key = '%s'", (char *)gwp_conf->app_key
	);
	printf("%s\n", db_query);
	pthread_mutex_lock(&mutex);
	res = PQexec(conn, db_query);
	pthread_mutex_unlock(&mutex);

	if ((PQresultStatus(res) == PGRES_TUPLES_OK) && PQntuples(res)) {
		base64_decode(PQgetvalue(res, 0, 0), strlen(PQgetvalue(res, 0, 0))-1, gwp_conf->secure_key);
		gwp_conf->secure = PQgetvalue(res, 0, 1)[0] == 't';
		ret = 1;
	} else {
		fprintf(stderr, "gateway_protocol_checkup_callback error\n");
		gw_stat.errors_count++;
	}
	PQclear(res);

	return ret;
}

/* Configuration-related */
static void process_static_conf(json_t* value, static_conf_t *st_conf) {
	if (json_is_object(value)) {
		json_t *aux;
		char buffer[128];

		aux = json_object_get(value, "gateway_id");
		if (json_is_string(aux)) {
			/* bad practice. must add checks for the EUI string */
			strncpy(buffer, json_string_value(aux), sizeof(buffer));
			sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &st_conf->gw_id[0], &st_conf->gw_id[1], &st_conf->gw_id[2],
									&st_conf->gw_id[3], &st_conf->gw_id[4], &st_conf->gw_id[5]
			);
		}
		aux = json_object_get(value, "gateway_secure_key");
		if (json_is_string(aux)) {
			strncpy(buffer, json_string_value(aux), sizeof(buffer));
			sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
					&st_conf->gw_secure_key[0], &st_conf->gw_secure_key[1], &st_conf->gw_secure_key[2], &st_conf->gw_secure_key[3],
					&st_conf->gw_secure_key[4], &st_conf->gw_secure_key[5], &st_conf->gw_secure_key[6], &st_conf->gw_secure_key[7],
					&st_conf->gw_secure_key[8], &st_conf->gw_secure_key[9], &st_conf->gw_secure_key[10], &st_conf->gw_secure_key[11],
					&st_conf->gw_secure_key[12], &st_conf->gw_secure_key[13], &st_conf->gw_secure_key[14], &st_conf->gw_secure_key[15]
			);
		}
		aux = json_object_get(value, "gateway_port");
		if (json_is_integer(aux)) {
			st_conf->gw_port = json_integer_value(aux);
		}
		aux = json_object_get(value, "db_type");
		if (json_is_string(aux)) {
			strncpy(st_conf->db_type, json_string_value(aux), sizeof(st_conf->db_type));
		}
		aux = json_object_get(value, "platform_gw_manager_ip");
		if (json_is_string(aux)) {
			strncpy(st_conf->platform_gw_manager_ip, json_string_value(aux), sizeof(st_conf->platform_gw_manager_ip));
		}
		aux = json_object_get(value, "platform_gw_manager_port");
		if (json_is_integer(aux)) {
			st_conf->platform_gw_manager_port = json_integer_value(aux);
		}
		aux = json_object_get(value, "thread_pool_size");
		if (json_is_integer(aux)) {
			st_conf->thread_pool_size = json_integer_value(aux);
		}
	}
}

static void process_dynamic_conf(json_t* value, dynamic_conf_t *dyn_conf) {
	if (json_is_object(value)) {
		json_t *aux;
		
		aux = json_object_get(value, "db_address");
		if (json_is_string(aux)) {
			strncpy(dyn_conf->db_addr, json_string_value(aux), sizeof(dyn_conf->db_addr));
		}
		aux = json_object_get(value, "db_port");
		if (json_is_integer(aux)) {
			dyn_conf->db_port = json_integer_value(aux);
		}
		aux = json_object_get(value, "db_name");
		if (json_is_string(aux)) {
			strncpy(dyn_conf->db_name, json_string_value(aux), sizeof(dyn_conf->db_name));
		}
		aux = json_object_get(value, "username");
		if (json_is_string(aux)) {
			strncpy(dyn_conf->db_user_name, json_string_value(aux), sizeof(dyn_conf->db_user_name));
		}
		aux = json_object_get(value, "password");
		if (json_is_string(aux)) {
			strncpy(dyn_conf->db_user_pass, json_string_value(aux), sizeof(dyn_conf->db_user_pass));
		}
		aux = json_object_get(value, "telemetry_send_freq");
		if (json_is_integer(aux)) {
			dyn_conf->telemetry_send_period = json_integer_value(aux);
		}
	}
}

static json_t * read_json_conf(const char *file_path) {
	struct stat filestatus;
	FILE *fp;
	char *file_contents;
	json_t *root;
	json_error_t error;

	if (stat(file_path, &filestatus)) {
		fprintf(stderr, "File %s not found.", file_path);
		return NULL;
	}
	file_contents = (char *)malloc(filestatus.st_size);
	if (!file_contents) {
		fprintf(stderr, "Memory error allocating %d bytes.", (int) filestatus.st_size);
		return NULL;
	}
	fp = fopen(file_path, "rt");
	if (!fp) {
		fprintf(stderr, "Unable to open %s.", file_path);
		fclose(fp);
		free(file_contents);
		return NULL;
	}
	if (fread(file_contents, filestatus.st_size, 1, fp) != 1) {
		fprintf(stderr, "Unable to read %s.", file_path);
		fclose(fp);
		free(file_contents);
		return NULL;
	}
	fclose(fp);
	
	file_contents[filestatus.st_size] = '\0';
	printf("file content : \n'%s'\n", file_contents);

	root = json_loads(file_contents, 0, &error);
	free(file_contents);

	if (!root) {
		fprintf(stderr, "Unable to parse json, line %d : %s\n.", error.line, error.text);
		return NULL;
	}
	
	return root;
}

static int read_static_conf(const char *static_conf_file_path, gw_conf_t *gw_conf) {
	json_t *jvalue;
	
	jvalue = read_json_conf(static_conf_file_path);
	if (!jvalue) {
		return 1;
	}
	process_static_conf(jvalue, &gw_conf->static_conf);

	json_decref(jvalue);
	
	return 0;
}

static int read_dynamic_conf(const char *dynamic_conf_file_path, gw_conf_t *gw_conf) {
	json_t *jvalue;
	
	jvalue = read_json_conf(dynamic_conf_file_path);
	if (!jvalue) {
		return 1;
	}
	process_dynamic_conf(jvalue, &gw_conf->dynamic_conf);

	json_decref(jvalue);
	
	return 0;
}

