#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <dirent.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define FILE_LINE_BUFFER_SIZE 200
#define MAC_ADDRESS_LENGTH 6
#define CONFIG_THREADS  0x01
#define CONFIG_MACFILE  0x02
#define CONFIG_SRCIP    0x04
#define CONFIG_DSTIP    0x08
#define CONFIG_DSTMAC   0x10
#define CONFIG_INTERVAL 0x20
#define CONFIG_DEVICE   0x40
#define CONFIG_SIZE     0x80
#define CONFIG_POWER    0x100
#define CONFIG_COUNT	0x200
#define CONFIG_LOGFILE  0x400
#define CONFIG_LOGLEVEL 0x800

#define OFF UINT_MAX
#define FATAL 10000
#define SEVERE 1000
#define WARNING 100
#define INFO 10
#define FINE 9
#define FINER 8
#define FINEST 7
#define TRACE 5
#define DEFAULT_LOG_LEVEL 10

typedef int LogLevel;

typedef enum BOOL {
	FALSE = 0, TRUE = 1
} BOOL;

typedef struct mac_node {
	u_int8_t* data;
	struct mac_node *next;
} MacNode, *MacLinkedList;

typedef struct log_descriptor {
	FILE * log_file_handler;
	LogLevel effective_level;
	pthread_mutex_t log_mutex;
} LogDescriptor;

struct config {
	char* mac_data_file;
	char* device;
	char* logfile;
	LogLevel loglevel;
	int interval;
	int threads;
	int power;
	int size;
	int count;
	u_int32_t srcip;
	u_int32_t dstip;
	u_int8_t dstmac[MAC_ADDRESS_LENGTH];
};

struct thread_input {
	char* device;
	int interval;
	int count;
	u_int8_t* payload;
	u_int16_t size;
	u_int32_t srcip;
	u_int32_t dstip;
	MacLinkedList srcmac;
	u_int8_t dstmac[MAC_ADDRESS_LENGTH];
};

LogDescriptor global_log_descriptor;

void do_debug_log(LogLevel level, const char* msg) {
	if (level >= global_log_descriptor.effective_level) {
		pthread_mutex_lock(&global_log_descriptor.log_mutex);
		fputs(msg, global_log_descriptor.log_file_handler);
		fflush(global_log_descriptor.log_file_handler);
		pthread_mutex_unlock(&global_log_descriptor.log_mutex);
	}
}

void debug_log(LogLevel level, const char* function_name, const char* msg) {
	pid_t pid = getpid();
	pthread_t tid = pthread_self();
	time_t* t = (time_t*) malloc(sizeof(time_t));
	char* timestamp = (char*) malloc(30 * sizeof(char));
	char* message = (char*) malloc((30 + strlen(msg) + 100) * sizeof(char));
	memset(timestamp, 0, 30 * sizeof(char));
	memset(message, 0, (30 + strlen(msg) + 100) * sizeof(char));
	time(t);
	strftime(timestamp, 30, "[%F %T Z%z]", localtime(t));
	sprintf(message, "%s %#x %lu %s %s\n", timestamp, pid, (unsigned long) tid,
			function_name, msg);
	do_debug_log(level, message);
	free(t);
	free(message);
	free(timestamp);
}

BOOL init_debug_log(const char* file_name, const LogLevel effective_level) {
	global_log_descriptor.effective_level = effective_level;
	global_log_descriptor.log_file_handler = NULL;
	global_log_descriptor.log_file_handler = fopen(file_name, "a+");
	if (global_log_descriptor.log_file_handler == NULL) {
		return FALSE;
	}
	pthread_mutex_init(&global_log_descriptor.log_mutex, NULL);
	return TRUE;
}

BOOL deinit_debug_log(void) {
	if (global_log_descriptor.log_file_handler != NULL) {
		fflush(global_log_descriptor.log_file_handler);
		fclose(global_log_descriptor.log_file_handler);
		pthread_mutex_destroy(&global_log_descriptor.log_mutex);
		return TRUE;
	}
	return FALSE;
}

int switch_config_name(const char* p) {
	if (strcmp(p, "threads") == 0) {
		return CONFIG_THREADS;
	}
	if (strcmp(p, "macfile") == 0) {
		return CONFIG_MACFILE;
	}
	if (strcmp(p, "srcip") == 0) {
		return CONFIG_SRCIP;
	}
	if (strcmp(p, "dstip") == 0) {
		return CONFIG_DSTIP;
	}
	if (strcmp(p, "dstmac") == 0) {
		return CONFIG_DSTMAC;
	}
	if (strcmp(p, "interval") == 0) {
		return CONFIG_INTERVAL;
	}
	if (strcmp(p, "device") == 0) {
		return CONFIG_DEVICE;
	}
	if (strcmp(p, "size") == 0) {
		return CONFIG_SIZE;
	}
	if (strcmp(p, "power") == 0) {
		return CONFIG_POWER;
	}
	if (strcmp(p, "count") == 0) {
		return CONFIG_COUNT;
	}
	if (strcmp(p, "logfile") == 0) {
		return CONFIG_LOGFILE;
	}
	if (strcmp(p, "loglevel") == 0) {
		return CONFIG_LOGLEVEL;
	}
	return 0;
}

int swtich_log_level(const char* p) {
	if (strcmp(p, "INFO") == 0) {
		return INFO;
	}
	if (strcmp(p, "TRACE") == 0) {
		return TRACE;
	}
	if (strcmp(p, "OFF") == 0) {
		return OFF;
	}
	return INFO;

}

u_int8_t* mac_addr_aton(char* p, u_int8_t* buf) {
	int i = 0;
	char *t = strtok(p, ":");
	while (i < MAC_ADDRESS_LENGTH && t != NULL) {
		buf[i++] =
				(u_int8_t) ((t[0]
						- (isalpha(t[0]) ?
								(islower(t[0]) ? 0x61 - 0xa : 0x41 - 0xA) : 0x30))
						* 16
						+ (t[1]
								- (isalpha(t[1]) ?
										(islower(t[1]) ? 0x61 - 0xa : 0x41 - 0xA) :
										0x30)));
		t = strtok(NULL, ":");
	}
	return buf;
}

void thread_sleep (int timeout)
{
        pthread_cond_t cond;
        pthread_mutex_t mutex;
        struct timeval tv;
        struct timespec tsp;

        pthread_mutex_init(&mutex, NULL);
        pthread_cond_init(&cond, NULL);

        pthread_mutex_lock(&mutex);
        gettimeofday(&tv, NULL);
        tsp.tv_sec = tv.tv_sec;
        tsp.tv_nsec = tv.tv_usec*1000;
        tsp.tv_sec += (time_t)(timeout/1000);
        tsp.tv_nsec += (time_t)(timeout%1000*1000*1000);
        if(tsp.tv_nsec >= 1000000000) {
                tsp.tv_sec += 1;
                tsp.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(&cond, &mutex, &tsp);
        pthread_mutex_unlock(&mutex);

        pthread_cond_destroy(&cond);
        pthread_mutex_destroy(&mutex);
}


void* thread_routine(void* input) {
	struct thread_input *p = input;
	MacLinkedList pmac = p->srcmac;
	MacLinkedList pmac_head = p->srcmac;
	libnet_t *plibnet_app;
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t udp_ptag, ip_ptag, eth_ptag, t;
	int i = 0;
	int val = 0;
	u_int16_t sport = (u_int16_t) 0x1234;
	u_int16_t dport = (u_int16_t) 0x5678;

	plibnet_app = libnet_init(LIBNET_LINK_ADV, p->device, errbuf);
	if (plibnet_app == NULL) {
		pthread_exit(NULL);
	}

	udp_ptag = libnet_build_udp(sport, /*source port*/
	dport, /*destination port*/
	LIBNET_UDP_H + p->size, /*Total size of UDP packet*/
	0, /*libnet autofill checksum*/
	p->payload, /*payload pointer*/
	p->size, /*payload size*/
	plibnet_app, /*libnet context*/
	0); /*create new UDP protocal tag*/
	if (udp_ptag == -1) {
		libnet_destroy(plibnet_app);
		pthread_exit(NULL);
	}

	ip_ptag = libnet_build_ipv4(
	LIBNET_IPV4_H + LIBNET_UDP_H + p->size, /*Total length of IP packet*/
	0, /*TOS*/
	242, /*IP ID*/
	0, /*IP Fragment*/
	64, /*IP TTL*/
	IPPROTO_UDP, /*IP Protocal*/
	0, /*libnet autofill checksum*/
	p->srcip, /*Source IP address*/
	p->dstip, /*Destination IP address*/
	NULL, /*Payload pointer*/
	0, /*payload size*/
	plibnet_app, /*libnet context*/
	0); /*create new IP protocal tag*/
	if (ip_ptag == -1) {
		libnet_destroy(plibnet_app);
		pthread_exit(NULL);
	}

	eth_ptag = libnet_build_ethernet(p->dstmac, /*des HW addr*/
	(p->srcmac)->data, /*src HW addr*/
	ETHERTYPE_IP, /*ether packet type*/
	NULL, /*prt to payload*/
	0, /*payload size*/
	plibnet_app, /*libnet handle*/
	0); /*ptr to packet memory*/
	if (eth_ptag == -1) {
		libnet_destroy(plibnet_app);
		pthread_exit(NULL);
	}

	for (i = 0; i < p->count; i++) {
		//libnet_adv_cull_packet(plibnet_app, &packet, &packet_size);
		if (pmac->data != NULL) {
			t = libnet_build_ethernet(p->dstmac, /*des HW addr*/
			pmac->data, /*src HW addr*/
			ETHERTYPE_IP, /*ether packet type*/
			NULL, /*prt to payload*/
			0, /*payload size*/
			plibnet_app, /*libnet handle*/
			eth_ptag); /*ptr to packet memory*/
			if (t == -1) {
				libnet_destroy(plibnet_app);
				pthread_exit(NULL);
			}
			val = libnet_write(plibnet_app);
			if (p->interval > 0) {
				//thread_sleep(p->interval);
				usleep(100*1000);	
			}
			if(pmac->next == NULL) {
				pmac = pmac_head;
			} else {
				pmac = pmac->next;
			}
		}
	}
	libnet_destroy(plibnet_app);
	return 0;
}

MacLinkedList submaclist(MacLinkedList* head, int count) 
{
	MacLinkedList p = NULL, r = NULL;
	int i = 0;

	for(i=0; i<count && *head !=NULL; i++,*head=(*head)->next)
	{
		if(p==NULL) {
			p = *head;
			r = p;
		}else {
			r = r->next;
		}	
	}
	r->next = NULL;
	return p;
}	
MacLinkedList loadMacFile(const char* mac_file, int* cnt) {
	MacLinkedList list, p, r;
	list = (MacLinkedList) malloc(sizeof(MacNode));
	list->data = NULL;
	list->next = NULL;
	p = NULL;
	r = list;
	*cnt = 0;

	FILE* fp = fopen(mac_file, "r");
	char *str = (char *) malloc(FILE_LINE_BUFFER_SIZE * sizeof(char));

	if (fp == NULL) {
		perror("Mac file open ERROR! : ");
		return NULL;
	}
	while (fgets(str, FILE_LINE_BUFFER_SIZE, fp) != NULL) {
		u_int8_t* buf = malloc(MAC_ADDRESS_LENGTH * sizeof(u_int8_t));
		if (buf == NULL) {
			perror("");
			fclose(fp);
			return NULL;
		}
		if (list->data == NULL) {
			list->data = mac_addr_aton(str, buf);
		} else {
			p = (MacLinkedList) malloc(sizeof(MacNode));
			p->data = NULL;
			p->next = NULL;
			if (p == NULL) {
				perror("");
				fclose(fp);
				return NULL;
			}
			p->data = mac_addr_aton(str, buf);
			r->next = p;
			r = p;
		}
		(*cnt)++;
	}

	fclose(fp);
	return list;
}

struct config* load_config(const char* config_file) {
	FILE* file_handler = fopen(config_file, "r");
	char buffer[FILE_LINE_BUFFER_SIZE];
	char name[FILE_LINE_BUFFER_SIZE / 2];
	char value[FILE_LINE_BUFFER_SIZE / 2];
	int config_flag = 0x0;

	if (file_handler == NULL) {
		perror("Config file open ERROR! : ");
		return NULL;
	}
	struct config * pointer_config = (struct config*) malloc(
			sizeof(struct config));
	if (pointer_config == NULL) {
		perror("Memory allocation ERROR ! : ");
		return NULL;
	}
	pointer_config->mac_data_file = NULL;
	pointer_config->device = NULL;
	pointer_config->logfile = NULL;
	while (fgets(buffer, FILE_LINE_BUFFER_SIZE, file_handler) != NULL) {
		if (buffer[0] == '#' || isspace(buffer[0])) {
			continue;
		}
		if (sscanf(buffer, "%s = %s", name, value) != 2) {
			perror("A invalid line in config files : ");
			continue;
		}
		switch (switch_config_name(name)) {
		case CONFIG_THREADS:
			pointer_config->threads = atoi(value);
			config_flag |= CONFIG_THREADS;
			break;
		case CONFIG_MACFILE:
			pointer_config->mac_data_file = (char*) malloc(
					sizeof(char) * (1 + strlen(value)));
			strcpy(pointer_config->mac_data_file, value);
			config_flag |= CONFIG_MACFILE;
			break;
		case CONFIG_SRCIP:
			inet_pton(AF_INET, value, &(pointer_config->srcip));
			config_flag |= CONFIG_SRCIP;
			break;
		case CONFIG_DSTIP:
			inet_pton(AF_INET, value, &(pointer_config->dstip));
			config_flag |= CONFIG_DSTIP;
			break;
		case CONFIG_DSTMAC:
			mac_addr_aton(value, pointer_config->dstmac);
			config_flag |= CONFIG_DSTMAC;
			break;
		case CONFIG_INTERVAL:
			pointer_config->interval = atoi(value);
			config_flag |= CONFIG_INTERVAL;
			break;
		case CONFIG_DEVICE:
			pointer_config->device = (char*) malloc(
					sizeof(char) * (1 + strlen(value)));
			strcpy(pointer_config->device, value);
			config_flag |= CONFIG_DEVICE;
			break;
		case CONFIG_SIZE:
			pointer_config->size = atoi(value);
			config_flag |= CONFIG_SIZE;
			break;
		case CONFIG_POWER:
			pointer_config->power = atoi(value);
			config_flag |= CONFIG_POWER;
			break;
		case CONFIG_COUNT:
			pointer_config->count = atoi(value);
			config_flag |= CONFIG_COUNT;
			break;
		case CONFIG_LOGFILE:
			pointer_config->logfile = (char*) malloc(
					sizeof(char) * (1 + strlen(value)));
			strcpy(pointer_config->logfile, value);
			config_flag |= CONFIG_LOGFILE;
			break;
		case CONFIG_LOGLEVEL:
			pointer_config->loglevel = swtich_log_level(value);
			config_flag |= CONFIG_LOGLEVEL;
			break;
		default:
			break;
		}
	}
	if (config_flag != 0xFFF) {
		free(pointer_config);
		if (pointer_config->device != NULL)
			free(pointer_config->device);
		if (pointer_config->mac_data_file != NULL)
			free(pointer_config->mac_data_file);
		if (pointer_config->logfile != NULL)
			free(pointer_config->logfile);
		return NULL;
	}
	return pointer_config;
}

int getInterfaceStatus(char *intrface) {
//	char *cmd = "iwconfig wlan2 | grep -oP 'Access Point: \K((\w+-\w+)|(\w{2}:){5}(\w){2})'";
//	FILE* fs = popen("", "r");
//
//	fclose(fs);
	return 0;
}

int main(int argc, char* argv[]) {
	//check sudo previlege

	int c;
	int srcmac_cnt;
	int i = 0;

	struct config* pointer_config = NULL;
	while ((c = getopt(argc, argv, "c:")) != -1) {
		if (c == 'c') {
			pointer_config = load_config(optarg);
			if (pointer_config == NULL) {
				return 1;
			}
		}
	}
	int threadCount = pointer_config->threads;
	MacLinkedList head = loadMacFile(pointer_config->mac_data_file, &srcmac_cnt);
	int mac_qty_thread = srcmac_cnt/threadCount;
	u_int8_t *payload = malloc(pointer_config->size*sizeof(u_int8_t));
	for(i=0; i<pointer_config->size; i++) {
		payload[i] = 0x41+i%26;
	}

	//check wireless interface work
	if (getInterfaceStatus(pointer_config->device) != 0) {
		perror("interface doesn't work");
		return 1;
	}
	struct thread_input *input = malloc(threadCount*sizeof(struct thread_input));
	pthread_t *tid = malloc(threadCount * sizeof(pthread_t));
	for (i = 0; i < threadCount; i++) {
		(input+i)->device = pointer_config->device;
		(input+i)->interval = pointer_config->interval;
		(input+i)->count = pointer_config->count;
		(input+i)->size = pointer_config->size;
		(input+i)->srcip = pointer_config->srcip;
		(input+i)->dstip = pointer_config->dstip;
		memcpy((input+i)->dstmac, pointer_config->dstmac, MAC_ADDRESS_LENGTH*sizeof(u_int8_t));
		(input+i)->payload = (u_int8_t*) malloc(pointer_config->size*sizeof(u_int8_t));
		memcpy((input+i)->payload, payload, pointer_config->size);
		if(i+1 == threadCount) {
			(input+i)->srcmac = submaclist(&head, 2*mac_qty_thread);
		} else {
			(input+i)->srcmac = submaclist(&head, mac_qty_thread);
		}
	
		pthread_create(&tid[i], NULL, thread_routine, (void*)(input+i));
	}

/*	for (i = 0; i < threadCount; i++) {
		pthread_join(tid[i], NULL);
	}
*/

	//free memory
/*	for (i = 0; i < threadCount; i++) {
		pthread_detach(tid[i]);
	}
*/

	//free input
	thread_sleep(100000);
	return 0;
}

