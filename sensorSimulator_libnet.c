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

typedef enum BOOL {FALSE=0, TRUE=1} BOOL;


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
	u_int8_t **srcmac;
	u_int8_t dstmac[MAC_ADDRESS_LENGTH];
};

struct thread_input {
	char* device;
	int interval;
	int count;
	int srcmac_qty;
	u_int8_t* payload;
	u_int16_t size;
	u_int32_t srcip;
	u_int32_t dstip;
	u_int8_t **srcmac;
	u_int8_t dstmac[MAC_ADDRESS_LENGTH];
};

LogDescriptor global_log_descriptor;

void do_debug_log(LogLevel level, const char* msg)
{
	if (level >= global_log_descriptor.effective_level) {
		pthread_mutex_lock(&global_log_descriptor.log_mutex);
		fputs(msg, global_log_descriptor.log_file_handler);
		fflush(global_log_descriptor.log_file_handler);
		pthread_mutex_unlock(&global_log_descriptor.log_mutex);
	}	
}

void debug_log(LogLevel level, const char* function_name, const char* msg)
{
	pid_t pid = getpid();
	pthread_t tid = pthread_self();
	time_t* t = (time_t*)malloc(sizeof(time_t));
	char* timestamp = (char*)malloc(30*sizeof(char));
	char* message = (char*)malloc((30+strlen(msg)+100)*sizeof(char));
	memset(timestamp, 0, 30*sizeof(char));
	memset(message, 0, (30+strlen(msg)+100)*sizeof(char));
	time(t);
	strftime(timestamp, 30, "[%F %T Z%z]", localtime(t));
	sprintf(message, "%s %#x %#x %s %s\n", timestamp, pid, tid, function_name, msg);
	do_debug_log(level, message);
	free(t);
	free(message);
	free(timestamp);	
}


BOOL init_debug_log(const char* file_name, const LogLevel effective_level)
{
	global_log_descriptor.effective_level = effective_level;
	global_log_descriptor.log_file_handler = NULL;
	global_log_descriptor.log_file_handler = fopen(file_name, "a+");
	if (global_log_descriptor.log_file_handler == NULL) {
		return FALSE;	
	}
	pthread_mutex_init(&global_log_descriptor.log_mutex, NULL);
	return TRUE;
}

BOOL deinit_debug_log(void)
{
	if(global_log_descriptor.log_file_handler != NULL) {
		fflush(global_log_descriptor.log_file_handler);
		fclose(global_log_descriptor.log_file_handler);
		pthread_mutex_destroy(&global_log_descriptor.log_mutex);
		return TRUE;
	}
	return FALSE;
}



int switch_config_name(const char* p)
{
	if(strcmp(p, "threads") == 0) {
		return CONFIG_THREADS;
	}
	if(strcmp(p, "macfile") == 0) {
		return CONFIG_MACFILE;
	}
	if(strcmp(p, "srcip") == 0) {
		return CONFIG_SRCIP;
	}
	if(strcmp(p, "dstip") == 0) {
		return CONFIG_DSTIP;
	}
	if(strcmp(p, "dstmac") == 0) {
		return CONFIG_DSTMAC;
	}
	if(strcmp(p, "interval") == 0) {
		return CONFIG_INTERVAL;
	}
	if(strcmp(p, "device") == 0) {
		return CONFIG_DEVICE;
	}
	if(strcmp(p, "size") == 0) {
		return CONFIG_SIZE;
	}
	if(strcmp(p, "power") == 0) {
		return CONFIG_POWER;
	}
	if(strcmp(p, "count") == 0) {
		return CONFIG_COUNT;
	}
	if(strcmp(p, "logfile") == 0) {
		return CONFIG_LOGFILE;
	}
	if(strcmp(p, "loglevel") == 0) {
		return CONFIG_LOGLEVEL;
	}
	return 0;	
}

int swtich_log_level(const char* p)
{
        if(strcmp(p, "INFO") == 0) {
                return INFO;
        }
        if(strcmp(p, "TRACE") == 0) {
                return TRACE;
        }
        if(strcmp(p, "OFF") == 0) {
                return OFF;
        }
	return INFO;

}

u_int8_t* mac_addr_aton(char* p, u_int8_t* buf)
{
	int i = 0;
	char *t = strtok(p, ":");
	while(i<MAC_ADDRESS_LENGTH && t != NULL) {
		buf[i++] = (u_int8_t)((t[0]-(isalpha(t[0])?(islower(t[0])?0x61-0xa:0x41-0xA):0x30))*16+(t[1]-(isalpha(t[1])?(islower(t[1])?0x61-0xa:0x41-0xA):0x30)));
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
	tsp.tv_sec += (time_t)timeout;
	pthread_cond_timedwait(&cond, &mutex, &tsp);
	pthread_mutex_unlock(&mutex);

	pthread_cond_destroy(&cond);
	pthread_mutex_destroy(&mutex);
}

void* thread_routine(void* input)
{
	struct thread_input *p = input;
	libnet_t *plibnet_app;
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t udp_ptag, ip_ptag, eth_ptag, t;
	int i = 0;
	int val = 0;
	u_int16_t sport = (u_int16_t)0x1234;
	u_int16_t dport = (u_int16_t)0x5678;

	plibnet_app = libnet_init(LIBNET_LINK_ADV, p->device, errbuf);
	if(plibnet_app == NULL) {
		pthread_exit(NULL);
	}

	udp_ptag = libnet_build_udp (sport, /*source port*/
		dport,	/*destination port*/
		LIBNET_UDP_H + p->size,	/*Total size of UDP packet*/
		0,	/*libnet autofill checksum*/
		p->payload, /*payload pointer*/
		p->size, /*payload size*/
		plibnet_app, /*libnet context*/
		0); /*create new UDP protocal tag*/
	if(udp_ptag == -1) {
		libnet_destroy(plibnet_app);
		pthread_exit(NULL);
	}

	ip_ptag = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + p->size, /*Total length of IP packet*/
		0, 	/*TOS*/
		242,	/*IP ID*/
		0,	/*IP Fragment*/
		64,	/*IP TTL*/
		IPPROTO_UDP,	/*IP Protocal*/
		0,	/*libnet autofill checksum*/
		p->srcip,	/*Source IP address*/
		p->dstip,	/*Destination IP address*/
		NULL,		/*Payload pointer*/
		0,		/*payload size*/
		plibnet_app,	/*libnet context*/
		0);		/*create new IP protocal tag*/
	if(ip_ptag == -1) {
		libnet_destroy(plibnet_app);
		pthread_exit(NULL);
	}

	eth_ptag = libnet_build_ethernet(
		p->dstmac,	/*des HW addr*/
                p->srcmac[0],	/*src HW addr*/ 
                ETHERTYPE_IP,	/*ether packet type*/
                NULL,		/*prt to payload*/
                0,		/*payload size*/
                plibnet_app,	/*libnet handle*/
                0);		/*ptr to packet memory*/
	if(eth_ptag == -1) {
		libnet_destroy(plibnet_app);
		pthread_exit(NULL);
	}

	for(i=0;i<p->count;i++) {     
		//libnet_adv_cull_packet(plibnet_app, &packet, &packet_size); 
		t = libnet_build_ethernet(
			p->dstmac,	/*des HW addr*/
                	p->srcmac[i%p->srcmac_qty],	/*src HW addr*/ 
	                ETHERTYPE_IP,	/*ether packet type*/
       		        NULL,		/*prt to payload*/
	                0,		/*payload size*/
			plibnet_app,	/*libnet handle*/
			eth_ptag);		/*ptr to packet memory*/
		if(t == -1) {
			libnet_destroy(plibnet_app);
			pthread_exit(NULL);
		}
		val = libnet_write(plibnet_app); 
		if(p->interval > 0) {
			thread_sleep(p->interval);
		}
	}
	libnet_destroy(plibnet_app); 
	return 0;
}

struct config* load_config(const char* config_file)
{
	FILE* file_handler = fopen(config_file, "r");	
	char buffer[FILE_LINE_BUFFER_SIZE];	
	char name[FILE_LINE_BUFFER_SIZE/2];
	char value[FILE_LINE_BUFFER_SIZE/2];
	int config_flag = 0x0;

	if(file_handler == NULL) {
		perror("Config file open ERROR! : ");
		return NULL;
	}
	struct config * pointer_config = (struct config*)malloc(sizeof(struct config));
	if(pointer_config == NULL) {
		perror("Memory allocation ERROR ! : ");
		return NULL;
	} 
	pointer_config->mac_data_file = NULL;
	pointer_config->device = NULL;
	pointer_config->logfile = NULL;
	while(fgets(buffer, FILE_LINE_BUFFER_SIZE, file_handler)!=NULL) {
		if(buffer[0] == '#' || isspace(buffer[0])) {
			continue;
		}
		if(sscanf(buffer, "%s = %s", name, value) != 2) {
			perror("A invalid line in config files : ");
			continue;
		}
		switch(switch_config_name(name)) {
			case CONFIG_THREADS:
				pointer_config->threads = atoi(value);
				config_flag |= CONFIG_THREADS;
				break;
			case CONFIG_MACFILE:
				pointer_config->mac_data_file = (char*)malloc(sizeof(char)*(1+strlen(value)));
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
				pointer_config->device = (char*)malloc(sizeof(char)*(1+strlen(value)));
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
				pointer_config->logfile = (char*)malloc(sizeof(char)*(1+strlen(value)));
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
	if(config_flag != 0xFFF) {
		free(pointer_config);
		if(pointer_config->device != NULL)
			free(pointer_config->device);
		if(pointer_config->mac_data_file != NULL)
			free(pointer_config->mac_data_file);
		if(pointer_config->logfile != NULL)
			free(pointer_config->logfile);
		return NULL;
	}
	return pointer_config;
}

int main(int argc, char* argv[])
{
	int c;
	u_int8_t payload[10] = {0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a};
	u_int8_t srcmac1[6] =  {0x10,0x11,0x12,0x13,0x14,0x15};
	u_int8_t srcmac2[6] =  {0x16,0x17,0x18,0x19,0x1a,0x1b}; 
	u_int8_t (*p)[6];
	p=&srcmac2;
	struct config* pointer_config = NULL;
	struct thread_input input;
	while((c=getopt(argc, argv, "c:")) != -1) {
		if(c == 'c') {
			pointer_config = load_config(optarg);
			if(pointer_config == NULL) {
				return 1;
			}
		}
	}
	input.device = pointer_config->device;
	input.interval = pointer_config->interval;
	input.count = pointer_config->count;
	input.srcmac_qty = 2;
	input.size = pointer_config->size;
	input.srcip = pointer_config->srcip;
	input.dstip = pointer_config->dstip;
	memcpy(input.dstmac, pointer_config->dstmac, 6*sizeof(u_int8_t));
	input.payload = (u_int8_t*)malloc(10*sizeof(u_int8_t));
	input.size = 10;
	input.srcmac = malloc(2*sizeof(u_int8_t*));
	input.srcmac[0] = malloc(6*sizeof(u_int8_t));
	input.srcmac[1] = malloc(6*sizeof(u_int8_t));
	memcpy(input.srcmac[0], srcmac1, 6*sizeof(u_int8_t));
	memcpy(input.srcmac[1], srcmac2, 6*sizeof(u_int8_t));
	thread_routine(&input);	
	return 0;
}

