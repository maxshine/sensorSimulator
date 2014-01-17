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
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define FILE_LINE_BUFFER_SIZE 200
#define MAC_ADDRESS_LENGTH 6
#define CONFIG_IP_QTY_THREAD  0x01
#define CONFIG_BROADCAST 0x02
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

#define ERROR_USER 1
#define ERROR_CONFIG 2
#define ERROR_HARDWARE 3
#define ERROR_MEMORY 4

typedef int LogLevel;

typedef enum BOOL {
	FALSE = 0, TRUE = 1
} BOOL;

typedef struct mac_node {
	u_int8_t data[MAC_ADDRESS_LENGTH];
	struct mac_node *next;
} MacNode, *MacLinkedList;

typedef struct ip_node {
	in_addr_t data;
	struct ip_node *next;
} IPNode, *IPLinkedList;

typedef struct log_descriptor {
	FILE * log_file_handler;
	LogLevel effective_level;
	pthread_mutex_t log_mutex;
} LogDescriptor;

struct config {
	char* device;
	char* logfile;
	LogLevel loglevel;
	BOOL broadcast;
	int interval;
	int ip_qty_thread;
	int size;
	in_addr_t srcip;
	in_addr_t dstip;
	u_int8_t srcmac[MAC_ADDRESS_LENGTH];
	u_int8_t dstmac[MAC_ADDRESS_LENGTH];
};

struct thread_input {
	char* device;
	int interval;
	u_int8_t* payload;
	u_int16_t size;
	in_addr_t srcip;
	IPLinkedList dstip;
	u_int8_t srcmac[MAC_ADDRESS_LENGTH];
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
	if (level >= global_log_descriptor.effective_level) {
		pid_t pid = getpid();
		pthread_t tid = pthread_self();
		time_t* t = (time_t*) malloc(sizeof(time_t));
		char* timestamp = (char*) malloc(30 * sizeof(char));
		char* message = (char*) malloc((30 + strlen(msg) + 100) * sizeof(char));
		memset(timestamp, 0, 30 * sizeof(char));
		memset(message, 0, (30 + strlen(msg) + 100) * sizeof(char));
		time(t);
		strftime(timestamp, 30, "[%F %T Z%z]", localtime(t));
		sprintf(message, "%s %#x %lx %s %s\n", timestamp, pid, (unsigned long) tid,
			function_name, msg);
		do_debug_log(level, message);
		free(t);
		free(message);
		free(timestamp);
	}
}

BOOL init_debug_log(const char* file_name, const LogLevel effective_level) 
{ global_log_descriptor.effective_level = effective_level;
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
	if (global_log_descriptor.log_file_handler != NULL) {
		fflush(global_log_descriptor.log_file_handler);
		fclose(global_log_descriptor.log_file_handler);
		pthread_mutex_destroy(&global_log_descriptor.log_mutex);
		return TRUE;
	}
	return FALSE;
}

int switch_config_name(const char* p) {
	if (strcmp(p, "ip_qty_thread") == 0) {
		return CONFIG_IP_QTY_THREAD;
	}
	if (strcmp(p, "broadcast") == 0) {
		return CONFIG_BROADCAST;
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

int switch_log_level(const char* p) {
	if (strcmp(p, "INFO") == 0) {
		return INFO;
	}
	if (strcmp(p, "TRACE") == 0) {
		return TRACE;
	}
	if (strcmp(p, "SEVERE") == 0) {
		return SEVERE;
	}
	if (strcmp(p, "OFF") == 0) {
		return OFF;
	}
	return INFO;

}

u_int8_t* mac_addr_aton(char* p, u_int8_t* buf) {
	int i = 0;
	char *c = strdup(p);
	char *t = strtok(c, ":");
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
	free(c);
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

void* thread_routine_b(void* input) {
	struct thread_input *p = input;
	IPLinkedList pip = p->dstip;
	IPLinkedList pip_head = p->dstip;
	libnet_t *plibnet_app;
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t udp_ptag, icmp_ptag, ip_ptag, eth_ptag, t;
	int i = 0;
	int val = 0;
	char log_buf[FILE_LINE_BUFFER_SIZE];
	char *functionname = "thread_routine";

	sprintf(log_buf, "INFO : Enter thread routine to send composed packets\n");
	debug_log(INFO, functionname, log_buf);

	plibnet_app = libnet_init(LIBNET_LINK_ADV, p->device, errbuf);
//	plibnet_app = libnet_init(LIBNET_RAW4, p->device, errbuf);
	if (plibnet_app == NULL) {
		sprintf(log_buf, "ERROR : Cannot initialize libnet context\n");
		debug_log(SEVERE, functionname, log_buf);
                sprintf(log_buf, "ERROR : libnet error %s\n", libnet_geterror(plibnet_app));
                debug_log(SEVERE, functionname, log_buf);
		pthread_exit(NULL);
	}

	icmp_ptag = libnet_build_icmpv4_echo(ICMP_ECHO, /* echo request type */
		0, /* reuqest code zero for echo request */
		0, /* ask libnet to fill in checksum */
		0, /* id for icmp */
		0, /* seq for icmp id */
		p->payload, /* payload */
		p->size, /* payload length */
		plibnet_app, /* libnet context */
		0); /* create new ICMP protocal tag */
        if (icmp_ptag == -1) {
                sprintf(log_buf, "ERROR : Cannot create libnet ICMP ptag\n");
                debug_log(SEVERE, functionname, log_buf);
                sprintf(log_buf, "ERROR : libnet error %s\n", libnet_geterror(plibnet_app));
                debug_log(SEVERE, functionname, log_buf);
                libnet_destroy(plibnet_app);
                pthread_exit(NULL);
        }


	ip_ptag = libnet_build_ipv4(
	LIBNET_IPV4_H + LIBNET_UDP_H + p->size, /*Total length of IP packet*/
	0, /*TOS*/
	0x42, /*IP ID*/
	0, /*IP Fragment*/
	64, /*IP TTL*/
	IPPROTO_ICMP, /*IP Protocal*/
	0, /*libnet autofill checksum*/
	p->srcip, /*Source IP address*/
	p->dstip->data, /*Destination IP address*/
	NULL, /*Payload pointer*/
	0, /*payload size*/
	plibnet_app, /*libnet context*/
	0); /*create new IP protocal tag*/
	if (ip_ptag == -1) {
                sprintf(log_buf, "ERROR : Cannot create libnet IP ptag\n");
                debug_log(SEVERE, functionname, log_buf);
                sprintf(log_buf, "ERROR : libnet error %s\n", libnet_geterror(plibnet_app));
                debug_log(SEVERE, functionname, log_buf);
		libnet_destroy(plibnet_app);
		pthread_exit(NULL);
	}

	eth_ptag = libnet_build_ethernet(p->dstmac,
	p->srcmac,
	ETHERTYPE_IP,
	NULL,
	0,
	plibnet_app,
	0);
	if (eth_ptag == -1) {
                sprintf(log_buf, "ERROR : Cannot create libnet ETHERNET ptag\n");
                debug_log(SEVERE, functionname, log_buf);
                sprintf(log_buf, "ERROR : libnet error %s\n", libnet_geterror(plibnet_app));
                debug_log(SEVERE, functionname, log_buf);
		libnet_destroy(plibnet_app);
		pthread_exit(NULL);
	}

	while(pip != NULL) {
		//libnet_adv_cull_packet(plibnet_app, &packet, &packet_size);
		t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + p->size, /*Total length of IP packet*/
			0, /*TOS*/
			0x42, /*IP ID*/
			0, /*IP Fragment*/
			64, /*IP TTL*/
			IPPROTO_ICMP, /*IP Protocal*/
			0, /*libnet autofill checksum*/
			p->srcip, /*Source IP address*/
			pip->data, /*Destination IP address*/
			NULL, /*Payload pointer*/
			0, /*payload size*/
			plibnet_app, /*libnet context*/
			ip_ptag); /*create new IP protocal tag*/
		if (t == -1) {
	       	        sprintf(log_buf, "ERROR : Cannot modify libnet IP ptag\n");
       		        debug_log(SEVERE, functionname, log_buf);
	                sprintf(log_buf, "ERROR : libnet error %s\n", libnet_geterror(plibnet_app));
       	        	debug_log(SEVERE, functionname, log_buf);
			libnet_destroy(plibnet_app);
			pthread_exit(NULL);
		}

		val = libnet_write(plibnet_app);
		if (p->interval > 0) {
			thread_sleep(p->interval);
		}
		pip = pip->next;
	}
	sprintf(log_buf, "INFO : Done with thread routine, totally sent %d packets\n", i);
	debug_log(INFO, functionname, log_buf);
	libnet_destroy(plibnet_app);
	return 0;
}

void* thread_routine(void* input) {
	struct thread_input *p = input;
	IPLinkedList pip = p->dstip;
	IPLinkedList pip_head = p->dstip;
	libnet_t *plibnet_app;
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t udp_ptag, icmp_ptag, ip_ptag, eth_ptag, t;
	int i = 0;
	int val = 0;
	char log_buf[FILE_LINE_BUFFER_SIZE];
	char *functionname = "thread_routine";

	sprintf(log_buf, "INFO : Enter thread routine to send composed packets\n");
	debug_log(INFO, functionname, log_buf);

//	plibnet_app = libnet_init(LIBNET_LINK_ADV, p->device, errbuf);
	plibnet_app = libnet_init(LIBNET_RAW4, p->device, errbuf);
	if (plibnet_app == NULL) {
		sprintf(log_buf, "ERROR : Cannot initialize libnet context\n");
		debug_log(SEVERE, functionname, log_buf);
                sprintf(log_buf, "ERROR : libnet error %s\n", libnet_geterror(plibnet_app));
                debug_log(SEVERE, functionname, log_buf);
		pthread_exit(NULL);
	}

	icmp_ptag = libnet_build_icmpv4_echo(ICMP_ECHO, /* echo request type */
		0, /* reuqest code zero for echo request */
		0, /* ask libnet to fill in checksum */
		0, /* id for icmp */
		0, /* seq for icmp id */
		p->payload, /* payload */
		p->size, /* payload length */
		plibnet_app, /* libnet context */
		0); /* create new ICMP protocal tag */
        if (icmp_ptag == -1) {
                sprintf(log_buf, "ERROR : Cannot create libnet ICMP ptag\n");
                debug_log(SEVERE, functionname, log_buf);
                sprintf(log_buf, "ERROR : libnet error %s\n", libnet_geterror(plibnet_app));
                debug_log(SEVERE, functionname, log_buf);
                libnet_destroy(plibnet_app);
                pthread_exit(NULL);
        }

	ip_ptag = libnet_build_ipv4(
	LIBNET_IPV4_H + LIBNET_UDP_H + p->size, /*Total length of IP packet*/
	0, /*TOS*/
	0x42, /*IP ID*/
	0, /*IP Fragment*/
	64, /*IP TTL*/
	IPPROTO_ICMP, /*IP Protocal*/
	0, /*libnet autofill checksum*/
	p->srcip, /*Source IP address*/
	p->dstip->data, /*Destination IP address*/
	NULL, /*Payload pointer*/
	0, /*payload size*/
	plibnet_app, /*libnet context*/
	0); /*create new IP protocal tag*/
	if (ip_ptag == -1) {
                sprintf(log_buf, "ERROR : Cannot create libnet IP ptag\n");
                debug_log(SEVERE, functionname, log_buf);
                sprintf(log_buf, "ERROR : libnet error %s\n", libnet_geterror(plibnet_app));
                debug_log(SEVERE, functionname, log_buf);
		libnet_destroy(plibnet_app);
		pthread_exit(NULL);
	}

	while(pip != NULL) {
		//libnet_adv_cull_packet(plibnet_app, &packet, &packet_size);
		t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + p->size, /*Total length of IP packet*/
			0, /*TOS*/
			0x42, /*IP ID*/
			0, /*IP Fragment*/
			64, /*IP TTL*/
			IPPROTO_ICMP, /*IP Protocal*/
			0, /*libnet autofill checksum*/
			p->srcip, /*Source IP address*/
			pip->data, /*Destination IP address*/
			NULL, /*Payload pointer*/
			0, /*payload size*/
			plibnet_app, /*libnet context*/
			ip_ptag); /*create new IP protocal tag*/
		if (t == -1) {
	       	        sprintf(log_buf, "ERROR : Cannot modify libnet IP ptag\n");
       		        debug_log(SEVERE, functionname, log_buf);
	                sprintf(log_buf, "ERROR : libnet error %s\n", libnet_geterror(plibnet_app));
			debug_log(SEVERE, functionname, log_buf);
			libnet_destroy(plibnet_app);
			pthread_exit(NULL);
		}

		val = libnet_write(plibnet_app);
		if (p->interval > 0) {
			thread_sleep(p->interval);
		}
		pip = pip->next;
	}
	sprintf(log_buf, "INFO : Done with thread routine, totally sent %d packets\n", i);
	debug_log(INFO, functionname, log_buf);
	libnet_destroy(plibnet_app);
	return 0;
}

IPLinkedList subiplist(IPLinkedList* head, int count) 
{
	IPLinkedList p = NULL, r = NULL;
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

IPLinkedList copyiplist(IPLinkedList head)
{
	IPLinkedList p=NULL, q=NULL, r=NULL, pEntry=NULL;
	int cnt = 0;
	p = head;
	while(p != NULL) {
	        pEntry = (IPLinkedList) malloc(sizeof(IPNode));
		if(pEntry == NULL) {
			perror("Memory allocation failed : ");
			exit(ERROR_MEMORY);
		}
	        pEntry->next = NULL;
		memcpy(&(pEntry->data), &(p->data), sizeof(in_addr_t)); 
		if(q==NULL) {
			q = pEntry;
			r = q;
		} else {
			r->next = pEntry;
			r = r->next;
		}
		p = p->next;
		cnt++;
	}
	return q;
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

MacLinkedList copymaclist(MacLinkedList head)
{
	MacLinkedList p=NULL, q=NULL, r=NULL, pEntry=NULL;
	int cnt = 0;
	p = head;
	while(p != NULL) {
	        pEntry = (MacLinkedList) malloc(sizeof(MacNode));
		if(pEntry == NULL) {
			perror("Memory allocation failed : ");
			exit(ERROR_MEMORY);
		}
	        pEntry->next = NULL;
		memcpy(pEntry->data, p->data, MAC_ADDRESS_LENGTH*sizeof(u_int8_t)); 
		if(q==NULL) {
			q = pEntry;
			r = q;
		} else {
			r->next = pEntry;
			r = r->next;
		}
		p = p->next;
		cnt++;
	}
	return q;
}

BOOL populate_srcmac(char* device, struct config* p)
{
	int sockfd;
	struct ifreq ifr;

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        strcpy(ifr.ifr_name, device);
        if(ioctl(sockfd, SIOCGIFHWADDR, &ifr)<0) {
                perror("ioctl");
        }
        memcpy(&(p->srcmac), (u_int8_t*)(&ifr.ifr_hwaddr.sa_data), MAC_ADDRESS_LENGTH*sizeof(u_int8_t));
	close(sockfd);
	
	return TRUE;

}

BOOL populate_srcip(char* device, struct config* p)
{
	int sockfd;
	struct ifreq ifr;

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        strcpy(ifr.ifr_name, device);
        if(ioctl(sockfd, SIOCGIFADDR, &ifr)<0) {
                perror("ioctl");
        }
        memcpy(&(p->srcip), (in_addr_t*)&((((struct sockaddr_in*)(&(ifr.ifr_addr)))->sin_addr).s_addr), sizeof(in_addr_t));
	close(sockfd);
	
	return TRUE;

}

IPLinkedList enumerate_ip(char* device, int* dstip_cnt)
{
	int sockfd;
	struct sockaddr_in sa_ipaddr;
	struct sockaddr_in sa_broadaddr;
	struct sockaddr_in sa_netmask;
	struct ifreq ifr;

	in_addr_t in_ipaddr;
	in_addr_t in_broadaddr;
	in_addr_t in_netmask;
	in_addr_t in_temp;

	int mask_length = 0;
	int host_length = 0;
	int i = 0, j = 0;

	IPLinkedList head=NULL, r=NULL, t=NULL;
	*dstip_cnt = 0;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	strcpy(ifr.ifr_name, device);
	if(ioctl(sockfd, SIOCGIFADDR, &ifr)<0) {
		perror("ioctl");
	}
	memcpy(&sa_ipaddr, (struct sockaddr_in*)(&ifr.ifr_addr), sizeof(struct sockaddr_in));
	memcpy(&in_ipaddr, (in_addr_t*)(&sa_ipaddr.sin_addr.s_addr), sizeof(in_addr_t));
        if(ioctl(sockfd, SIOCGIFBRDADDR, &ifr)<0) {
                perror("ioctl");
        }
	memcpy(&sa_broadaddr, (struct sockaddr_in*)(&ifr.ifr_broadaddr), sizeof(struct sockaddr_in));
	memcpy(&in_broadaddr, (in_addr_t*)(&sa_broadaddr.sin_addr.s_addr), sizeof(in_addr_t));
        if(ioctl(sockfd, SIOCGIFNETMASK, &ifr)<0) {
                perror("ioctl");
        }
	memcpy(&sa_netmask, (struct sockaddr_in*)(&ifr.ifr_netmask), sizeof(struct sockaddr_in));
	memcpy(&in_netmask, (in_addr_t*)(&sa_netmask.sin_addr.s_addr), sizeof(in_addr_t));
	memcpy(&in_temp, (in_addr_t*)&in_netmask, sizeof(in_addr_t));

	while(in_temp > 0) {
		mask_length++;
		in_temp = in_temp >> 1;
	}
	host_length = sizeof(in_addr_t)*8 - mask_length;

	i = 1;
	j = (~in_netmask)>>mask_length;
	while(i<j) {
		t = (IPLinkedList)malloc(sizeof(IPNode));
		t->next = NULL;
		t->data = (in_addr_t)((i<<mask_length) | (in_ipaddr<<host_length)>>host_length);
		if(head == NULL) {
			head = t;
			r = head;
		} else {
			r->next = t;
			r = r->next;
		}
		i++;
		(*dstip_cnt)++;
	}
	
	close(sockfd);

	return head;
}

MacLinkedList loadMacFile(const char* mac_file, int* cnt) {
	MacLinkedList list, p, r;
	list = (MacLinkedList) malloc(sizeof(MacNode));
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
		if (*cnt == 0) {
			mac_addr_aton(str, list->data);
		} else {
			p = (MacLinkedList) malloc(sizeof(MacNode));
			p->next = NULL;
			if (p == NULL) {
				perror("");
				fclose(fp);
				return NULL;
			}
			mac_addr_aton(str, p->data);
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
	struct config * pointer_config = (struct config*) malloc(sizeof(struct config));
	if (pointer_config == NULL) {
		perror("Memory allocation ERROR ! : ");
		return NULL;
	}
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
		case CONFIG_IP_QTY_THREAD:
			pointer_config->ip_qty_thread = atoi(value);
			config_flag |= CONFIG_IP_QTY_THREAD;
			break;
		case CONFIG_BROADCAST:
			pointer_config->broadcast = atoi(value)==0?FALSE:TRUE;
			config_flag |= CONFIG_BROADCAST;
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
			pointer_config->device = (char*) malloc(sizeof(char) * (1 + strlen(value)));
			strcpy(pointer_config->device, value);
			config_flag |= CONFIG_DEVICE;
			break;
		case CONFIG_SIZE:
			pointer_config->size = atoi(value);
			config_flag |= CONFIG_SIZE;
			break;
		case CONFIG_LOGFILE:
			pointer_config->logfile = (char*) malloc(sizeof(char) * (1 + strlen(value)));
			strcpy(pointer_config->logfile, value);
			config_flag |= CONFIG_LOGFILE;
			break;
		case CONFIG_LOGLEVEL:
			pointer_config->loglevel = switch_log_level(value);
			config_flag |= CONFIG_LOGLEVEL;
			break;
		default:
			break;
		}
	}
/*
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
*/
	populate_srcmac(pointer_config->device, pointer_config);
	populate_srcip(pointer_config->device, pointer_config);
	return pointer_config;
}

void freeConfig(struct config *p_config) {
	if (p_config->device != NULL)
		free(p_config->device);
	if (p_config->logfile != NULL)
		free(p_config->logfile);
}

/*
 * use access point ti identify whether interface is on work. 0 represents OK, other values mean not
 */
int getInterfaceStatus(char *interface) {
	char cmd[FILE_LINE_BUFFER_SIZE];
	/*sprintf(cmd, "iwconfig %s | grep -oP 'Access Point: \\K((\\w+-\\w+)|(\\w{2}:){5}(\\w){2})'", interface);*/

	/* To support most system, use basic RE in grep */
	sprintf(cmd, "iwconfig %s | grep -o 'Access Point:[[:space:]]\\+\\([-:[:alnum:]]\\+\\)' | awk 'END{print $3}'", interface);
	FILE* fs = popen(cmd, "r");
	char str[FILE_LINE_BUFFER_SIZE];
	int result = 0;
	if (fgets(str, FILE_LINE_BUFFER_SIZE, fs) != NULL) {
		if (strcmp("Not-Associated\n", str) == 0) {
		/* wlan interface is not associated with any AP */
			result = 1;
		}
	} else {
		/* wlan interface is down*/
		result = 2;
	}

	fclose(fs);
	return result;
}

/*
 * use iwconig set txpower for interface
 */
int setTxPower(char* interface, int nmW){
	char cmd[FILE_LINE_BUFFER_SIZE];
	int ret_code = 1;
	sprintf(cmd, "iwconfig %s txpower %dmW", interface, nmW);
	ret_code = system(cmd);
	return ret_code;
}

void freeIPLinkedList(IPLinkedList list) {
	IPLinkedList p, q;
	p = list;
	while (p != NULL) {
		q = p;
		p = p->next;
		free(q);
	}
}

void freeThreadInput(struct thread_input* input){
	if(input->device != NULL)
		free(input->device);
	if(input->payload != NULL)
		free(input->payload);
	if(input->dstip != NULL)
		freeIPLinkedList(input->dstip);
}

int main(int argc, char* argv[]) {

	int c;
	int srcmac_cnt;
	int dstip_cnt;
	int i = 0;
	char log_buf[FILE_LINE_BUFFER_SIZE];
	u_int8_t broadcast_mac_addr[MAC_ADDRESS_LENGTH] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	char *functionname = "main";
	struct config* pointer_config = NULL;

	/* check sudo previlege */
	if(geteuid() != getpwnam("root")->pw_uid) {
		puts("ERROR : I need root privilege to run, exiting...\n");
		return ERROR_USER;
	}

	while ((c = getopt(argc, argv, "c:")) != -1) {
		if (c == 'c') {
			pointer_config = load_config(optarg);
			if (pointer_config == NULL) {
				printf("ERROR : Invalid configuration file - %s, exiting...\n", optarg);
				return ERROR_CONFIG;
			}
		}
	}
	if(pointer_config == NULL) {
		puts("ERROR : No configuration file in input parameter, please use -c <filename>, exiting...\n");
		return ERROR_CONFIG;
	}

	if(!init_debug_log(pointer_config->logfile, pointer_config->loglevel)) {
		printf("ERROR : Cannot initialize log file %s for debugging, exiting...\n", pointer_config->logfile);
		return ERROR_CONFIG;
	}

        sprintf(log_buf, "INFO : Program is started \n");
        debug_log(INFO, functionname, log_buf);

	/* check wireless interface work */
	if (getInterfaceStatus(pointer_config->device) != 0) {
		sprintf(log_buf, "ERROR : Interface %s is not associated with any AP, please check it, exiting...\n", pointer_config->device);
		debug_log(SEVERE, functionname, log_buf);
		puts(log_buf);
		return ERROR_HARDWARE;
	}

	/* set wireless interface tx power 
	if (pointer_config->power != 0) {
		if (setTxPower(pointer_config->device, pointer_config->power) != 0) {
			sprintf(log_buf, "ERROR : Not able to manipulate the WiFi interface %s for new txPower, exiting...\n", pointer_config->device);
			debug_log(SEVERE, functionname, log_buf);
			puts(log_buf);
			return ERROR_HARDWARE;
		}
	} */

	IPLinkedList head = enumerate_ip(pointer_config->device, &dstip_cnt);
	int threadCount = dstip_cnt / pointer_config->ip_qty_thread;
	threadCount = threadCount==0?1:threadCount;
	u_int8_t *payload = NULL;
	if(pointer_config->size > 0) {
		u_int8_t *payload = malloc(pointer_config->size*sizeof(u_int8_t));
		for(i=0; i<pointer_config->size; i++) {
			payload[i] = 0x41+i%26;
		}
	}

	struct thread_input *input = malloc(threadCount*sizeof(struct thread_input));
	pthread_t *tid = malloc(threadCount * sizeof(pthread_t));
	for (i = 0; i < threadCount; i++) {
		(input+i)->device = malloc((1+strlen(pointer_config->device))*sizeof(char));
		memcpy((input+i)->device, pointer_config->device, (1+strlen(pointer_config->device))*sizeof(char));
		(input+i)->interval = pointer_config->interval;
		(input+i)->size = pointer_config->size;
		(input+i)->srcip = pointer_config->srcip;
		memcpy((input+i)->dstmac, pointer_config->dstmac, MAC_ADDRESS_LENGTH*sizeof(u_int8_t));
		if(pointer_config->size != 0) {
			(input+i)->payload = (u_int8_t*) malloc(pointer_config->size*sizeof(u_int8_t));
			memcpy((input+i)->payload, payload, pointer_config->size*sizeof(u_int8_t));
		} else {
			(input+i)->payload = NULL;
		}
		if(i+1 == threadCount) {
			(input+i)->dstip = subiplist(&head, 2*pointer_config->ip_qty_thread); // get all of the remains 
		} else {
			(input+i)->dstip = subiplist(&head, pointer_config->ip_qty_thread);
		}
		if(pointer_config->broadcast == TRUE) {
			memcpy((input+i)->dstmac, broadcast_mac_addr, MAC_ADDRESS_LENGTH*sizeof(u_int8_t));
			pthread_create(&tid[i], NULL, thread_routine_b, (void*)(input+i));
		} else {
			pthread_create(&tid[i], NULL, thread_routine, (void*)(input+i));
		}
	}

	/* Wait all worker thread to complete tasks */
	for (i = 0; i < threadCount; i++) {
		pthread_join(tid[i], NULL);
	}

	/* free thread input data memory block */
	for (i = 0; i < threadCount; i++) {
		freeThreadInput(input+i);
	}
	free(input);
	free(tid);

	/* free config data */
	freeConfig(pointer_config);
	free(payload);

        sprintf(log_buf, "INFO : Program is finished\n");
        debug_log(INFO, functionname, log_buf);

	deinit_debug_log();

	return 0;
}

