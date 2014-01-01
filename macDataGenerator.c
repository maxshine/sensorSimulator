#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#define MAC_ADDRESS_LENGTH 6

#define MAX_QTY_1 254U
#define MAX_QTY_2 65534U
#define MAX_QTY_3 16777214U
#define MAX_QTY_4 4294967294U

#define DIVIDER_4 4294967295U
#define DIVIDER_3 16777215U
#define DIVIDER_2 65535U
#define DIVIDER_1 255U

#define FILE_LINE_BUFFER_SIZE 200


u_int8_t hex_atob(char* p) {
	u_int8_t buf = (u_int8_t)((p[0]-(isalpha(p[0])?(islower(p[0])?0x61-0xa:0x41-0xA):0x30))*16
		+(p[1]-(isalpha(p[1])?(islower(p[1])?0x61-0xa:0x41-0xA):0x30)));
        return buf; 
}

void usage(void)
{
	puts("Error usage !\n");
	puts("Usage : macDataGenerator <mac_prefix> <qty_to_create> <output_filename>\n");
	puts("Example : macDataGenerator 14:11 1000 macid.data\n");
	puts("\n");
}

unsigned int switch_qty_max(int i)
{
	switch(i) {
		case 0:
			puts("ERROR : Input MAC prefix is incorrect !\n");
			break;
		case 1:
			return MAX_QTY_1;
		case 2:
			return MAX_QTY_2;
		case 3:
			return MAX_QTY_3;
		case 4:
			return MAX_QTY_4;
		default:
			puts("ERROR : Input MAC prefix is incorrect !\n");
	}
	return 0U;
}

unsigned int switch_divider(int i)
{
	switch(i) {
		case 0:
			puts("ERROR : Divider zero ERROR !\n");
			break;
		case 1:
			return DIVIDER_1;
		case 2:
			return DIVIDER_2;
		case 3:
			return DIVIDER_3;
		case 4:
			return DIVIDER_4;
		default:
			puts("ERROR : Invalid divider !\n");
	}
	return 0U;
}

int main(int argc, char* argv[])
{
	if(argc != 4) {
		usage();
		return 1;
	}

	unsigned int prefix_bits = 0;
	unsigned int bits_to_do = 0;
	unsigned int i,j,k;
	unsigned int qty_to_create = atoi(argv[2]);
	FILE *fp = fopen(argv[3], "w");
	char* t;
	u_int8_t mac[MAC_ADDRESS_LENGTH];
	memset(mac, 0x0, MAC_ADDRESS_LENGTH*sizeof(u_int8_t));

	if(fp == NULL) {
		perror("ERROR open output file : ");
		return 1;
	}

	char *mac_prefix = malloc((1+strlen(argv[3]))*sizeof(char));
	memcpy(mac_prefix, argv[1], 1+strlen(argv[3]));

	t = strtok(argv[1], ":");
	i = 0;
	while(t!=NULL) {
		mac[i] =  hex_atob(t);
		i++;
		t = strtok(NULL, ":");
	}
	prefix_bits = i;
	bits_to_do = MAC_ADDRESS_LENGTH - prefix_bits;
	if(bits_to_do<1 || bits_to_do>4) {
		puts("ERROR : Invalid input mac prefix !\n");
		return 2;
	}

	if(qty_to_create >= switch_qty_max(bits_to_do)) {
		puts("ERROR : MAC quantity exceeds the limits\n");
		return 3;
	}

	for(i=0; i<qty_to_create; i++) {
		j = bits_to_do;
		k = i+1;
		while(j>1) {
			mac[MAC_ADDRESS_LENGTH-j] = k / switch_divider(j);
			k = k % switch_divider(j);
			j--;
		}
		mac[MAC_ADDRESS_LENGTH-j] = k;
		fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	fclose(fp);
	return 0;
}

