#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main(void)
{
	int32_t SockFd;
	int32_t len;
	SockFd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if(SockFd == -1) {
		perror("Open socket ERROR");
	}
	char szBuff[10] = "This is a";

	struct sockaddr_ll stTagAddr;
	memset(&stTagAddr, 0, sizeof(stTagAddr));
	stTagAddr.sll_family    = AF_PACKET;
	stTagAddr.sll_protocol  = htons(ETH_P_IP);
	int ret;
	struct ifreq req;
	int sd;
	sd = socket(AF_INET,SOCK_DGRAM,0);
	strcpy(req.ifr_name,"wlan0");
	ret=ioctl(sd,SIOCGIFINDEX,&req);
	if(ret == -1) {
		perror("ERROR IOCTL");
	}
	close(sd);
	stTagAddr.sll_ifindex   = req.ifr_ifindex;
	stTagAddr.sll_pkttype   = PACKET_OUTGOING;
	stTagAddr.sll_halen     = 6;

	stTagAddr.sll_addr[0]   = 0x00;
	stTagAddr.sll_addr[1]   = 0x01;
	stTagAddr.sll_addr[2]   = 0x02;
	stTagAddr.sll_addr[3]   = 0x03;
	stTagAddr.sll_addr[4]   = 0x04;
	stTagAddr.sll_addr[5]   = 0x05;
	stTagAddr.sll_addr[6]   = 0x06;
	stTagAddr.sll_addr[7]   = 0x07;

	while(1) {
		len = sendto(SockFd, (int8_t *)szBuff, sizeof(szBuff), 0, (const struct sockaddr *)&stTagAddr, sizeof(stTagAddr));
		if(len == -1) {
			perror("ERROR : ");
		}
		printf("Send out %d bytes\n", len);
		sleep(1);
	}
	return 0;
}
