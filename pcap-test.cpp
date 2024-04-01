#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include "net.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr *) packet;
		if(ethernet->ether_type!=ntohs(0x0800)) continue;

		struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *) (packet+sizeof(*ethernet));
		if(ipv4->ip_p!=6) continue;
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *) (packet+sizeof(*ethernet)+(ipv4->ip_hl)*4);
		int data_len = header->caplen - (sizeof(*ethernet)+(ipv4->ip_hl)*4+(tcp->th_off)*4);
		const u_char* normalPacket = (u_char *) (packet+sizeof(*ethernet)+(ipv4->ip_hl)*4+(tcp->th_off)*4);

		print_ETHER(ethernet);
		print_IPv4(ipv4);
		print_TCP(tcp);
		print_DATA(normalPacket, data_len);
		printf("\n\n\n");
	}

	pcap_close(pcap);
}
