#include <libnet.h>
void print_ETHER(struct libnet_ethernet_hdr *);
void print_IPv4(struct libnet_ipv4_hdr *);
void print_TCP(struct libnet_tcp_hdr *);
void print_DATA(const u_char* normalPacket, int data_len);