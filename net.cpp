#include "net.h"
#include <stdio.h>
#include <libnet.h>
void print_mac(u_int8_t host[]){
    for(int i=0;i<ETHER_ADDR_LEN-1;i++){
        printf("%02x:", host[i]);
    }
    printf("%02x\n", host[ETHER_ADDR_LEN-1]);
}
void print_ETHER(struct libnet_ethernet_hdr * ethernet){
    printf("-------ETHER-------\n");
    printf("src(mac) : ");
    print_mac(ethernet->ether_shost);

    printf("dst(mac) : ");
    print_mac(ethernet->ether_dhost);
    printf("\n");
}

void print_ip(uint32_t ip){
    printf("%u.", (ip & 0xFF000000)>>24);
    printf("%u.", (ip & 0x00FF0000)>>16);
    printf("%u.", (ip & 0x0000FF00)>>8);
    printf("%u", ip & 0x000000FF);
}

void print_IPv4(struct libnet_ipv4_hdr * ipv4){
    printf("-------IPv4-------\n");
    printf("src(ip) : ");
    print_ip(ntohl(ipv4->ip_src.s_addr));
    printf("\n");

    printf("dst(ip) : ");  
    print_ip(ntohl(ipv4->ip_dst.s_addr));
    printf("\n\n");
}

void print_TCP(struct libnet_tcp_hdr * tcp){
    printf("-------TCP-------\n");
    printf("src(port) : %d\n", ntohs(tcp->th_sport));
    printf("dst(port) : %d\n", ntohs(tcp->th_dport));
    printf("\n");
}

void print_DATA(const u_char* normalPacket, int data_len){
    printf("-------DATA-------\n");
    if(data_len <= 20){
        for(int i=0;i<data_len;i++){
            if(i==10) printf("\n");
            printf("%02x ", normalPacket[i]);
        }
    }
    else{
        for(int i=0;i<20;i++){
            if(i==10) printf("\n");
            printf("%02x ", normalPacket[i]);
        }
    }
}