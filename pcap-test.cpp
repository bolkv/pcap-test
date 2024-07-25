#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include "pcap-test.h"
#include <stdint.h>
#include <arpa/inet.h>

void usage(){
	printf("syntax: pcap-test <interface>\n");
	printf("simple: pcap-test eth0\n");
}


Param param ={
	.dev_ =NULL
};


bool parse(Param* param, int argc, char*argv[]){
	if(argc != 2){
		usage();
		return false;
	}

	param->dev_ = argv[1];
	return true;
}

bool isTCP(struct libnet_ipv4_hdr* ipv4_hdr){
	if((ipv4_hdr ->ip_p) == TCP){
	       return true;
	}
	else return false;
	
}



void print_info_packet(const u_char* packet){

	struct libnet_ipv4_hdr* hdr = (struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr));
	if(isTCP(hdr)){
	
		printf("============================\n");
		print_ethernet_info(packet);
		packet += sizeof(struct libnet_ethernet_hdr);
		print_ipv4_info(packet);
		packet += sizeof(struct libnet_ipv4_hdr);
		print_tcp_info(packet);
		print_data(packet);
		printf("============================\n");
	}
	else printf("This Packet is not TCP\n");

}

void print_mac(const uint8_t *mac){
	for(int i=0;i<6;i++){
		printf("%02x ",mac[i]);
	}
	printf("\n");
}

void print_ethernet_info(const u_char* packet){
	printf("Ethernet Header\n");
	struct libnet_ethernet_hdr*  ethernet_hdr = ( struct libnet_ethernet_hdr*)packet;
	printf("Source Mac Address: ");
	print_mac(ethernet_hdr->ether_shost);
	printf("Destinatation Mac Address: ");
	print_mac(ethernet_hdr->ether_dhost);
	printf("\n");
}

void print_ip(struct in_addr ip){
	unsigned char* bytes = (unsigned char*)&ip;
	printf("%d.%d.%d.%d\n", bytes[0],bytes[1],bytes[2],bytes[3]);
}

void print_ipv4_info(const u_char* packet){

	printf("Ipv4 Header\n");
	struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)packet;
	printf("Source Ip Address: ");
	print_ip(ipv4_hdr->ip_src);
	printf("Destination Ip Address: ");
	print_ip(ipv4_hdr->ip_dst);

	printf("\n");
}

void print_tcp_info(const u_char* packet){
	printf("TCP Header\n");
	struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)packet;
	printf("Source Port: %u\n ",ntohs(tcp_hdr->th_sport));
	printf("Destination Port: %u\n",ntohs(tcp_hdr->th_dport));
	printf("\n");
}

void print_data(const u_char* packet){
	printf("DATA\n");
	packet += sizeof(struct libnet_tcp_hdr);
	for(int i=0;i<20;i++){
		printf("%02x",packet[i]);
	}
	printf("\n");

}


int main(int argc, char*argv[]){
	
	if(!parse(&param,argc,argv)){
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap;
	pcap = pcap_open_live(param.dev_, BUFSIZ,1,1000,errbuf);

	if(pcap == NULL){
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n",param.dev_,errbuf);
		return -1;
	}

	while(true){

		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap,&header,&packet);
		if(res == 0) continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
			printf("pcap_next_ex return %d(%s)\n",res,pcap_geterr(pcap));
			break;
		}

		print_info_packet(packet);

	}

	pcap_close(pcap);

	return 0;
}

