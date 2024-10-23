#ifndef ISA_TOP_H
#define ISA_TOP_H

#include <stdlib.h>
#include <stdio.h>
#include <ncurses.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <time.h>
#include "hashtable.h"

connection_stats_t merge(connection_stats_t *connection1,connection_stats_t *connection2);
pcap_t* create_pcap_handle(char* interface);
void get_link_header_len(pcap_t* handle);
void packet_handler(u_char *user,const struct pcap_pkthdr *packethdr, const u_char *packetptr);
void stop_capture(int signo);
int main(int argc, char* argv[]);

#endif // ISA_TOP_H