#ifndef ISA_TOP_H
#define ISA_TOP_H

#include <sys/types.h>
#include <arpa/inet.h>

#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <ncurses.h>
#include <pthread.h>

#include "hashtable.h"

connection_stats_t merge(connection_stats_t *connection1, connection_stats_t *connection2);
pcap_t *create_pcap_handle(char *interface);
void get_link_header_len(pcap_t *handle);
void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr);
void stop_capture(int signo);
int main(int argc, char *argv[]);
void update_speed(connection_stats_t *conn);
int compare(const void *a, const void *b);
void format_ip_port(char *protocol, const char *ip, uint16_t port, char *buffer,
                    size_t buffer_size);
void format_p_count(uint64_t packets, char *buffer, size_t buffer_size);
void format_b_speed(uint64_t speed, char *buffer, size_t buffer_size);

#endif // ISA_TOP_H