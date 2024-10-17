#include <stdlib.h>
#include <stdio.h>
#include <ncurses.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <signal.h>


typedef struct connection_key {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} connection_key_t;

typedef struct connection_stats {
    connection_key_t key;
    uint64_t rx_bytes;
    uint64_t rx_packets;
    uint64_t tx_bytes;
    uint64_t tx_packets;
    struct connection_stats *next;
} connection_stats_t;

unsigned int hash_function(connection_key_t *key);
void insert_or_update(connection_key_t *key, uint64_t bytes);
connection_stats_t *find(connection_key_t *key);
void delete(connection_key_t *key);