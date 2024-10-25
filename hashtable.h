#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdint.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct connection_key {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    char protocol[8]; // Use a string for protocol
} connection_key_t;

typedef struct connection_stats {
    connection_key_t key;
    uint64_t rx_bytes;
    uint64_t rx_packets;
    uint64_t tx_bytes;
    uint64_t tx_packets;
    time_t update_time;
    struct connection_stats *next;
} connection_stats_t;

unsigned int hash_function(connection_key_t *key);
void insert_or_update(connection_key_t *key, uint64_t bytes);
connection_stats_t *find(connection_key_t *key);
void delete(connection_key_t *key);
void insert_merged(connection_stats_t *merged, unsigned int hash_index);
void print_all_items();

#endif // HASHTABLE_H