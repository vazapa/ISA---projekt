/*
* Name: Vaclav Zapletal
* Login: xzaple40
*/

#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>

#define HASH_SIZE 1024

typedef struct connection_stats connection_stats_t;

extern connection_stats_t *hash_table[HASH_SIZE];

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
    time_t tx_speed;
    time_t tx_packet_speed;
    time_t rx_speed;
    time_t rx_packet_speed;
    struct connection_stats *next;
    // time_t last_active;

} connection_stats_t;

unsigned int hash_function(connection_key_t *key);
void insert_or_update(connection_key_t *key, uint64_t bytes);
connection_stats_t *find(connection_key_t *key);
void delete(connection_key_t *key);
void insert_merged(connection_stats_t *merged, unsigned int hash_index);
void print_all_items();

#endif // HASHTABLE_H