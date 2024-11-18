#include "hashtable.h"
#include "isa-top.h"

#define HASH_SIZE 1024

connection_stats_t *hash_table[HASH_SIZE];

unsigned int hash_function(connection_key_t *key) {
    unsigned int hash = 0;
    char combined[INET6_ADDRSTRLEN * 2 + 10 + 8]; 
    snprintf(combined, sizeof(combined), "%s%s%d%d%s", key->src_ip, key->dst_ip, key->src_port,
             key->dst_port, key->protocol);
    for (int i = 0; combined[i] != '\0'; i++) {
        hash = (hash * 31) + combined[i];
    }
    return hash % HASH_SIZE;
}

void insert_merged(connection_stats_t *merged, unsigned int hash_index) {
    
    connection_stats_t *current = hash_table[hash_index];
    connection_stats_t *prev = NULL;

    // Search for existing connection
    while (current != NULL) {
        if (strcmp(current->key.src_ip, merged->key.src_ip) == 0 &&
            strcmp(current->key.dst_ip, merged->key.dst_ip) == 0 &&
            current->key.src_port == merged->key.src_port &&
            current->key.dst_port == merged->key.dst_port &&
            strcmp(current->key.protocol, merged->key.protocol) == 0) {

            // Merge stats
            current->rx_bytes = merged->rx_bytes;
            current->rx_packets = merged->rx_packets;
            current->tx_bytes = merged->tx_bytes;
            current->tx_packets = merged->tx_packets;
            current->update_time = merged->update_time;
            return;
        }
        prev = current;
        current = current->next;
    }

    // If no matching connection found, insert the merged connection at the hash index
    merged->next = hash_table[hash_index];
    hash_table[hash_index] = merged;
}


void insert_or_update(connection_key_t *key, uint64_t bytes) {
    unsigned int hash_index = hash_function(key);
    // First check if we have a reverse connection
    connection_key_t reverse_key;
    strcpy(reverse_key.src_ip, key->dst_ip);
    reverse_key.src_port = key->dst_port;
    strcpy(reverse_key.dst_ip, key->src_ip);
    reverse_key.dst_port = key->src_port;
    strcpy(reverse_key.protocol, key->protocol);
    connection_stats_t *reverse_conn = find(&reverse_key);
    connection_stats_t merged;
    
    connection_stats_t *current = find(key);
    if (current != NULL) {
        
        current->tx_bytes += bytes;
        current->tx_packets += 1;
        current->update_time = time(NULL);

        
        if (reverse_conn != NULL) {
            if (strcmp(current->key.src_ip, current->key.dst_ip) != 0) {
                merged = merge(current, reverse_conn);
                delete(&reverse_key); 
            } else {
                merged = merge(current, reverse_conn);
            
            }
            insert_merged(&merged, hash_function(&merged.key));
        }
        
        return;
    }

    if (reverse_conn != NULL) {
        reverse_conn->rx_bytes += bytes;
        reverse_conn->rx_packets += 1;
        reverse_conn->update_time = time(NULL);
        return;
    }

    
    connection_stats_t *new_entry = malloc(sizeof(connection_stats_t));
    new_entry->key = *key;
    new_entry->update_time = time(NULL);
    new_entry->rx_bytes = 0;
    new_entry->rx_packets = 0;
    new_entry->tx_bytes = bytes;
    new_entry->tx_packets = 1;
    new_entry->next = hash_table[hash_index];
    new_entry->tx_speed = 0;
    new_entry->rx_speed = 0;
    new_entry->rx_packet_speed = 0;
    new_entry->tx_packet_speed = 0;
    hash_table[hash_index] = new_entry;
}

connection_stats_t *find(connection_key_t *key) {
    unsigned int hash_index = hash_function(key);
    connection_stats_t *current = hash_table[hash_index];

    while (current != NULL) {
        if (strcmp(current->key.src_ip, key->src_ip) == 0 &&
            strcmp(current->key.dst_ip, key->dst_ip) == 0 &&
            current->key.src_port == key->src_port && current->key.dst_port == key->dst_port &&
            strcmp(current->key.protocol, key->protocol) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void delete(connection_key_t *key) {
    unsigned int hash_index = hash_function(key);
    connection_stats_t *current = hash_table[hash_index];
    connection_stats_t *prev = NULL;

    while (current != NULL) {
        if (strcmp(current->key.src_ip, key->src_ip) == 0 &&
            strcmp(current->key.dst_ip, key->dst_ip) == 0 &&
            current->key.src_port == key->src_port && current->key.dst_port == key->dst_port &&
            strcmp(current->key.protocol, key->protocol) == 0) {
            if (prev == NULL) {
                hash_table[hash_index] = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

