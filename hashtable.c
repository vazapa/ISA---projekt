#include "hashtable.h"
#define HASH_SIZE 1024

connection_stats_t *hash_table[HASH_SIZE];

unsigned int hash_function(connection_key_t *key) {
    unsigned int hash = 0;
    char combined[INET6_ADDRSTRLEN * 2 + 10];
    snprintf(combined, sizeof(combined), "%s%s%d%d%d", key->src_ip, key->dst_ip, key->src_port, key->dst_port, key->protocol);
    for (int i = 0; combined[i] != '\0'; i++) {
        hash = (hash * 31) + combined[i];
    }
    return hash % HASH_SIZE;
}

void insert_or_update(connection_key_t *key, uint64_t bytes) {
    unsigned int hash_index = hash_function(key);
    connection_stats_t *current = hash_table[hash_index];

    while (current != NULL) {
        if (strcmp(current->key.src_ip, key->src_ip) == 0 &&
            strcmp(current->key.dst_ip, key->dst_ip) == 0 &&
            current->key.src_port == key->src_port &&
            current->key.dst_port == key->dst_port &&
            current->key.protocol == key->protocol) {
            current->rx_bytes += bytes;
            current->rx_packets += 1;
            return;
        }
        current = current->next;
    }

    connection_stats_t *new_entry = (connection_stats_t *)malloc(sizeof(connection_stats_t));
    new_entry->key = *key;
    new_entry->rx_bytes = bytes;
    new_entry->rx_packets = 1;
    new_entry->tx_bytes = 0;
    new_entry->tx_packets = 0;
    new_entry->next = hash_table[hash_index];
    hash_table[hash_index] = new_entry;
}

connection_stats_t *find(connection_key_t *key) {
    unsigned int hash_index = hash_function(key);
    connection_stats_t *current = hash_table[hash_index];

    while (current != NULL) {
        if (strcmp(current->key.src_ip, key->src_ip) == 0 &&
            strcmp(current->key.dst_ip, key->dst_ip) == 0 &&
            current->key.src_port == key->src_port &&
            current->key.dst_port == key->dst_port &&
            current->key.protocol == key->protocol) {
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
            current->key.src_port == key->src_port &&
            current->key.dst_port == key->dst_port &&
            current->key.protocol == key->protocol) {
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

