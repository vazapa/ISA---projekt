#include "hashtable.h"
#include "isa-top.h"

#define HASH_SIZE 1024

connection_stats_t *hash_table[HASH_SIZE];

unsigned int hash_function(connection_key_t *key) {
    unsigned int hash = 0;
    char combined[INET6_ADDRSTRLEN * 2 + 10 + 8]; // Adjust size for protocol string
    snprintf(combined, sizeof(combined), "%s%s%d%d%s", key->src_ip, key->dst_ip, key->src_port, key->dst_port, key->protocol);
    for (int i = 0; combined[i] != '\0'; i++) {
        hash = (hash * 31) + combined[i];
    }
    return hash % HASH_SIZE;
}

void insert_or_update(connection_key_t *key, uint64_t bytes) {
    unsigned int hash_index = hash_function(key);
    connection_stats_t *current = hash_table[hash_index];
    time_t now = time(NULL); // todo

    while (current != NULL) {
        if (strcmp(current->key.src_ip, key->src_ip) == 0 &&
            strcmp(current->key.dst_ip, key->dst_ip) == 0 &&
            current->key.src_port == key->src_port &&
            current->key.dst_port == key->dst_port &&
            strcmp(current->key.protocol, key->protocol) == 0) {
            current->tx_bytes += bytes;
            current->tx_packets += 1;
            current->update_time = now;
            return;
        }
        current = current->next;
    }

    connection_stats_t *new_entry = (connection_stats_t *)malloc(sizeof(connection_stats_t));
    new_entry->key = *key;
    new_entry->update_time = now;
    new_entry->rx_bytes = 0;
    new_entry->rx_packets = 0;
    new_entry->tx_bytes = bytes;
    new_entry->tx_packets = 1;
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
            current->key.src_port == key->src_port &&
            current->key.dst_port == key->dst_port &&
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


void print_all_items() {
    printf("Printing all items from the hashtable:\n");
    for (int i = 0; i < HASH_SIZE; i++) {
        connection_stats_t *current = hash_table[i];
        while (current != NULL) {
            connection_key_t sec_connection;
            strcpy(sec_connection.src_ip,current->key.dst_ip);
            sec_connection.src_port = current->key.dst_port;
            strcpy(sec_connection.dst_ip,current->key.src_ip);
            sec_connection.dst_port = current->key.src_port;
            strcpy(sec_connection.protocol,current->key.protocol);

            connection_stats_t *found_connection = find(&sec_connection);
            if(current->key.src_port == 80 || current->key.dst_port == 80){
                if(found_connection != NULL){

                    connection_stats_t merged_connection = merge(current,found_connection);
                    printf("nasel jsem counter connection\n");
                    printf("Src IP: %s, Src Port: %d, Dst IP: %s, Dst Port: %d, Protocol: %s, Rx Bytes: %lu, Rx Packets: %lu, Tx Bytes: %lu, Tx Packets: %lu\n",
                        merged_connection.key.src_ip, merged_connection.key.src_port,
                        merged_connection.key.dst_ip, merged_connection.key.dst_port,
                        merged_connection.key.protocol,
                        merged_connection.rx_bytes, merged_connection.rx_packets,
                        merged_connection.tx_bytes, merged_connection.tx_packets);

                    // Delete the reverse connection to avoid duplicate printing
                    delete(&sec_connection);
                }else{
                    printf("Src IP: %s, Src Port: %d, Dst IP: %s, Dst Port: %d, Protocol: %s, Rx Bytes: %lu, Rx Packets: %lu, Tx Bytes: %lu, Tx Packets: %lu\n",
                        current->key.src_ip, current->key.src_port,
                        current->key.dst_ip, current->key.dst_port,
                        current->key.protocol,
                        current->rx_bytes, current->rx_packets,
                        current->tx_bytes, current->tx_packets);
                }
            }
            current = current->next;
        }
    }
}