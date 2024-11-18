/*
* Name: Vaclav Zapletal
* Login: xzaple40
*/

/*
 * Parts of the following code are inspired by/adapted from:
 * Title: Develop a Packet Sniffer with Libpcap
 * Author: Vic Hargrave
 * Source: https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/
 * License: Apache License, Version 2.0
 * 
 * Unedited functions:
 *  *pcap_t *create_pcap_handle(char *interface) 
 *  void get_link_header_len(pcap_t *handle) 
 * 
 * Edited functions:
 *  void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) 
 *  void stop_capture(int signo) 
 */

#include "hashtable.h"
#include "isa-top.h"

#define SRC_IP_PORT_WIDTH 45
#define DST_IP_PORT_WIDTH 55
#define PROTO_WIDTH 10
#define RX_WIDTH 15
#define TX_WIDTH 15
#define SPEED_WIDTH 8
#define PKT_WIDTH 6

#define KILO 1000
#define MEGA 1000000
#define GIGA 1000000000

pcap_t *pcap_handle;
int header_length;
char order;


// Updates speed of connection and reset its values
void update_speed(connection_stats_t *conn) {
    time_t now = time(NULL);
    double time_difference = difftime(now, conn->update_time);

    conn->rx_speed = ((conn->rx_bytes)) / (time_difference + 1);
    conn->tx_speed = ((conn->tx_bytes)) / (time_difference + 1);
    conn->rx_packet_speed = conn->rx_packets / (time_difference + 1);
    conn->tx_packet_speed = conn->tx_packets / (time_difference + 1);

    if ( conn->rx_bytes > 0 || conn->tx_bytes > 0 || conn->rx_packets > 0 || conn->tx_packets > 0) {
        
        conn->rx_bytes = 0;
        conn->tx_bytes = 0;
        conn->tx_packets = 0;
        conn->rx_packets = 0;
        conn->update_time = now;
        
    } else {
        if (difftime(now, conn->update_time) > 1.0) {
            
            delete (&conn->key);
            return;
        }
    }

}

// Comparing function for qsort
int compare(const void *a, const void *b) {
    connection_stats_t *conn_a = *((connection_stats_t **)a);
    connection_stats_t *conn_b = *((connection_stats_t **)b);

    if (order == 'b') {
        if (conn_a->tx_speed > conn_a->rx_speed) {
            if (conn_a->tx_speed < conn_b->tx_speed)
                return 1;
            if (conn_a->tx_speed > conn_b->tx_speed)
                return -1;
        } else {
            if (conn_a->rx_speed < conn_b->rx_speed)
                return 1;
            if (conn_a->rx_speed > conn_b->rx_speed)
                return -1;
        }
    } else {
        if (conn_a->tx_packet_speed > conn_a->rx_packet_speed) {
            if (conn_a->tx_packet_speed < conn_b->tx_packet_speed)
                return 1;
            if (conn_a->tx_packet_speed > conn_b->tx_packet_speed)
                return -1;
        } else {
            if (conn_a->rx_packet_speed < conn_b->rx_packet_speed)
                return 1;
            if (conn_a->rx_packet_speed > conn_b->rx_packet_speed)
                return -1;
        }
    }
    return 0;
}


// Prints 10 connections with highest speed
void print_top_connections() {

    clear();

    printw("%-*s %-*s %-*s %*s %*s %*s %*s\n", SRC_IP_PORT_WIDTH, "Src IP:port", DST_IP_PORT_WIDTH,
           "Dst IP:port", PROTO_WIDTH, "Proto", SPEED_WIDTH, "Rx b/s", PKT_WIDTH, "p/s",
           SPEED_WIDTH, "Tx b/s", PKT_WIDTH, "p/s");

    connection_stats_t *top_connections[HASH_SIZE * 10]; 

    int count = 0;

    for (int i = 0; i < HASH_SIZE; i++) {
        connection_stats_t *current = hash_table[i];
        
        while (current != NULL) {

            update_speed(current);

            if (count < 10) {
                top_connections[count++] = current;
            } else { //If there is more than 10 connections, it calculate traffic and stores only highest

                int min_idx = 0;
                uint64_t min_traffic = top_connections[0]->rx_speed + top_connections[0]->tx_speed;

                for (int j = 1; j < 10; j++) {
                    uint64_t traffic = top_connections[j]->rx_speed +top_connections[j]->tx_speed; 
                    if (traffic < min_traffic) {
                        min_idx = j;
                        min_traffic = traffic;
                    }
                }

                uint64_t current_traffic = current->rx_speed + current->tx_speed;
                if (current_traffic > min_traffic) {
                    top_connections[min_idx] = current;
                }
            }
            current = current->next;
        }
    }
    qsort(top_connections, count, sizeof(connection_stats_t *), compare); // Sorting using compare


    // Printing with correct spaces and format
    for (int i = 0; i < count; i++) {
        connection_stats_t *conn = top_connections[i];

        time_t now = time(NULL);
        char src_ip_port[SRC_IP_PORT_WIDTH];
        char dst_ip_port[DST_IP_PORT_WIDTH];
        char rx_speed_str[8];
        char tx_speed_str[8];

        snprintf(src_ip_port, SRC_IP_PORT_WIDTH, "%s:%d", conn->key.src_ip, conn->key.src_port);
        snprintf(dst_ip_port, DST_IP_PORT_WIDTH, "%s:%d", conn->key.dst_ip, conn->key.dst_port);

        format_b_speed(conn->rx_speed, rx_speed_str, sizeof(rx_speed_str));
        format_b_speed(conn->tx_speed, tx_speed_str, sizeof(tx_speed_str));

        char rx_pkt_str[8];
        char tx_pkt_str[8];
        format_p_count(conn->rx_packet_speed, rx_pkt_str, sizeof(rx_pkt_str));
        format_p_count(conn->tx_packet_speed, tx_pkt_str, sizeof(tx_pkt_str));

        format_ip_port(conn->key.protocol, conn->key.src_ip, conn->key.src_port, src_ip_port,
                       SRC_IP_PORT_WIDTH);
        format_ip_port(conn->key.protocol, conn->key.dst_ip, conn->key.dst_port, dst_ip_port,
                       DST_IP_PORT_WIDTH);

        if ((conn->rx_speed != 0 && conn->tx_speed != 0) ||
            (difftime(now, conn->update_time) < 5.0)) {

            if (strcmp(conn->key.protocol, "icmp") == 0) {
                printw("%-*s %-*s %-*s %*s %*s %*s %*s\n", SRC_IP_PORT_WIDTH, conn->key.src_ip,
                       DST_IP_PORT_WIDTH, conn->key.dst_ip, PROTO_WIDTH, conn->key.protocol,
                       SPEED_WIDTH, rx_speed_str, PKT_WIDTH, rx_pkt_str, SPEED_WIDTH, tx_speed_str,
                       PKT_WIDTH, tx_pkt_str);
            } else {
                printw("%-*s %-*s %-*s %*s %*s %*s %*s\n", SRC_IP_PORT_WIDTH, src_ip_port,
                       DST_IP_PORT_WIDTH, dst_ip_port, PROTO_WIDTH, conn->key.protocol, SPEED_WIDTH,
                       rx_speed_str, PKT_WIDTH, rx_pkt_str, SPEED_WIDTH, tx_speed_str, PKT_WIDTH,
                       tx_pkt_str);
            }
        }
    }
}

// Loop for displaying statistics in separate thread
void *display_loop(void *args) {

    while (1) {
        print_top_connections();
        refresh();
        sleep(1);
    }
    return NULL;
}

// Merges 2 connections into one
connection_stats_t merge(connection_stats_t *connection1, connection_stats_t *connection2) {

    connection_stats_t merged_connection;

    
    strcpy(merged_connection.key.src_ip, connection1->key.src_ip);
    merged_connection.key.src_port = connection1->key.src_port;
    strcpy(merged_connection.key.dst_ip, connection1->key.dst_ip);
    merged_connection.key.dst_port = connection1->key.dst_port;
    strcpy(merged_connection.key.protocol, connection1->key.protocol);

   
    merged_connection.tx_packets = connection1->tx_packets;
    merged_connection.tx_bytes = connection1->tx_bytes;
    merged_connection.rx_packets = connection2->tx_packets;
    merged_connection.rx_bytes = connection2->tx_bytes;
    

    merged_connection.update_time = connection1->update_time;
    

    return merged_connection;
}

pcap_t *create_pcap_handle(char *interface) 
{
    pcap_t *created_handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 network_mask;
    bpf_u_int32 source_ip;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char filter[] = "";

    // Get network interface source IP address and network_mask.
    if (pcap_lookupnet(interface, &source_ip, &network_mask, error_buffer) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", error_buffer);
        endwin();
        exit(0);
        
    }

    // Open the interface for live capture.
    created_handle = pcap_open_live(interface, BUFSIZ, 1, 1000, error_buffer);
    if (created_handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", error_buffer);
        endwin();
        exit(0);
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(created_handle, &bpf, filter, 1, network_mask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(created_handle));
        endwin();
        exit(0);
    }

    // Bind the packet filter to the libpcap created_handle.
    if (pcap_setfilter(created_handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(created_handle));
        endwin();
        exit(0);
    }

    return created_handle;
}

void get_link_header_len(pcap_t *handle) 
{
    int link_type;

    // Determine the datalink layer type.
    if ((link_type = pcap_datalink(handle)) == PCAP_ERROR) {
        printf("pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }

    // Set the datalink layer header size.
    switch (link_type) {
    case DLT_NULL:
        header_length = 4;
        break;

    case DLT_EN10MB:
        header_length = 14;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        header_length = 24;
        break;

    default:
        return;
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {

    struct ip *ip_header;
    struct ip6_hdr *ip6_header;
    struct icmp *icmp_header;
    struct icmp6_hdr *icmp6_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    connection_key_t key;
    char source_ip[INET6_ADDRSTRLEN];
    char destination_ip[INET6_ADDRSTRLEN];

    // Skip the datalink layer header and get the IP header fields.
    packetptr += header_length;

    // Determine if the packet is IPv4 or IPv6
    if (((struct ip *)packetptr)->ip_v == 4) {
        // IPv4 packet
        ip_header = (struct ip *)packetptr;
        strcpy(source_ip, inet_ntoa(ip_header->ip_src));
        strcpy(destination_ip, inet_ntoa(ip_header->ip_dst));
        strcpy(key.src_ip, source_ip);
        strcpy(key.dst_ip, destination_ip);

        // Advance to the transport layer header and parse the fields based on the protocol.
        packetptr += 4 * ip_header->ip_hl;
        switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)packetptr;
            key.src_port = ntohs(tcp_header->th_sport);
            key.dst_port = ntohs(tcp_header->th_dport);
            strcpy(key.protocol, "tcp");
            break;

        case IPPROTO_UDP:
            udp_header = (struct udphdr *)packetptr;
            key.src_port = ntohs(udp_header->uh_sport);
            key.dst_port = ntohs(udp_header->uh_dport);
            strcpy(key.protocol, "udp");
            break;

        case IPPROTO_ICMP:
            icmp_header = (struct icmp *)packetptr;
            key.src_port = 0;
            key.dst_port = 0;
            strcpy(key.protocol, "icmp");
            break;
        default:
            return;
        }
    } else if (((struct ip6_hdr *)packetptr)->ip6_vfc >> 4 == 6) {
        // IPv6 packet
        ip6_header = (struct ip6_hdr *)packetptr;
        inet_ntop(AF_INET6, &ip6_header->ip6_src, source_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, destination_ip, INET6_ADDRSTRLEN);
        strcpy(key.src_ip, source_ip);
        strcpy(key.dst_ip, destination_ip);

        packetptr += sizeof(struct ip6_hdr);
        switch (ip6_header->ip6_nxt) {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)packetptr;
            key.src_port = ntohs(tcp_header->th_sport);
            key.dst_port = ntohs(tcp_header->th_dport);
            strcpy(key.protocol, "tcp");
            break;

        case IPPROTO_UDP:
            udp_header = (struct udphdr *)packetptr;
            key.src_port = ntohs(udp_header->uh_sport);
            key.dst_port = ntohs(udp_header->uh_dport);
            strcpy(key.protocol, "udp");
            break;

        case IPPROTO_ICMPV6:
            icmp6_header = (struct icmp6_hdr *)packetptr;
            key.src_port = 0;
            key.dst_port = 0;
            strcpy(key.protocol, "icmpv6");

            break;
        default:
            return;
        }
    } else {

        return;
    }


    insert_or_update(&key, packethdr->len);
}

// Cleanup function after exiting ncurses
void stop_capture(int signo) 
{

    endwin();
    if (pcap_handle != NULL) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }

    for (int i = 0; i < HASH_SIZE; i++) {
        connection_stats_t *current = hash_table[i];
        while (current != NULL) {
            connection_stats_t *next = current->next;
            free(current);
            current = next;
        }
        hash_table[i] = NULL;
    }

    exit(0);
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    order = 'b';

    if (argc != 3 && argc != 5) {
        printf("Usage: %s -i <interface> [-s b/p]\n", argv[0]);

        exit(0);
    }
    if (strcmp(argv[1], "-i") != 0) {
        printf("Usage: %s -i <interface> [-s b/p]\n", argv[0]);
        exit(0);
    }
    if (argc == 5 && strcmp(argv[3], "-s") == 0 && argv[4] != NULL) {
        order = *argv[4];
        if (order != 'b' && order != 'p') {

            printf("Usage: %s -i <interface> [-s b/p]\n", argv[0]);

            exit(0);
        }
    }

    interface = argv[2];

    
    initscr();
    cbreak();
    noecho();
    scrollok(stdscr, TRUE);

    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);
    signal(SIGQUIT, stop_capture);

    // Create packet capture handle.
    pcap_handle = create_pcap_handle(interface);
    if (pcap_handle == NULL) {
        fprintf(stderr, "create_pcap_handle(): invalid handle\n");
        endwin();
        exit(0);
    }

    // Get the type of link layer.
    get_link_header_len(pcap_handle);
    if (header_length == 0) {
        fprintf(stderr, "get_link_header_len(): invalid header length\n");
        endwin();
        exit(0);
    }

    pthread_t display_thread;
    pthread_create(&display_thread, NULL, display_loop, NULL);

    if (pcap_loop(pcap_handle, -1, packet_handler, (u_char *)NULL) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(pcap_handle));
        endwin();
        exit(0);
    }

    return 0;
}
