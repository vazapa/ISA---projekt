#include "isa-top.h"
#include "hashtable.h"



#define HASH_SIZE 1024

#define SRC_IP_PORT_WIDTH 45
#define DST_IP_PORT_WIDTH 55
#define PROTO_WIDTH 10
#define RX_WIDTH 15
#define TX_WIDTH 15
#define SPEED_WIDTH 8  
#define PKT_WIDTH 6    

#define KILO 1000ULL
#define MEGA (KILO * 1000ULL)
#define GIGA (MEGA * 1000ULL)
/*
Todo
- Sortovat podle paketu/bitu todo kontrola
- Merge funkce spojuje spatne!!!!!!!!! 2 ruzne pingy na google a 8.8.8.8 a zacne si to zrat navzajem
- TODO - 14 zmizet
- todo opravit aby to nebylo moc stejne jak sniffer nekoho jineho (Similar code found with 1 license type - View matches)

*/
pcap_t* pcap_handle;
int header_length;
int packets;

connection_stats_t *hash_table[HASH_SIZE];
char order;


void format_packet_count(uint64_t packets, char *buffer, size_t buffer_size) {
    if (packets >= KILO) {
        double formatted = packets / (double)KILO;
        if (formatted >= 100) {
            snprintf(buffer, buffer_size, "%.1fK", formatted);
        } else if (formatted >= 10) {
            snprintf(buffer, buffer_size, "%.1fK", formatted);
        } else {
            snprintf(buffer, buffer_size, "%.1fK", formatted);
        }
    } else {
        snprintf(buffer, buffer_size, "%.0f", (double)packets);
    }
}

void format_network_speed(uint64_t speed, char *buffer, size_t buffer_size) {
    double formatted_speed;
    const char *unit;

    if (speed >= GIGA) {
        formatted_speed = speed / (double)GIGA;
        unit = "G";
    } else if (speed >= MEGA) {
        formatted_speed = speed / (double)MEGA;
        unit = "M";
    } else if (speed >= KILO) {
        formatted_speed = speed / (double)KILO;
        unit = "K";
    } else {
        formatted_speed = speed;
        unit = " ";
    }

    if(formatted_speed == 0){
        snprintf(buffer, buffer_size, "0");
    }
    else if(speed < KILO){
        snprintf(buffer, buffer_size, "%.0f", formatted_speed);
    } 
    else {
        snprintf(buffer, buffer_size, "%.1f%s", formatted_speed, unit);
    }
}


void update_speed(connection_stats_t *conn) {
    time_t now = time(NULL);
    double time_difference = difftime(now, conn->update_time);

    // Update speeds
    conn->rx_speed = ((conn->rx_bytes)) / (time_difference + 1);
    
    
    conn->tx_speed = ((conn->tx_bytes)) / (time_difference + 1);
    
    
    conn->rx_packet_speed = conn->rx_packets / (time_difference + 1);
    conn->tx_packet_speed = conn->tx_packets / (time_difference + 1);

    // If there's activity, update last_active timestamp
    if (conn->rx_bytes > 0 || conn->tx_bytes > 0 || 
        conn->rx_packets > 0 || conn->tx_packets > 0) {
        conn->last_active = now;
    }

    // Reset counters
    conn->rx_bytes = 0;
    conn->tx_bytes = 0;
    conn->tx_packets = 0;
    conn->rx_packets = 0;
    conn->update_time = now;
}


int compare(const void *a, const void *b) {
    connection_stats_t *conn_a = *((connection_stats_t**)a);
    connection_stats_t *conn_b = *((connection_stats_t**)b);



    if(order == 'b'){
        if(conn_a->tx_speed > conn_a->rx_speed){
            if (conn_a->tx_speed < conn_b->tx_speed) return 1;
            if (conn_a->tx_speed > conn_b->tx_speed) return -1;
        }
        else{
            if (conn_a->rx_speed < conn_b->rx_speed) return 1;
            if (conn_a->rx_speed > conn_b->rx_speed) return -1;
        }
    }
    else{
        if(conn_a->tx_packet_speed > conn_a->rx_packet_speed){
            if (conn_a->tx_packet_speed < conn_b->tx_packet_speed) return 1;
            if (conn_a->tx_packet_speed > conn_b->tx_packet_speed) return -1;
        }
        else{
            if (conn_a->rx_packet_speed < conn_b->rx_packet_speed) return 1;
            if (conn_a->rx_packet_speed > conn_b->rx_packet_speed) return -1;
        }
    }
    return 0;
}

void format_ip_port(char* protocol,const char *ip, uint16_t port, char *buffer, size_t buffer_size) {
    if (strchr(ip, ':') != NULL) { // IPv6 address
        if(strcmp(protocol,"icmpv6") == 0){
            snprintf(buffer, buffer_size, "[%s]", ip);
        }else{
            snprintf(buffer, buffer_size, "[%s]:%d", ip, port);
        }
    } 
    else { 
        if(strcmp(protocol,"icmp") == 0){
            snprintf(buffer, buffer_size, "%s", ip);
        }else{
            snprintf(buffer, buffer_size, "%s:%d", ip, port);
            }
    }
}

void print_top_connections() {
    
    clear();
    
    printw("%-*s %-*s %-*s %*s %*s %*s %*s\n",
       SRC_IP_PORT_WIDTH, "Src IP:port",
       DST_IP_PORT_WIDTH, "Dst IP:port",
       PROTO_WIDTH, "Proto",
       SPEED_WIDTH, "Rx b/s",
       PKT_WIDTH, "p/s",
       SPEED_WIDTH, "Tx b/s",
       PKT_WIDTH, "p/s");

    // Iterate over the hashtable and collect active connections
    //connection_stats_t *top_connections[10];  // Array to store top 10 connections
    connection_stats_t *top_connections[HASH_SIZE * 10];  // Assuming max 10 connections per bucket

    int count = 0;

    for (int i = 0; i < HASH_SIZE; i++) {
        connection_stats_t *current = hash_table[i];
        while (current != NULL) {
            connection_stats_t merged_connection;

            connection_key_t sec_connection;
            strcpy(sec_connection.src_ip,current->key.dst_ip);
            sec_connection.src_port = current->key.dst_port;
            strcpy(sec_connection.dst_ip,current->key.src_ip);
            sec_connection.dst_port = current->key.src_port;
            strcpy(sec_connection.protocol,current->key.protocol);

            connection_stats_t *found_connection = find(&sec_connection);
                if(found_connection != NULL){

                    
                    if(strcmp(current->key.src_ip,sec_connection.src_ip) != 0){ // neni localhost 
                        merged_connection = merge(current,found_connection,false);
                        delete(&sec_connection);
                    }else{
                        merged_connection = merge(current,current,true);
                    }
                    insert_merged(&merged_connection,hash_function(&merged_connection.key));
                }
            update_speed(current);
            // Sort and store only top 10 connections
            
            if (count < 10) {
                top_connections[count++] = current;
            } else {

                int min_idx = 0;
                uint64_t min_traffic = top_connections[0]->rx_speed + top_connections[0]->tx_speed;

                for (int j = 1; j < 10; j++) {
                    uint64_t traffic = top_connections[j]->rx_speed + top_connections[j]->tx_speed;
                    if (traffic < min_traffic) {
                        min_idx = j;
                        min_traffic = traffic;
                    }
                }

                // Replace if current has more traffic
                uint64_t current_traffic = current->rx_speed + current->tx_speed;
                if (current_traffic > min_traffic) {
                    top_connections[min_idx] = current;
                }













                // // Implement sorting logic to keep only the top 10 connections
                // for (int j = 0; j < 10; j++) {
                //     // if (current->tx_bytes > top_connections[j]->tx_bytes) {
                //         top_connections[j] = current;
                //         break;
                //     // }
                // }
            }
            current = current->next;
        }
    }

    
    qsort(top_connections, count, sizeof(connection_stats_t*), compare);


    // Print each of the top connections
    for (int i = 0; i < count ; i++) {
        connection_stats_t *conn = top_connections[i];
        
        time_t now = time(NULL);
        char src_ip_port[SRC_IP_PORT_WIDTH];
        char dst_ip_port[DST_IP_PORT_WIDTH];
        char rx_speed_str[8];
        char tx_speed_str[8];


        
        snprintf(src_ip_port, SRC_IP_PORT_WIDTH, "%s:%d", 
                conn->key.src_ip, conn->key.src_port);
        snprintf(dst_ip_port, DST_IP_PORT_WIDTH, "%s:%d", 
                conn->key.dst_ip, conn->key.dst_port);
        
        format_network_speed(conn->rx_speed, rx_speed_str, sizeof(rx_speed_str));
        format_network_speed(conn->tx_speed, tx_speed_str, sizeof(tx_speed_str));

        char rx_pkt_str[8];
        char tx_pkt_str[8];
        format_packet_count(conn->rx_packet_speed, rx_pkt_str, sizeof(rx_pkt_str));
        format_packet_count(conn->tx_packet_speed, tx_pkt_str, sizeof(tx_pkt_str));

        format_ip_port(conn->key.protocol,conn->key.src_ip, conn->key.src_port, src_ip_port, SRC_IP_PORT_WIDTH);
        format_ip_port(conn->key.protocol,conn->key.dst_ip, conn->key.dst_port, dst_ip_port, DST_IP_PORT_WIDTH);
        
        if ((conn->rx_speed != 0 || conn->tx_speed != 0) || 
            (difftime(now, conn->last_active) < 2.0)) {
        
            if(strcmp(conn->key.protocol,"icmp") == 0 ){
                printw("%-*s %-*s %-*s %*s %*s %*s %*s\n",
                    SRC_IP_PORT_WIDTH, conn->key.src_ip,
                    DST_IP_PORT_WIDTH, conn->key.dst_ip,
                    PROTO_WIDTH, conn->key.protocol,
                    SPEED_WIDTH, rx_speed_str,
                    PKT_WIDTH, rx_pkt_str,
                    SPEED_WIDTH, tx_speed_str,
                    PKT_WIDTH, tx_pkt_str);
            }else{
                printw("%-*s %-*s %-*s %*s %*s %*s %*s\n",
                    SRC_IP_PORT_WIDTH, src_ip_port,
                    DST_IP_PORT_WIDTH, dst_ip_port,
                    PROTO_WIDTH, conn->key.protocol,
                    SPEED_WIDTH, rx_speed_str,
                    PKT_WIDTH, rx_pkt_str,
                    SPEED_WIDTH, tx_speed_str,
                    PKT_WIDTH, tx_pkt_str);
            }
        }
    }
    
}

void* display_loop(void *args) {
    
    while (1) {
        print_top_connections();
        refresh();
        sleep(1);
    }
    return NULL;
}


connection_stats_t merge(connection_stats_t *connection1,connection_stats_t *connection2, bool same_addrs){
    
    
    connection_stats_t merged_connection;

    // Kopírování klíčových hodnot (src/dst IP, porty, protokol)
    strcpy(merged_connection.key.src_ip, connection1->key.src_ip);
    merged_connection.key.src_port = connection1->key.src_port;
    strcpy(merged_connection.key.dst_ip, connection1->key.dst_ip);
    merged_connection.key.dst_port = connection1->key.dst_port;
    strcpy(merged_connection.key.protocol, connection1->key.protocol);

    
    

    
    if(same_addrs){
        merged_connection.tx_packets = connection1->tx_packets / 2;
        merged_connection.tx_bytes = connection1->tx_bytes / 2;
        merged_connection.rx_packets = connection1->tx_packets / 2;  
        merged_connection.rx_bytes = connection1->tx_bytes / 2;      
    }else{
        merged_connection.tx_packets = connection1->tx_packets;
        merged_connection.tx_bytes = connection1->tx_bytes;
        merged_connection.rx_packets = connection2->tx_packets;  
        merged_connection.rx_bytes = connection2->tx_bytes;      
    }

    merged_connection.update_time = connection1->update_time;
    merged_connection.last_active = connection1->last_active;

    
    return merged_connection;
}

pcap_t* create_pcap_handle(char* interface) // TODO edit
{
    pcap_t *created_handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 network_mask;
    bpf_u_int32 source_ip;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char filter[] = "";
    //char filter[] = "icmp or icmp6";
    


    // Get network interface source IP address and network_mask.
    if (pcap_lookupnet(interface, &source_ip, &network_mask, error_buffer) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", error_buffer);
        return NULL;
    }

    // Open the interface for live capture.
    // created_handle = pcap_open_live(interface, BUFSIZ, 1, 0, error_buffer);
    created_handle = pcap_open_live(interface, BUFSIZ, 1, 1000, error_buffer);
    if (created_handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", error_buffer);
        return NULL;
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(created_handle, &bpf, filter, 1, network_mask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(created_handle));
        return NULL;
    }

    // Bind the packet filter to the libpcap created_handle.    
    if (pcap_setfilter(created_handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(created_handle));
        return NULL;
    }

    return created_handle;
}

void get_link_header_len(pcap_t* handle) // TODO edit
{
    int link_type;
 
    // Determine the datalink layer type.
    if ((link_type = pcap_datalink(handle)) == PCAP_ERROR) {
        printf("pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
 
    // Set the datalink layer header size.
    switch (link_type)
    {
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
        printf("Unsupported datalink (%d)\n", link_type);
        header_length = 0;
    }
}


void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {

    struct ip* ip_header;
    struct ip6_hdr* ip6_header;
    struct icmp* icmp_header;
    struct icmp6_hdr* icmp6_header;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    connection_key_t key;
    char source_ip[INET6_ADDRSTRLEN];
    char destination_ip[INET6_ADDRSTRLEN];

    // Skip the datalink layer header and get the IP header fields.
    packetptr += header_length;

    // Determine if the packet is IPv4 or IPv6
    if (((struct ip*)packetptr)->ip_v == 4) {
        // IPv4 packet
        ip_header = (struct ip*)packetptr;
        strcpy(source_ip, inet_ntoa(ip_header->ip_src));
        strcpy(destination_ip, inet_ntoa(ip_header->ip_dst));
        strcpy(key.src_ip, source_ip);
        strcpy(key.dst_ip, destination_ip);

        // Advance to the transport layer header and parse the fields based on the protocol.
        packetptr += 4 * ip_header->ip_hl;
        switch (ip_header->ip_p) {
            case IPPROTO_TCP:
                tcp_header = (struct tcphdr*)packetptr;
                key.src_port = ntohs(tcp_header->th_sport);
                key.dst_port = ntohs(tcp_header->th_dport);
                strcpy(key.protocol, "tcp");
                break;

            case IPPROTO_UDP:
                udp_header = (struct udphdr*)packetptr;
                key.src_port = ntohs(udp_header->uh_sport);
                key.dst_port = ntohs(udp_header->uh_dport);
                strcpy(key.protocol, "udp");
                break;

            case IPPROTO_ICMP:
                icmp_header = (struct icmp*)packetptr;
                key.src_port = 0;
                key.dst_port = 0;
                strcpy(key.protocol, "icmp");
                break;

            default:
                // Unsupported protocol, return without updating the hash table.
                return;
        }
    } else if (((struct ip6_hdr*)packetptr)->ip6_vfc >> 4 == 6) {
        // IPv6 packet
        ip6_header = (struct ip6_hdr*)packetptr;
        inet_ntop(AF_INET6, &ip6_header->ip6_src, source_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, destination_ip, INET6_ADDRSTRLEN);
        strcpy(key.src_ip, source_ip);
        strcpy(key.dst_ip, destination_ip);

        // Advance to the transport layer header and parse the fields based on the protocol.
        packetptr += sizeof(struct ip6_hdr);
        switch (ip6_header->ip6_nxt) {
            case IPPROTO_TCP:
                tcp_header = (struct tcphdr*)packetptr;
                key.src_port = ntohs(tcp_header->th_sport);
                key.dst_port = ntohs(tcp_header->th_dport);
                strcpy(key.protocol, "tcp");
                break;

            case IPPROTO_UDP:
                udp_header = (struct udphdr*)packetptr;
                key.src_port = ntohs(udp_header->uh_sport);
                key.dst_port = ntohs(udp_header->uh_dport);
                strcpy(key.protocol, "udp");
                break;

            case IPPROTO_ICMPV6:
                icmp6_header = (struct icmp6_hdr*)packetptr;
                key.src_port = 0;
                key.dst_port = 0;
                strcpy(key.protocol, "icmpv6");
                
                
                break;

            default:
                // Unsupported protocol, return without updating the hash table.
                return;
        }
    } else {
        // Unsupported IP version, return without updating the hash table.
        return;
    }

    // Update the hash table with the packet length.
    insert_or_update(&key, packethdr->len);
}




void stop_capture(int signo) //TODO edit
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
    
    
    // free(interface);
    // free(order);
    //print_all_items();

    

    printf("aaaaaaaaaaaa ted fr koncim aaaaaaaaaaaa\n");


    exit(0);
}

int main(int argc, char* argv[]){
    char* interface = NULL;  
    // order = malloc(2);  
    // stpcpy(order,"b");
    order = 'b';

    

    if (argc != 3 && argc != 5) {
        //free(interface) ;
        printf("Usage: %s -i <interface> [-s b/p]\n", argv[0]);
        
        exit(0);
    }
    if(strcmp(argv[1],"-i") != 0 ){
        printf("Usage: %s -i <interface> [-s b/p]\n", argv[0]);
        exit(0);
    }
    if(argc == 5 && strcmp(argv[3], "-s") == 0 && argv[4] != NULL){    
        order = *argv[4];
        if(order != 'b' && order !='p'){
        
            printf("Usage: %s -i <interface> [-s b/p]\n", argv[0]);
            
            
            exit(0);
        }
            
    }
    
    interface = argv[2];
    
    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    scrollok(stdscr, TRUE);
    
    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);
    signal(SIGQUIT, stop_capture);


    

    //Create packet capture handle.
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
    
     // Start the ncurses display loop in a separate thread
    pthread_t display_thread;
    pthread_create(&display_thread, NULL, display_loop, NULL);

    // Start the packet capture with a set count or continually if the count is 0.
    if (pcap_loop(pcap_handle, -1, packet_handler, (u_char*)NULL) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(pcap_handle));
        endwin();
        exit(0);
    }
    
    return 0;
}
