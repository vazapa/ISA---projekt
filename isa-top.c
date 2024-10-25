#include "isa-top.h"
#include "hashtable.h"



#define HASH_SIZE 1024




/*
Src IP:port                 Dst IP:port             Proto          Rx               Tx
                                                                   b/s    p/s       b/s   p/s
147.229.13.210:443          147.229.14.76:61027     tcp            130.8M 62.3k     10.2M 1.8K

*/

/*
Todo

- 2 zaznamy jednoho spojeni v hashtablu zaznamenat jako jeden
- Urcit smer podle prvniho paketu
- ??????????????Kazdou sekundu vymazat hashtable, znovu ho nacist a vypocitat rychlosti??????????????
- Vymyslet jak pocitat pocet paketu za sekundu
- Vymyslet jak pocitat pocet bitu za sekundu 
- Printovat pouze 10 nejrycheljsich kazdou sekundu
- Sortovat podle paketu/bitu


*/

pcap_t* pcap_handle;
int header_length;
int packets;
char* interface = NULL;  // TODO vyresit cleaning a free
connection_stats_t *hash_table[HASH_SIZE];

void calcute_packet_persec(connection_stats_t *connection){
    time_t now = time(NULL);
    double time_difference = difftime(now,connection->update_time);

    if(time_difference > 0){

    }
}

void print_top_connections() {
    // Clear the screen and print header
    clear();
    printw("Src IP:port                 Dst IP:port             Proto          Rx               Tx\n");
    printw("                                                                   b/s    p/s       b/s   p/s\n");

    // Iterate over the hashtable and collect active connections
    connection_stats_t *top_connections[10];  // Array to store top 10 connections
    int count = 0;

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
                if(found_connection != NULL){

                    connection_stats_t merged_connection = merge(current,found_connection);
                    insert_merged(&merged_connection,hash_function(&merged_connection.key));
                    
                 //   delete(&sec_connection);
                }

            // Sort and store only top 10 connections
            if (count < 10) {
                top_connections[count++] = current;
            } else {
                // Implement sorting logic to keep only the top 10 connections
                for (int j = 0; j < 10; j++) {
                    // if (/* sorting condition, e.g., current->rx_bytes > top_connections[j]->rx_bytes */) {
                        top_connections[j] = current;
                        break;
                    // }
                }
            }
            current = current->next;
        }
    }

    // Print each of the top connections
    for (int i = 0; i < count; i++) {
        connection_stats_t *conn = top_connections[i];
        // if(conn->key.src_port == 80 || conn->key.dst_port == 80){
        if(strcmp( conn->key.src_ip,"8.8.8.8") == 0 || strcmp( conn->key.dst_ip,"8.8.8.8") == 0){ 

        printw("%s:%d          %s:%d                  %s           %lu    %lu          %lu    %lu\n",
               conn->key.src_ip, conn->key.src_port,
               conn->key.dst_ip, conn->key.dst_port,
               conn->key.protocol,
               conn->rx_bytes , conn->rx_packets,
               conn->tx_bytes , conn->tx_packets);
    }
    }
    // refresh();
}

void* display_loop(void *args) {
    while (1) {
        print_top_connections();
        refresh();
        sleep(1);
    }
    return NULL;
}


connection_stats_t merge(connection_stats_t *connection1,connection_stats_t *connection2){
    /*
    Src IP: 192.168.0.119, Src Port: 0, Dst IP: 8.8.8.8, Dst Port: 0, Protocol: icmp, Rx Bytes: 980, Rx Packets: 10, Tx Bytes: 0, Tx Packets: 0
    Src IP: 8.8.8.8, Src Port: 0, Dst IP: 192.168.0.119, Dst Port: 0, Protocol: icmp, Rx Bytes: 1078, Rx Packets: 11, Tx Bytes: 0, Tx Packets: 0
    Src IP: 192.168.0.119, Src Port: 0, Dst IP: 8.8.8.8, Dst Port: 0, Protocol: icmp, Rx Bytes: 980, Rx Packets: 10, Tx Bytes: 1078, Tx Packets: 11
    */
    
    connection_stats_t merged_connection;

    // Kopírování klíčových hodnot (src/dst IP, porty, protokol)
    strcpy(merged_connection.key.src_ip, connection1->key.src_ip);
    merged_connection.key.src_port = connection1->key.src_port;
    strcpy(merged_connection.key.dst_ip, connection1->key.dst_ip);
    merged_connection.key.dst_port = connection1->key.dst_port;
    strcpy(merged_connection.key.protocol, connection1->key.protocol);

    // Rx (přijaté) statistiky pro první spojení
    merged_connection.tx_packets = connection1->tx_packets;
    merged_connection.tx_bytes = connection1->tx_bytes;

    // Tx (odeslané) statistiky pro druhé spojení (druhá strana komunikace)
    merged_connection.rx_packets = connection2->tx_packets;  // Odpovídá přijatým z druhé strany
    merged_connection.rx_bytes = connection2->tx_bytes;      // Odpovídá přijatým bajtům z druhé strany

    
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


    // Get network interface source IP address and network_mask.
    if (pcap_lookupnet(interface, &source_ip, &network_mask, error_buffer) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", error_buffer);
        return NULL;
    }

    // Open the interface for live capture.
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

void packet_handler(u_char *user,const struct pcap_pkthdr *packethdr, const u_char *packetptr)
{
    struct ip* ip_header;
    struct icmp* icmp_header;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    char ip_header_info[256];
    char source_ip[256];
    char destination_ip[256];

    connection_key_t key;
 

    // Skip the datalink layer header and get the IP header fields.
    packetptr += header_length;
    ip_header = (struct ip*)packetptr;

    strcpy(source_ip, inet_ntoa(ip_header->ip_src));
    strcpy(destination_ip, inet_ntoa(ip_header->ip_dst));
    // sprintf(ip_header_info, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
    //         ntohs(ip_header->ip_id), ip_header->ip_tos, ip_header->ip_ttl,
    //         4*ip_header->ip_hl, ntohs(ip_header->ip_len));
    strcpy(key.src_ip, source_ip);
    strcpy(key.dst_ip, destination_ip);

    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4 * ip_header->ip_hl;
    switch (ip_header->ip_p)
    {
    case IPPROTO_TCP:
        tcp_header = (struct tcphdr*)packetptr;
        key.src_port = ntohs(tcp_header->th_sport);
        key.dst_port = ntohs(tcp_header->th_dport);
        strcpy(key.protocol, "tcp");
        // printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        // insert_or_update(&key, packethdr->len);
        break;
 
    case IPPROTO_UDP:
        udp_header = (struct udphdr *)packetptr;
        key.src_port = ntohs(udp_header->uh_sport);
        key.dst_port = ntohs(udp_header->uh_dport);
        strcpy(key.protocol, "udp");
        // insert_or_update(&key, packethdr->len);
        break;
 
    case IPPROTO_ICMP:
        icmp_header = (struct icmp*)packetptr;
        key.src_port = 0;
        key.dst_port = 0;
        strcpy(key.protocol, "icmp");
        // printf("ICMP %s -> %s\n", source_ip, destination_ip);
        // printf("%s\n", ip_header_info);
        // printf("Type:%d Code:%d ID:%d Seq:%d\n", icmp_header->icmp_type, icmp_header->icmp_code,
        //        ntohs(icmp_header->icmp_hun.ih_idseq.icd_id), ntohs(icmp_header->icmp_hun.ih_idseq.icd_seq));
        // printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        insert_or_update(&key, packethdr->len);
        break;
    }
}


void stop_capture(int signo) //TODO edit
{
    
    struct pcap_stat stats;
 
    if (pcap_stats(pcap_handle, &stats) >= 0) {
        printf("\n%d packets captured\n", packets);
        printf("%d packets received by filter\n", stats.ps_recv); 
        printf("%d packets dropped\n\n", stats.ps_drop);
    }

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
    
    endwin();
    free(interface);
    print_all_items();

    

    printf("aaaaaaaaaaaa ted fr koncim aaaaaaaaaaaa\n");


    exit(0);
}

int main(int argc, char* argv[]){
    char *interface = malloc(sizeof(char*)); // zmenit 

    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    scrollok(stdscr, TRUE);


    if (argc < 3 || argc > 3) {
        free(interface) ;
        printf("Usage: %s -i <interface>\n", argv[0]);
        exit(0);
    }
    if(strcmp(argv[1],"-i") == 0 ){
        strcpy(interface,argv[2]);
    }else{
        printf("Usage: %s -i <interface>\n", argv[0]);
        free(interface);
        
        exit(0);
    }
    
    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);
    signal(SIGQUIT, stop_capture);


    

    //Create packet capture handle.
    pcap_handle = create_pcap_handle(interface);
    if (pcap_handle == NULL) {
        fprintf(stderr, "create_pcap_handle(): invalid handle\n");
        return -1;
    }

    // Get the type of link layer.
    get_link_header_len(pcap_handle);
    if (header_length == 0) {
        fprintf(stderr, "get_link_header_len(): invalid header length\n");
        return -1;
    }
    
     // Start the ncurses display loop in a separate thread
    pthread_t display_thread;
    pthread_create(&display_thread, NULL, display_loop, NULL);

    // Start the packet capture with a set count or continually if the count is 0.
    if (pcap_loop(pcap_handle, -1, packet_handler, (u_char*)NULL) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(pcap_handle));
        return -1;
    }
    
    
    
    
    

    
    
    return 0;
}