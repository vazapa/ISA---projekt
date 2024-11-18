/*
* Name: Vaclav Zapletal
* Login: xzaple40
*/
#include "utils.h"

// Changes units 
void format_p_count(uint64_t packets, char *buffer, size_t buffer_size) {
    if (packets >= KILO) {
        double formatted = packets / (double)KILO;
        snprintf(buffer, buffer_size, "%.1fK", formatted);
    } else {
        snprintf(buffer, buffer_size, "%lu", packets);
    }
}

// Changes units 
void format_b_speed(uint64_t speed, char *buffer, size_t buffer_size) {
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

    if (formatted_speed == 0) {
        snprintf(buffer, buffer_size, "0");
    } else if (speed < KILO) {
        snprintf(buffer, buffer_size, "%.0f", formatted_speed);
    } else {
        snprintf(buffer, buffer_size, "%.1f%s", formatted_speed, unit);
    }
}

//Format connection string for ipv4 or ipv6
void format_ip_port(char *protocol, const char *ip, uint16_t port, char *buffer,
                    size_t buffer_size) {
    if (strchr(ip, ':') != NULL) { 
        if (strcmp(protocol, "icmpv6") == 0) {
            snprintf(buffer, buffer_size, "[%s]", ip);
        } else {
            snprintf(buffer, buffer_size, "[%s]:%d", ip, port);
        }
    } else {
        if (strcmp(protocol, "icmp") == 0) {
            snprintf(buffer, buffer_size, "%s", ip);
        } else {
            snprintf(buffer, buffer_size, "%s:%d", ip, port);
        }
    }
}