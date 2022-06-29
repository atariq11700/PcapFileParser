#pragma once
#include <iostream>
#include "mac.h"
#include "network.h"

namespace network {
    namespace protocols {
        namespace ip {
            enum class ip_protocols : uint8_t {
                UDP = 17,
                TCP = 6,
                ICMP = 1
            };

            const char* get_protocols_as_string(ip_protocols proto);

            struct header {
                uint8_t ihl: 4, version: 4;
                uint8_t differentiated_services;
                uint16_t total_length;
                uint16_t identification;
                uint16_t fragment_offset: 13, flags: 3;
                uint8_t ttl;
                ip_protocols protocol;
                uint16_t header_checksum;
                network::ip_addr src_ip;
                network::ip_addr dest_ip;

                header(uint8_t* const data);
                void print();

                private:
                header();
            };
            struct packet {
                mac::header mac_header;
                ip::header ip_header;

                packet(uint8_t* const data);
                void print();
                
                private:
                packet();
            };
        }
    }
}