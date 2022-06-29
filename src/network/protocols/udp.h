#pragma once
#include <iostream>
#include "mac.h"
#include "ip.h"

namespace network {
    namespace protocols {
        namespace udp {
            struct header {
                uint16_t src_port;
                uint16_t dest_port;
                uint16_t length;
                uint16_t checksum;

                header(uint8_t* const data);
                void print();

                private:
                header();
            };
            struct packet {
                mac::header mac_header;
                ip::header ip_header;
                udp::header udp_header;

                void print();
                packet(uint8_t* const data);

                private:
                packet();
            };
        }
    }
}