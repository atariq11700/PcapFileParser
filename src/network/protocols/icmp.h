#pragma once
#include <iostream>
#include "mac.h"
#include "ip.h"

namespace network {
    namespace protocols {
        namespace icmp {
            struct header {
                uint8_t type;
                uint8_t code;
                uint16_t checksum;

                void print();
                header(uint8_t* const data);

                private:
                header();

            };
            struct packet {
                mac::header mac_header;
                ip::header ip_header;
                icmp::header icmp_header;

                packet(uint8_t* const data);
                void print();

                private:
                packet();
            };
        }
    }
}