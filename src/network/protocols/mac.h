#pragma once
#include <iostream>
#include "network.h"

namespace network {
    namespace protocols {
        namespace mac {
            struct header {
                network::mac_addr dest_mac;
                network::mac_addr src_mac;
                network::ether_types ether_type;
                header(uint8_t* const data);
                void print();

                private:
                header();
            };
        }
    }
}