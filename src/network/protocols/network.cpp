#include "network.h"



const char* network::get_ether_types_as_string(ether_types val) {
    switch (val) {
        case ether_types::ARP : {
            return "ARP";
        }
        case ether_types::IPv4 : {
            return "IPv4";
        }
        default : {
            return 0;
        }
    }

} 
