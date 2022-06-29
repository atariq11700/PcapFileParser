#pragma once
#include <iostream>



namespace network {
    enum class ether_types : uint16_t {
                ARP = 0x0806,
                IPv4 = 0x0800
    };

    const char* get_ether_types_as_string(ether_types val);

    struct ip_addr {
        uint8_t one;
        uint8_t two;
        uint8_t three;
        uint8_t four;

        bool operator==(const ip_addr& other) {
            return (
                one == other.one &&
                two == other.two &&
                three == other.three &&
                four == other.four
                );
        }
    };

    struct mac_addr {
        uint8_t one;
        uint8_t two;
        uint8_t three;
        uint8_t four;
        uint8_t five;
        uint8_t six;
    };
}

