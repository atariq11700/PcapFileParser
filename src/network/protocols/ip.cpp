#include "ip.h"
#include <string.h>
#include "network.h"
#include "../../utils/utils.h"
#include <bitset>

network::protocols::ip::header::header(uint8_t* const data) {
    memcpy(this, data, sizeof(header));

    __bswap_16ptr(&identification + 1);
    __bswap_16ptr(&total_length);
    __bswap_16ptr(&identification);
    __bswap_16ptr(&header_checksum);
}

void network::protocols::ip::header::print() {
    printf("\tPacket IP Header\n");
    printf("\t\tVersion: %d\n", version);
    printf("\t\tIHL: %d\n", ihl);
    printf("\t\tDifferentiated Services: 0x%0X\n", differentiated_services);
    printf("\t\tTotal Length: %d\n", total_length);
    printf("\t\tIdentification: 0x%04X\n", identification);
    const char* cFlags = std::bitset<3>(flags).to_string().c_str();
    // printf("\t\t        _ _ _ \n\t\tFlags: |%c|%c|%c|\n\t\t        - - - \n",cFlags[0], cFlags[1], cFlags[2]);
    printf("\t\tFlags: %s\n",cFlags);
    printf("\t\tFragment Offset: %d\n", fragment_offset);
    printf("\t\tTTL: %d\n", ttl);
    printf("\t\tProtocol: %d(%s)\n", protocol, get_protocols_as_string(protocol));
    printf("\t\tHeader Checksum: 0x%04X\n", header_checksum);
    printf("\t\tSource IP: %d.%d.%d.%d\n",src_ip.one, src_ip.two,src_ip.three,src_ip.four);
    printf("\t\tDest IP: %d.%d.%d.%d\n",dest_ip.one, dest_ip.two,dest_ip.three,dest_ip.four);

}

network::protocols::ip::packet::packet(uint8_t* const data)
    : mac_header(data), ip_header(data + sizeof(mac::header)) {
}

void network::protocols::ip::packet::print() {
    ip_header.print();
}

const char* network::protocols::ip::get_protocols_as_string(ip_protocols proto) {
    switch (proto) {
        case ip_protocols::UDP: {
            return "UDP";
        }
        case ip_protocols::TCP: {
            return "TCP";
        }
        case ip_protocols::ICMP: {
            return "ICMP";
        }
        default: {
            return "";
        }
    }
}