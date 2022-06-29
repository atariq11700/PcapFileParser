#include "udp.h"
#include "../../utils/utils.h"
#include <string.h>


network::protocols::udp::header::header(uint8_t* const data) {
    memcpy(this, data, sizeof(header));

    __bswap_16ptr(&src_port);
    __bswap_16ptr(&dest_port);
    __bswap_16ptr(&length);
    __bswap_16ptr(&checksum);

}

network::protocols::udp::packet::packet(uint8_t* const data)
    : mac_header(data), ip_header(data + sizeof(mac::header)), udp_header(data + sizeof(mac::header) + sizeof(ip::header)) {
    
}


void network::protocols::udp::packet::print() {
    udp_header.print();
}

void network::protocols::udp::header::print() {
    printf("\tPacket UDP Header\n");
    printf("\t\tSrc Port: %d\n", src_port);
    printf("\t\tDest port: %d\n", dest_port);
    printf("\t\tLength: %d\n", length);
    printf("\t\tChecksum: 0x%04X\n", checksum);
}