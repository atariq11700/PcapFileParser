#include "icmp.h"
#include "../../utils/utils.h"
#include <string.h>

network::protocols::icmp::header::header(uint8_t* const data) {
    memcpy(this, data, sizeof(header));
    __bswap_16ptr(&checksum);
}

network::protocols::icmp::packet::packet(uint8_t* const data)
    : mac_header(data), ip_header(data + sizeof(mac::header)), icmp_header(data + sizeof(mac::header) + sizeof(ip::header)) {

}

void network::protocols::icmp::packet::print() {
    icmp_header.print();
}

void network::protocols::icmp::header::print() {
    printf("\tPacket ICMP Header\n");
    printf("\t\tType: %d\n", type);
    printf("\t\tCode: %d\n", code);
    printf("\t\tChecksum: 0x%04X\n", checksum);
}