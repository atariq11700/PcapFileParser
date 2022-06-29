#include "mac.h"
#include "../structs.h"
#include <string.h>


void network::protocols::mac::header::print() {
    printf("\tPacket Ether II Header\n");
    printf("\t\tDest Mac Addr: %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac.one, dest_mac.two, dest_mac.three, dest_mac.four, dest_mac.five, dest_mac.six);
    printf("\t\tSrc Mac Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",  src_mac.one,  src_mac.two,  src_mac.three,  src_mac.four,  src_mac.five,  src_mac.six);
    printf("\t\tEthernet Type: %s\n", network::get_ether_types_as_string(ether_type));
}

network::protocols::mac::header::header(uint8_t* const data) {
    memcpy(this, data, sizeof(header));
    __bswap_16ptr((uint16_t*)&ether_type);
}