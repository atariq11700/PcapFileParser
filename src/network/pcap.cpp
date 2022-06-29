#include "pcap.h"
#include <string.h>

void pcap::pcap_global_header::print() {
    printf("Pcap Version: %d.%d\n", version_major, version_minor);
    printf("Time Zone: %d\n", thiszone);
    printf("Sig Figs: %d\n", sigfigs);
    printf("Snap Length: %d\n", snaplen);
    printf("Network Type: %d\n", network);
}

pcap::pcap_global_header::pcap_global_header(uint8_t* const data) {
    memcpy(this, data, sizeof(pcap_global_header));
}

pcap::pcap_packet_header::pcap_packet_header(uint8_t* const data) {
    memcpy(this, data, sizeof(pcap_packet_header));
}