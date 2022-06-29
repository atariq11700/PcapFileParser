#pragma once
#include <iostream>

namespace pcap {
    struct pcap_global_header {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
        pcap_global_header(){};
        pcap_global_header(uint8_t* const data);
        void print();
    };
    struct pcap_packet_header {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
        pcap_packet_header(){};
        pcap_packet_header(uint8_t* const data);
    };
}
