#include "tcp.h"
#include <bitset>
#include <string.h>
#include "../../utils/utils.h"
#include "mac.h"
#include "ip.h"

const std::string& get_control_bits_as_string_helper(network::protocols::tcp::control_bits val, std::string& str) {
    using namespace network::protocols::tcp;


    // printf("val: %s\n", std::bitset<6>((uint8_t)val).to_string().c_str());

    if ((uint8_t)val == 0) {
        return str;
    }

    if ((uint8_t)val & (uint8_t)control_bits::URG) {
        return get_control_bits_as_string_helper((control_bits)((uint8_t)val ^ (uint8_t)control_bits::URG), str += "URG ");
    }
    else if ((uint8_t)val & (uint8_t)control_bits::ACK) {
        return get_control_bits_as_string_helper((control_bits)((uint8_t)val ^ (uint8_t)control_bits::ACK), str += "ACK ");
    }
    else if ((uint8_t)val & (uint8_t)control_bits::PSH) {
        return get_control_bits_as_string_helper((control_bits)((uint8_t)val ^ (uint8_t)control_bits::PSH), str += "PSH ");
    }
    else if ((uint8_t)val & (uint8_t)control_bits::RST) {
        return get_control_bits_as_string_helper((control_bits)((uint8_t)val ^ (uint8_t)control_bits::RST), str += "RST ");
    }
    else if ((uint8_t)val & (uint8_t)control_bits::SYN) {
        return get_control_bits_as_string_helper((control_bits)((uint8_t)val ^ (uint8_t)control_bits::SYN), str += "SYN ");
    }
    else if ((uint8_t)val & (uint8_t)control_bits::FIN) {
        return get_control_bits_as_string_helper((control_bits)((uint8_t)val ^ (uint8_t)control_bits::FIN), str += "FIN ");
    } else {
        return str;
    }
}

const char* network::protocols::tcp::get_control_bits_as_string(control_bits val, std::string& str) {
    get_control_bits_as_string_helper(val, str);
    return str.c_str();
}


network::protocols::tcp::header::header(uint8_t* const data) {
    memcpy(this, data, sizeof(header));

    __bswap_16ptr(&src_port);
    __bswap_16ptr(&dest_port);
    __bswap_32ptr(&sequence_number);
    __bswap_32ptr(&ack_number);
    __bswap_16ptr((uint16_t*)(&ack_number + 1)); //bitfields address
    __bswap_16ptr(&window);
    __bswap_16ptr(&checksum);
    __bswap_16ptr(&urgent_ptr);
}

network::protocols::tcp::packet::packet(uint8_t* const data)
    : mac_header(data), ip_header(data + sizeof(mac::header)), tcp_header(data + sizeof(mac::header) + sizeof(ip::header)) 
    {}

void network::protocols::tcp::header::print() {
    printf("\tPacket TCP Header\n");
    printf("\t\tSrc port: %d\n", src_port);
    printf("\t\tDest port: %d\n", dest_port);
    printf("\t\tSequence Number: %u\n", sequence_number);
    printf("\t\tAck Number: %u\n", ack_number);
    printf("\t\tData Offset: 0x%01X\n", data_offset);
    printf("\t\tReserved: %s\n", std::bitset<3>(reserved).to_string().c_str());
    printf("\t\tEcn: %s\n", std::bitset<3>(ecn).to_string().c_str());
    printf("\t\tControl Bits: %s\n", std::bitset<6>(control_bits).to_string().c_str());
    std::string str;
    printf("\t\tControl Bits String: %s\n", get_control_bits_as_string((tcp::control_bits)control_bits, str));
    printf("\t\tWindow: %d\n", window);
    printf("\t\tChecksum: 0x%04X\n", checksum);
    printf("\t\tUrg ptr: %d\n", urgent_ptr);
}

void network::protocols::tcp::packet::print() {
    tcp_header.print();
}
