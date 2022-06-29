#pragma once
#include <iostream>
#include "mac.h"
#include "ip.h"

namespace network {
    namespace protocols {
        namespace tcp {
            struct header {
                uint16_t src_port;
                uint16_t dest_port;
                uint32_t sequence_number;
                uint32_t ack_number;
                // ecn lowest bit       reserved      data offset    control bits    highest -> 2nd highest ecn bit
                // 1                     000          1111            111111          11
                // uint16_t data_offset : 4, reserved :3, ecn: 3, control_bits: 6;
                uint16_t control_bits: 6, ecn: 3, reserved: 3, data_offset: 4;
                uint16_t window;
                uint16_t checksum;
                uint16_t urgent_ptr;

                header(uint8_t* const data);
                void print();

                private:
                header();
            };
            struct packet {
                mac::header mac_header;
                ip::header ip_header;
                tcp::header tcp_header;

                packet(uint8_t* const data);
                void print();
                bool operator==(const packet& other);

                private:
                packet();
            };
            enum class control_bits : uint8_t {
                URG = 0b100000,
                ACK = 0b010000,
                PSH = 0b001000,
                RST = 0b000100,
                SYN = 0b000010,
                FIN = 0b000001,
            };
            const char* get_control_bits_as_string(control_bits val, std::string& str);
        }
    }
}