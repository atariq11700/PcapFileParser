#pragma once
#include <iostream>
#include "mac.h"
#include "network.h"

namespace network {
    namespace protocols {
        namespace arp {
            enum class opcodes : uint16_t {
                reserved,
                Request,
                Reply,
                Request_Reserve,
                Reply_Reserve,
                DRARP_Request,
                DRARP_Reply,
                DRARP_Error,
                InARP_Request,
                InARP_Reply,
                ARP_NAK,
                MARS_Request,
                MARS_Multi,
                MARS_MServ,
                MARS_Join,
                MARS_Leave,
                MARS_NAK,
                MARS_Unserv,
                MARS_SJoin,
                MARS_SLeave,
                MARS_Grouplist_Request,
                MARS_Grouplist_Reply,
                MARS_Redirect_Map,
                MAPOS_UNARP,
                OP_EXP1,
                OP_EXP2
            };
            struct header {
                uint16_t hardware_type;
                ether_types protocol_type;
                uint8_t hardware_address_length;
                uint8_t protocol_address_length;
                opcodes opcode;
                header(uint8_t* const data);
                
                private:
                header();
            };
            struct data {
                network::mac_addr src_mac;
                network::ip_addr src_ip;
                network::mac_addr dest_mac;
                network::ip_addr dest_ip;
            };
            struct packet {
                mac::header mac_header;
                arp::header arp_header;
                arp::data arp_data;
                void print();
                packet(uint8_t* const data);

                private:
                packet();
            };
            

            const char* get_opcodes_as_string(opcodes opcode);
        }
    }
}