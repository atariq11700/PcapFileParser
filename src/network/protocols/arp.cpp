#include "arp.h"
#include <string.h>
#include "../../utils/utils.h"
#include "network.h"

const char* network::protocols::arp::get_opcodes_as_string(opcodes opcode) {
    switch (opcode) {
        case opcodes::reserved : {
            return "reserved";
        }
        case opcodes::Request : {
            return "Request";
        }
        case opcodes::Reply : {
            return "Reply";
        }
        case opcodes::Request_Reserve : {
            return "Request_Reserve";
        }
        case opcodes::Reply_Reserve : {
            return "Reply_Reserve";
        }
        case opcodes::DRARP_Request : {
            return "DRARP_Request";
        }
        case opcodes::DRARP_Reply : {
            return "DRARP_Reply";
        }
        case opcodes::DRARP_Error : {
            return "DRARP_Error";
        }
        case opcodes::InARP_Request : {
            return "InARP_Request";
        }
        case opcodes::InARP_Reply : {
            return "InARP_Reply";
        }
        case opcodes::ARP_NAK : {
            return "ARP_NAK";
        }
        case opcodes::MARS_Request : {
            return "MARS_Request";
        }
        case opcodes::MARS_Multi : {
            return "MARS_Multi";
        }
        case opcodes::MARS_MServ : {
            return "MARS_MServ";
        }
        case opcodes::MARS_Join : {
            return "MARS_Join";
        }
        case opcodes::MARS_Leave : {
            return "MARS_Leave";
        }
        case opcodes::MARS_NAK : {
            return "MARS_NAK";
        }
        case opcodes::MARS_Unserv : {
            return "MARS_Unserv";
        }
        case opcodes::MARS_SJoin : {
            return "MARS_SJoin";
        }
        case opcodes::MARS_SLeave : {
            return "MARS_SLeave";
        }
        case opcodes::MARS_Grouplist_Request : {
            return "MARS_Grouplist_Request";
        }
        case opcodes::MARS_Grouplist_Reply : {
            return "MARS_Grouplist_Reply";
        }
        case opcodes::MARS_Redirect_Map : {
            return "MARS_Redirect_Map";
        }
        case opcodes::MAPOS_UNARP : {
            return "MAPOS_UNARP";
        }
        case opcodes::OP_EXP1 : {
            return "OP_EXP1";
        }
        case opcodes::OP_EXP2 : {
            return "OP_EXP2";
        }
        default : {
            return 0;
        }
    }
}

void network::protocols::arp::packet::print() {
    printf("\tPacket Arp Header\n");
    printf("\t\tHardware Type: %d\n", (uint16_t)arp_header.hardware_type);
    printf("\t\tProtocol Type: %s\n", network::get_ether_types_as_string(arp_header.protocol_type));
    printf("\t\tHardware Address Length: %d\n", arp_header.hardware_address_length);
    printf("\t\tProtocol Address Length: %d\n", arp_header.protocol_address_length);
    printf("\t\tOpcode: %d(%s)\n", (uint16_t)arp_header.opcode, arp::get_opcodes_as_string(arp_header.opcode));
}

network::protocols::arp::header::header(uint8_t* const data) {
    memcpy(this, data, sizeof(header));
    __bswap_16ptr(&hardware_type);
    __bswap_16ptr((uint16_t*)&protocol_type);
    __bswap_16ptr((uint16_t*)&opcode);
}

network::protocols::arp::packet::packet(uint8_t* const data)
    : mac_header(data), arp_header(data + sizeof(mac::header)) {
    memcpy(&arp_data, data + sizeof(mac::header) + sizeof(header), sizeof(arp::data));
}