#include "report.h"
#include <algorithm>

#ifdef linux
#include <sys/time.h>
#endif

#ifndef linux
#include "time.h"
#endif

using namespace network::protocols;

#define MAX_INT_CHARS 10

//?Layer 3
void Report::log_packet(ip::packet packet) {
    m_ip_packets++;
    m_total_packets++;
}
void Report::log_packet(arp::packet packet){
    m_arp_packets++;
    m_total_packets++;
}
void Report::l3_log_other_packet(mac::header header) {
    m_other_layer3_packets++;
    m_total_packets++;
}

//?Layer 4
void Report::log_packet(tcp::packet packet, uint64_t ts){
    log_ip_port(packet.ip_header.src_ip, packet.ip_header.dest_ip, packet.tcp_header.dest_port, ts);
    m_tcp_packets++;
    if (packet.tcp_header.dest_port == 53 || packet.tcp_header.src_port == 53) {
        m_dns_packets++;
    } else if (packet.tcp_header.dest_port == 67 || packet.tcp_header.src_port == 67) {
        m_dhcp_packets++;
    } else if (packet.tcp_header.dest_port == 123 || packet.tcp_header.src_port == 123){
        m_ntp_packets++;
    } else if (packet.tcp_header.dest_port == 80 || packet.tcp_header.src_port == 80){
        m_http_packets++;
    } else if (packet.tcp_header.dest_port == 443 || packet.tcp_header.src_port == 443){
        m_https_packets++;
    }

    log_ip_addr(packet.ip_header.src_ip, packet.ip_header.total_length - sizeof(ip::header) - sizeof(tcp::header)); 
    

    if (packet.tcp_header.control_bits & (uint8_t)tcp::control_bits::FIN){
        m_fin_bit++;
    }

    if (packet.tcp_header.control_bits & (uint8_t)tcp::control_bits::RST) {
        m_rst_bit++;
    }

    if (packet.tcp_header.control_bits == (uint8_t)tcp::control_bits::SYN) { //syn packet
        m_tcp_syn_packets.emplace_back(packet);
        
        if (m_syn_counts.find(*(uint32_t*)&(packet.ip_header.src_ip)) != m_syn_counts.end()) {
            std::pair<int, std::pair<uint64_t, uint64_t>>& val = m_syn_counts.at(*(uint32_t*)&(packet.ip_header.src_ip));
            if (ts - val.second.second >= 30) { //two minutes since last syn packet
                m_syn_counts.erase(*(uint32_t*)&(packet.ip_header.src_ip));
                if (syn_flood_attack.start_time != 0) {
                    syn_flood_attack.end_time = ts;
                }
            } else if (val.first > 100) { //consider syn attack
                syn_flood_attack.attacker_ip = packet.ip_header.src_ip;
                syn_flood_attack.victim_ip = packet.ip_header.dest_ip;
                syn_flood_attack.start_time = val.second.first;
                syn_flood_attack.file_name = m_filename;
                m_syn_counts.erase(*(uint32_t*)&(packet.ip_header.src_ip));
            } 
            val.first += 1;
            val.second.second = ts;
        
        } else {
            m_syn_counts.insert({*(uint32_t*)&(packet.ip_header.src_ip), { 1 , {ts, ts}}});
        }
    }

    if (packet.tcp_header.control_bits == ((uint8_t)tcp::control_bits::SYN | (uint8_t)tcp::control_bits::ACK) ){ //synack packet
        std::vector<tcp::packet>::iterator itrPacket = std::find_if(m_tcp_syn_packets.begin(), m_tcp_syn_packets.end(), [&](tcp::packet pack){
            return 
                pack.ip_header.src_ip == packet.ip_header.dest_ip && 
                pack.ip_header.dest_ip == packet.ip_header.src_ip &&
                pack.tcp_header.src_port == packet.tcp_header.dest_port &&
                pack.tcp_header.dest_port == packet.tcp_header.src_port;
        });

        if (itrPacket != m_tcp_syn_packets.end()) {
            m_tcp_synack_packets.emplace_back(packet);
            do {
                m_tcp_syn_packets.erase(itrPacket);
                itrPacket = std::find_if(m_tcp_syn_packets.begin(), m_tcp_syn_packets.end(), [&](tcp::packet pack){
                    return 
                        pack.ip_header.src_ip == packet.ip_header.dest_ip && 
                        pack.ip_header.dest_ip == packet.ip_header.src_ip &&
                        pack.tcp_header.src_port == packet.tcp_header.dest_port &&
                        pack.tcp_header.dest_port == packet.tcp_header.src_port;
                });
            } while (itrPacket != m_tcp_syn_packets.end());
        }
    }

    if (packet.tcp_header.control_bits == (uint16_t)tcp::control_bits::ACK ) { //ack packet
        std::vector<tcp::packet>::iterator itrPacket = std::find_if(m_tcp_synack_packets.begin(), m_tcp_synack_packets.end(), [&](tcp::packet pack){
            return 
                pack.ip_header.src_ip == packet.ip_header.dest_ip && 
                pack.ip_header.dest_ip == packet.ip_header.src_ip &&
                pack.tcp_header.src_port == packet.tcp_header.dest_port &&
                pack.tcp_header.dest_port == packet.tcp_header.src_port;
        });

        if (itrPacket != m_tcp_synack_packets.end()) {
            m_succ_tcp_handshakes++;
            do {
                m_tcp_synack_packets.erase(itrPacket);
                itrPacket = std::find_if(m_tcp_synack_packets.begin(), m_tcp_synack_packets.end(), [&](tcp::packet pack){
                    return 
                        pack.ip_header.src_ip == packet.ip_header.dest_ip && 
                        pack.ip_header.dest_ip == packet.ip_header.src_ip &&
                        pack.tcp_header.src_port == packet.tcp_header.dest_port &&
                        pack.tcp_header.dest_port == packet.tcp_header.src_port;
                });
            } while (itrPacket != m_tcp_synack_packets.end());
        }
    }
}


void Report::notify_eof() {
    m_bad_tcp_handshakes += m_tcp_syn_packets.size();
    m_bad_tcp_handshakes += m_tcp_synack_packets.size();
    // printf("Syn vector size %u\n", m_tcp_syn_packets.size());
    m_tcp_syn_packets.clear();
    m_tcp_synack_packets.clear();
}

void Report::log_packet(udp::packet packet, uint64_t ts){
    log_ip_port(packet.ip_header.src_ip, packet.ip_header.dest_ip, packet.udp_header.dest_port, ts);
    m_udp_packets++;
    if (packet.udp_header.dest_port == 53 || packet.udp_header.src_port == 53) {
        m_dns_packets++;
    } else if (packet.udp_header.dest_port == 67 || packet.udp_header.src_port == 67) {
        m_dhcp_packets++;
    } else if (packet.udp_header.dest_port == 123 || packet.udp_header.src_port == 123){
        m_ntp_packets++;
    } else if (packet.udp_header.dest_port == 80 || packet.udp_header.src_port == 80){
        m_http_packets++;
    } else if (packet.udp_header.dest_port == 443 || packet.udp_header.src_port == 443){
        m_https_packets++;
    }
    log_ip_addr(packet.ip_header.src_ip, packet.ip_header.total_length - sizeof(ip::header) - sizeof(udp::header));    
}
void Report::log_packet(icmp::packet packet, uint64_t ts){
    m_icmp_packets++;
    log_ip_addr(packet.ip_header.src_ip, packet.ip_header.total_length - sizeof(ip::header) - sizeof(icmp::header));  
}
void Report::l4_log_other_packet(ip::packet packet) {
    m_other_layer4_packets++;
}

void Report::print() {
    FILE* output_file = fopen("output.txt", "w");

    printf(
        "Total Packets: %u\n\nLayer 3 Info\n\tTotal IP Packets: %u\n\tTotal ARP Packets: %u\n\tOther Layer 3 Packets: %u\n\nLayer 4 Info\n\tTotal TCP Packets: %u\n\tSuccessful TCP Handshakes: %u\n\tBad TCP Handshakes: %u\n\tTotal UDP Packets: %u\n\tTotal ICMP Packets: %u\n\tOther Layer 4 Packets: %u\n\nLayer 5-7 Info\n\tTotal DNS Packets: %u\n\tTotal DHCP Packets: %u\n\tTotal NTP Packets: %u\n\tTotal HTTP Packets: %u\n\tTotal HTTPS Packets: %u\n",
        m_total_packets,
        m_ip_packets,
        m_arp_packets,
        m_other_layer3_packets,
        m_tcp_packets,
        m_succ_tcp_handshakes,
        m_bad_tcp_handshakes,
        m_udp_packets,
        m_icmp_packets,
        m_other_layer4_packets,
        m_dns_packets,
        m_dhcp_packets,
        m_ntp_packets,
        m_http_packets,
        m_https_packets
    );
    fprintf(output_file, "Total Packets: %u\n\nLayer 3 Info\n\tTotal IP Packets: %u\n\tTotal ARP Packets: %u\n\tOther Layer 3 Packets: %u\n\nLayer 4 Info\n\tTotal TCP Packets: %u\n\tSuccessful TCP Handshakes: %u\n\tBad TCP Handshakes: %u\n\tTotal UDP Packets: %u\n\tTotal ICMP Packets: %u\n\tOther Layer 4 Packets: %u\n\nLayer 5-7 Info\n\tTotal DNS Packets: %u\n\tTotal DHCP Packets: %u\n\tTotal NTP Packets: %u\n\tTotal HTTP Packets: %u\n\tTotal HTTPS Packets: %u\n\n",
        m_total_packets,
        m_ip_packets,
        m_arp_packets,
        m_other_layer3_packets,
        m_tcp_packets,
        m_succ_tcp_handshakes,
        m_bad_tcp_handshakes,
        m_udp_packets,
        m_icmp_packets,
        m_other_layer4_packets,
        m_dns_packets,
        m_dhcp_packets,
        m_ntp_packets,
        m_http_packets,
        m_https_packets
    );

    printf("Unique IP's\n");
    fprintf(output_file, "Unique IP's\n");
    std::unordered_map<uint32_t, std::pair<uint64_t, uint64_t>>::iterator itr = m_unique_ips.begin();
    while (itr != m_unique_ips.end()) {
        network::ip_addr addr = *(network::ip_addr*)&(itr->first);
        printf("\t%d.%d.%d.%d sent %d packets totalling %d layer 5-7 bytes.\n", 
            addr.one,
            addr.two,
            addr.three,
            addr.four,
            (*itr).second.first,
            (*itr).second.second
        );
        fprintf(output_file, "\t%d.%d.%d.%d sent %d packets totalling %d layer 5-7 bytes.\n", 
            addr.one,
            addr.two,
            addr.three,
            addr.four,
            (*itr).second.first,
            (*itr).second.second
        );
        itr++;
    }

    printf("SYN Flood Attack\n");
    printf("\tFound in file: %s\n", syn_flood_attack.file_name);
    printf("\tAttacker IP: %d.%d.%d.%d\n", 
        syn_flood_attack.attacker_ip.one,
        syn_flood_attack.attacker_ip.two,
        syn_flood_attack.attacker_ip.three,
        syn_flood_attack.attacker_ip.four
    );
    printf("\tVictim IP: %d.%d.%d.%d\n", 
        syn_flood_attack.victim_ip.one,
        syn_flood_attack.victim_ip.two,
        syn_flood_attack.victim_ip.three,
        syn_flood_attack.victim_ip.four
    );
    printf("\tStart time in unix time: %d\n", syn_flood_attack.start_time);
    printf("\tEnd time in unix time: %d\n", syn_flood_attack.end_time);
    fprintf(output_file, "SYN Flood Attack\n");
    fprintf(output_file, "\tFound in file: %s\n", syn_flood_attack.file_name);
    fprintf(output_file, "\tAttacker IP: %d.%d.%d.%d\n", 
        syn_flood_attack.attacker_ip.one,
        syn_flood_attack.attacker_ip.two,
        syn_flood_attack.attacker_ip.three,
        syn_flood_attack.attacker_ip.four
    );
    fprintf(output_file, "\tVictim IP: %d.%d.%d.%d\n", 
        syn_flood_attack.victim_ip.one,
        syn_flood_attack.victim_ip.two,
        syn_flood_attack.victim_ip.three,
        syn_flood_attack.victim_ip.four
    );
    fprintf(output_file, "\tStart time in unix time: %d\n", syn_flood_attack.start_time);
    fprintf(output_file, "\tEnd time in unix time: %d\n", syn_flood_attack.end_time);

    printf("Port Scan Attack\n");
    printf("\tFound in file: %s\n", port_scan_attack.file_name);
    printf("\tAttacker IP: %d.%d.%d.%d\n", 
        port_scan_attack.attacker_ip.one,
        port_scan_attack.attacker_ip.two,
        port_scan_attack.attacker_ip.three,
        port_scan_attack.attacker_ip.four
    );
    printf("\tVictim IP: %d.%d.%d.%d\n", 
        port_scan_attack.victim_ip.one,
        port_scan_attack.victim_ip.two,
        port_scan_attack.victim_ip.three,
        port_scan_attack.victim_ip.four
    );
    printf("\tStart time in unix time: %d\n", port_scan_attack.start_time);
    printf("\tEnd time in unix time: %d\n", port_scan_attack.end_time);
    fprintf(output_file, "Port Scan Attack\n");
    fprintf(output_file, "\tFound in file: %s\n", port_scan_attack.file_name);
    fprintf(output_file, "\tAttacker IP: %d.%d.%d.%d\n", 
        port_scan_attack.attacker_ip.one,
        port_scan_attack.attacker_ip.two,
        port_scan_attack.attacker_ip.three,
        port_scan_attack.attacker_ip.four
    );
    fprintf(output_file, "\tVictim IP: %d.%d.%d.%d\n", 
        port_scan_attack.victim_ip.one,
        port_scan_attack.victim_ip.two,
        port_scan_attack.victim_ip.three,
        port_scan_attack.victim_ip.four
    );
    fprintf(output_file, "\tStart time in unix time: %d\n", port_scan_attack.start_time);
    fprintf(output_file, "\tEnd time in unix time: %d\n", port_scan_attack.end_time);

    fclose(output_file);
}  

void Report::log_ip_addr(network::ip_addr addr, int data_size_bytes) {
    if (m_unique_ips.find(*(uint32_t*)&addr) != m_unique_ips.end()) {
        std::pair<uint64_t, uint64_t>& val = m_unique_ips.at(*(uint32_t*)&addr);
        val.first += 1;
        val.second += data_size_bytes;
    } else {
        m_unique_ips.insert({*(uint32_t*)&addr, {1, data_size_bytes}});
    }
}

void Report::update_current_filename(const char* filename) {
    m_filename = filename;
}

void Report::log_ip_port(network::ip_addr addr_src, network::ip_addr addr_dest, uint16_t port, uint64_t ts) {
    if (m_port_counts.find(*(uint32_t*)&addr_src) != m_port_counts.end()) {
        std::pair<std::unordered_map<uint16_t, uint8_t>, std::pair<uint64_t, uint64_t>>& val = m_port_counts.at(*(uint32_t*)&addr_src);

        if (val.first.find(port) == val.first.end()) {
            val.first.insert({port, 1});
        }
        // if (std::find(val.first.begin(), val.first.end(), port) == val.first.end()) {
        //     val.first.emplace_back(port);
        // }

        if (ts - val.second.second > 4) {
            m_port_counts.erase(*(uint32_t*)&addr_src);
            if (port_scan_attack.start_time != 0) {
                port_scan_attack.end_time = ts;
            }
        } else if (val.first.size() > 20000) {
            port_scan_attack.file_name = m_filename;
            port_scan_attack.attacker_ip = addr_src;
            port_scan_attack.victim_ip = addr_dest;
            port_scan_attack.start_time = val.second.first;
        }
        val.second.second = ts;

    } else {
        m_port_counts.insert({*(uint32_t*)&addr_src, {std::unordered_map<uint16_t, uint8_t>(), {ts, ts}}});
    }
}