#pragma once
#include <iostream>
#include <vector>
#include <string.h>
#include <unordered_map>
#include "../network/structs.h"



using namespace network::protocols;
class Report {
public:
    struct Attack {
        network::ip_addr attacker_ip;
        network::ip_addr victim_ip;
        const char* file_name;
        uint64_t start_time = 0;
        uint64_t end_time = 0; 
    }; 
private:
    uint64_t m_total_packets = 0;
    uint64_t m_ip_packets = 0;
    uint64_t m_arp_packets = 0;
    uint64_t m_other_layer3_packets = 0;
    uint64_t m_tcp_packets = 0;
    uint64_t m_udp_packets = 0;
    uint64_t m_icmp_packets = 0;
    uint64_t m_other_layer4_packets = 0;
    uint64_t m_dns_packets = 0;
    uint64_t m_dhcp_packets = 0;
    uint64_t m_ntp_packets = 0;
    uint64_t m_http_packets = 0;
    uint64_t m_https_packets = 0;
    const char* m_filename;


    std::vector<tcp::packet> m_tcp_syn_packets;
    std::vector<tcp::packet> m_tcp_synack_packets;


    std::unordered_map<uint32_t, std::pair<uint64_t, uint64_t>> m_unique_ips;
    std::unordered_map<
        uint32_t, 
        std::pair<
            int, 
            std::pair<
                uint64_t, 
                uint64_t
            >
        >
    > m_syn_counts;

    std::unordered_map<
        uint32_t, 
        std::pair<
            std::unordered_map<uint16_t, uint8_t>, 
            std::pair<
                uint64_t, 
                uint64_t
            >
        >
    > m_port_counts;


    uint64_t m_succ_tcp_handshakes = 0;
    uint64_t m_bad_tcp_handshakes = 0;

    uint64_t m_fin_bit = 0;
    uint64_t m_rst_bit = 0;


    Attack port_scan_attack;
    Attack syn_flood_attack;

    void log_ip_addr(network::ip_addr addr, int data_size_bytes);
    void log_ip_port(network::ip_addr addr_src, network::ip_addr addr_dest, uint16_t port, uint64_t ts);

public:

    void log_packet(network::protocols::ip::packet packet);
    void log_packet(network::protocols::arp::packet packet);
    void log_packet(network::protocols::tcp::packet packet, uint64_t ts);
    void log_packet(network::protocols::udp::packet packet, uint64_t ts);
    void log_packet(network::protocols::icmp::packet packet, uint64_t ts);
    void l3_log_other_packet(network::protocols::mac::header header);
    void l4_log_other_packet(network::protocols::ip::packet header);
    void notify_eof();
    void update_current_filename(const char* filename);


    std::string to_string();
    void print();


};