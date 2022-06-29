#include <iostream>
#include <string.h>
#include "network/structs.h"
#include "log/report.h"

using namespace network::protocols;

int main(int argc, const char** argv, const char** envp) {
    Report* report = new Report();
    // report.print();

    for (int i = 1; i < argc; i++) {
        report->update_current_filename(argv[i]);
        FILE* fp = fopen(argv[i], "rb");
        if (fp == NULL) {
            printf("Unable to open file %s\n", argv[i]);
            exit(1);
        } else {
            printf("[%d/%d] : Scanning file %s\n",i ,argc - 1, argv[i]);
        }
        fseek(fp, 0, SEEK_SET); 
        
        pcap::pcap_global_header global_header;
        fread(&global_header, sizeof(global_header), 1, fp);
        // global_header.print();

        int packet_id = 1;
        pcap::pcap_packet_header packet_header;
        uint8_t* packet_buffer;

        while (1) {
            // if (packet_id % 5000 == 0) {
            //     printf("Packet Counter: %d\n", packet_id);
            // }


            fread(&packet_header, sizeof(packet_header), 1, fp);

            if (packet_id == 1){
                packet_buffer = (uint8_t*)malloc(packet_header.incl_len);
            } else {
                packet_buffer = (uint8_t*)realloc((void*)packet_buffer, packet_header.incl_len);
            }

            size_t bytes_read = fread(packet_buffer, 1, packet_header.incl_len, fp);
            if (bytes_read != packet_header.incl_len){
                break;
            }

            // printf("Packet #%d\n", packet_id);
            // printf("\tUNIX Time: %d.%06d\n", packet_header.ts_sec, packet_header.ts_usec);
            // printf("\tBytes Captured/Actual: %d/%d\n", packet_header.incl_len, packet_header.orig_len);

            mac::header mac_header(packet_buffer);
            // mac_header.print();

            if (mac_header.ether_type == network::ether_types::ARP) {
                arp::packet packet(packet_buffer);
                // packet.print();
                report->log_packet(packet);

            } else if (mac_header.ether_type == network::ether_types::IPv4) {
                ip::packet ip_packet(packet_buffer);
                // ip_packet.print();
                report->log_packet(ip_packet);

                if (ip_packet.ip_header.protocol == ip::ip_protocols::TCP) {
                    tcp::packet tcp_packet(packet_buffer);
                    // tcp_packet.print();
                    report->log_packet(tcp_packet, packet_header.ts_sec);
                    
                } else if (ip_packet.ip_header.protocol == ip::ip_protocols::UDP){
                    udp::packet udp_packet(packet_buffer);
                    // udp_packet.print();
                    report->log_packet(udp_packet, packet_header.ts_sec);
                } else if (ip_packet.ip_header.protocol == ip::ip_protocols::ICMP) {
                    icmp::packet icmp_packet(packet_buffer);
                    // icmp_packet.print();
                    report->log_packet(icmp_packet, packet_header.ts_sec);
                } else {
                    report->l4_log_other_packet(ip_packet);
                }

            } else {
                report->l3_log_other_packet(mac_header);
            }


            packet_id++;
        }


        free(packet_buffer);
        fclose(fp);
        report->notify_eof();
    }
    report->print();
    delete report;

}