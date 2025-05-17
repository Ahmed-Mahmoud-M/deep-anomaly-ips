#include "Intrusion Prevention system/src/sniffing/PacketCapture.cpp"
#include "Intrusion Prevention system/src/sniffing/PacketParser.cpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>




void display_packet_details(const NetworkPacket& packet) {
    // Display basic information
    std::cout << "\n=== Packet Details ===" << std::endl;
    std::cout << "Source:      " << PacketParser::ip_to_String(packet.src_ip) 
              << ":" << packet.src_port << std::endl;
    std::cout << "Destination: " << PacketParser::ip_to_String(packet.dst_ip) 
              << ":" << packet.dst_port << std::endl;
    
    // Display protocol information
    std::cout << "Protocol:    ";
    switch(packet.ip_protocol) {
        case PacketParser::IP_PROTOCOL_TCP:
            std::cout << "TCP";
            break;
        case PacketParser::IP_PROTOCOL_UDP:
            std::cout << "UDP";
            break;
        default:
            std::cout << "Unknown (" << (int)packet.ip_protocol << ")";
    }
    std::cout << std::endl;
    
    // Display TCP flags if applicable
    if(packet.ip_protocol == PacketParser::IP_PROTOCOL_TCP) {
        std::cout << "TCP Flags:   [";
        if(packet.tcp_flags & 0x01) std::cout << "FIN ";
        if(packet.tcp_flags & 0x02) std::cout << "SYN ";
        if(packet.tcp_flags & 0x04) std::cout << "RST ";
        if(packet.tcp_flags & 0x08) std::cout << "PSH ";
        if(packet.tcp_flags & 0x10) std::cout << "ACK ";
        if(packet.tcp_flags & 0x20) std::cout << "URG ";
        std::cout << "]" << std::endl;
    }
    
    // Display packet size
    std::cout << "Packet Size: " << packet.ip_length << " bytes" << std::endl;
    
    // Display payload information
    if(!packet.payload.empty()) {
        std::cout << "Payload:     " << packet.payload_size << " bytes" << std::endl;
        
        // Display first few bytes of payload in hex
        std::cout << "First 16 bytes: ";
        for(size_t i = 0; i < std::min((size_t)16, packet.payload.size()); i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << (int)packet.payload[i] << " ";
        }
        std::cout << std::dec << std::endl;
    }
    
    std::cout << "=====================" << std::endl;
}

int main() {

    PacketCapture capture;

    capture.set_interface("eth0");
    capture.set_filiter("tcp");
    capture.start_capture();


    while (true) {
        capture.process_next_packet();
        if (capture.has_packets()) {
            NetworkPacket packet;
            PacketParser parser;

            if(parser.parse_packet(capture.get_current_packet(),packet)) {
                 display_packet_details(packet);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}