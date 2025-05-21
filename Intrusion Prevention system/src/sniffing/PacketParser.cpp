#include "../../include/sniffing/PacketParser.hpp"
#include <cstdint>
#include <cstdio>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>

PacketParser::PacketParser() : parse_errors(0){}



/*
These two functions manually convert 16‑ and 32‑bit values from network byte order (big‑endian) to machine’s host byte order (often little‑endian)
*/

uint16_t PacketParser::ntohs(uint16_t net_short) {
    return ((net_short << 8) & 0xFF00) | ((net_short >> 8) & 0x00FF);
}

uint32_t PacketParser::ntohl(uint32_t net_long) {
    return ((net_long << 24) & 0xFF000000) |
           ((net_long <<  8) & 0x00FF0000) |
           ((net_long >>  8) & 0x0000FF00) |
           ((net_long >> 24) & 0x000000FF);
}


std::string PacketParser::ip_to_String(uint32_t ip) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&ip,buf,INET6_ADDRSTRLEN);


    return std::string(buf);


}


std::string PacketParser::mac_to_string(const uint8_t *mac) {

    char buf[18];

    snprintf(buf, sizeof(buf),"%02x:%02x:%02x:%02x:%02x:%02x",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);


    return std::string(buf);
}


bool PacketParser::parse_ethernet(const uint8_t * data,uint32_t size,NetworkPacket& result){
    if (size < 14) return false;
    
    memcpy(result.dst_mac, data, 6);
    memcpy(result.src_mac, data + 6, 6);
    result.ether_type = ntohs(*(uint16_t*)(data + 12));
    
    return true;
}

bool PacketParser::parse_ip(const uint8_t* data, uint32_t size, NetworkPacket& result) {
    if (size < 20) return false;
    
    result.ip_version = (data[0] >> 4) & 0x0F;
    if (result.ip_version != 4) return false;
    
    result.ip_protocol = data[9];
    result.ip_length = ntohs(*(uint16_t*)(data + 2));
    result.ttl = data[8];
    result.ip_header_length = (data[0] & 0x0F) * 4;
    result.src_ip = *(uint32_t*)(data + 12);
    result.dst_ip = *(uint32_t*)(data + 16);
    
    // Parse transport layer
    uint8_t ihl = (data[0] & 0x0F) * 4;
    if (size < ihl) return false;
    
    const uint8_t* transport_data = data + ihl;
    uint32_t transport_size = size - ihl;
    
    switch (result.ip_protocol) {
        case IP_PROTOCOL_TCP:
            return parse_tcp(transport_data, transport_size, result);
        case IP_PROTOCOL_UDP:
            return parse_udp(transport_data, transport_size, result);
        default:
            return false;
    }
}

bool PacketParser::parse_tcp(const uint8_t* data, uint32_t size, NetworkPacket& result) {
    if (size < 20) return false;
    
    result.tcp_window = ntohs(*(uint16_t*)(data + 14));

    result.src_port = ntohs(*(uint16_t*)(data));
    result.dst_port = ntohs(*(uint16_t*)(data + 2));
    result.seq_num = ntohl(*(uint32_t*)(data + 4));
    result.ack_num = ntohl(*(uint32_t*)(data + 8));
    result.tcp_flags = data[13];
    result.tcp_header_length = (data[12] >> 4) * 4;
    // Get payload
    uint8_t data_offset = (data[12] >> 4) * 4;
    if (size <= data_offset) return false;
    
    result.payload_size = size - data_offset;
    if (result.payload_size > 0) {
        result.payload.assign(data + data_offset, data + size);
    }
    
    return true;
}

bool PacketParser::parse_udp(const uint8_t* data, uint32_t size, NetworkPacket& result) {
    if (size < 8) return false;
    
    result.src_port = ntohs(*(uint16_t*)(data));
    result.dst_port = ntohs(*(uint16_t*)(data + 2));
    result.udp_header_length = 8;
    // Get payload
    result.payload_size = ntohs(*(uint16_t*)(data + 4)) - 8;
    if (result.payload_size > 0 && size >= 8 + result.payload_size) {
        result.payload.assign(data + 8, data + 8 + result.payload_size);
    }
    
    return true;
}


bool PacketParser::parse_packet(const std::vector<uint8_t>& raw_packet, NetworkPacket& result) {
    if (raw_packet.empty()) return false;
    
    const uint8_t* data = raw_packet.data();
    uint32_t remaining = raw_packet.size();
    
    // Reset result
    memset(&result, 0, sizeof(NetworkPacket));
    
    // Parse Ethernet header (14 bytes)
    if (!parse_ethernet(data, remaining, result)) {
        parse_errors++;
        return false;
    }
    
    // Skip VLAN tags if present
    if (result.ether_type == 0x8100) { // VLAN tagged
        if (remaining < 18) return false;
        result.ether_type = ntohs(*(uint16_t*)(data + 16));
        data += 4;
        remaining -= 4;
    }
    
    // Parse IP layer
    if (result.ether_type == ETHERTYPE_IP) {
        if (!parse_ip(data + 14, remaining - 14, result)) {
            parse_errors++;
            return false;
        }
    } else {
        return false; 
    }
    
    return true;
}


