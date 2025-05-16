#pragma  once 


#include <cstdint>
#include <map>
#include <string>
#include <vector>
struct NetworkPacket {

    // Ethernet header

    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ether_type;


    // IP layer

    uint8_t ip_version;
    uint8_t ip_protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t ip_length;
    uint8_t ttl;


    // Transport layer

    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t tcp_flags;


    // payload 

    std::vector<uint8_t>payload;
    uint16_t payload_size;

};


class PacketParser{
    public:
        PacketParser();

        // Main parsing function 

        bool parse_packet(const std::vector<uint8_t>&raw_packet,NetworkPacket&result);

        // Individual layer parser

    bool parse_ethernet(const uint8_t* data, uint32_t size, NetworkPacket& result);

    bool parse_ip(const uint8_t* data, uint32_t size, NetworkPacket& result);
    bool parse_tcp(const uint8_t* data, uint32_t size, NetworkPacket& result);
    bool parse_udp(const uint8_t* data, uint32_t size, NetworkPacket& result);



        // utils functions

        static std::string ip_to_String(uint32_t ip);
        static std::string mac_to_string(const uint8_t mac[6]);
        static uint16_t ntohs(uint16_t net_short);
        static uint32_t ntohl(uint32_t net_long);
    private:

    static const uint16_t ETHERTYPE_IP = 0x0800;
    static const uint16_t ETHERTYPE_IPV6 = 0x86DD;
    static const uint8_t IP_PROTOCOL_TCP = 6;
    static const uint8_t IP_PROTOCOL_UDP = 17;


    // State tracking
    uint32_t parse_errors;
    std::map<uint8_t, uint32_t> protocol_counts;





};