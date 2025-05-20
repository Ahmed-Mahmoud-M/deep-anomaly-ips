#include "../../include/sniffing/FlowTracker.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <unordered_map>


// flow equailty operator
bool FlowTracker::FlowKey::operator==(const FlowKey& other) const {

    return src_ip == other.src_ip &&
     dst_ip == other.dst_ip &&
     src_port == other.src_port &&
     dst_port == other.dst_port &&
     protocol == other.protocol;
}


// FLowkey hash implementation 

size_t FlowTracker::FlowKeyHash::operator()(const FlowKey &key) const{
    return std::hash<uint32_t>()(key.src_ip)^
    std::hash<uint32_t>()(key.dst_ip) ^
    std::hash<uint32_t>()(key.src_port) ^
    std::hash<uint32_t>()(key.dst_port) ^
    std::hash<uint32_t>()(key.protocol);
}

// constructor 
FlowTracker::FlowTracker(std::chrono::seconds inactive_timeout, std::chrono::seconds active_timeout): inactive_timeout(inactive_timeout),active_timeout(active_timeout) {}





/*
void FlowTracker::update_flow_stats(FlowStats& stats, const NetworkPacket& packet)

is responsible for updating various statistics for a specific flow every time a new packet is observed that belongs to that flow

This function gets called by process_packet(...) every time a packet arrives, to keep those stats updated.


*/



void FlowTracker::update_flow_statistics(FlowStatistics &stats,const NetworkPacket & packet) {
    // packet size stats

    // Packet size stats
    stats.min_pkt_size = std::min(stats.min_pkt_size, packet.ip_length);
    stats.max_pkt_size = std::max(stats.max_pkt_size, packet.ip_length);
    stats.total_pkt_sizes += packet.ip_length;

    
    // TCP flag counts
    if (packet.ip_protocol == PacketParser::IP_PROTOCOL_TCP) {
        if (packet.tcp_flags & 0x02) stats.syn_count++;
        if (packet.tcp_flags & 0x01) stats.fin_count++;
        if (packet.tcp_flags & 0x04) stats.rst_count++;
        if (packet.tcp_flags & 0x08) stats.psh_count++;
        if (packet.tcp_flags & 0x10) stats.ack_count++;
    }

    // Inter-arrival time (CICIDS2017 feature)
    auto now = std::chrono::system_clock::now();
    if (stats.total_packets > 0) {
        double iat = std::chrono::duration<double>(now - stats.last_packet_time).count();
        if (stats.min_iat < 0 || iat < stats.min_iat) stats.min_iat = iat;
        if (iat > stats.max_iat) stats.max_iat = iat;
        stats.total_iat += iat;
    }


    

  
}


void FlowTracker::cleanup_expired_flows() {
    auto now = std::chrono::system_clock::now();
    auto it = active_flows.begin();
    
    while (it != active_flows.end()) {
        if (is_flow_expired(it->first, it->second)) {
            finalize_flow(it->first);
            it = active_flows.erase(it);
        } else {
            ++it;
        }
    }
}

bool FlowTracker::is_flow_expired(const FlowKey& key, const FlowStatistics& stats) const {
    auto now = std::chrono::system_clock::now();
    
    // Inactive timeout
    auto inactive_duration = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats.last_packet_time);
    if (inactive_duration > inactive_timeout) return true;
    
    // Absolute timeout
    auto total_duration = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats.start_time);
    if (total_duration > active_timeout) return true;
    
    // TCP connection closed
    if (key.protocol == PacketParser::IP_PROTOCOL_TCP) {
        if (stats.fin_count >= 2 || stats.rst_count > 0) return true;
    }
    
    return false;
}


// Finalize completed flow
void FlowTracker::finalize_flow(const FlowKey& key) {
    completed_flows.push_back(key);
}


// Main packet processing
void FlowTracker::process_packet(const NetworkPacket& packet) {
    FlowKey key{
        .src_ip = packet.src_ip,
        .dst_ip = packet.dst_ip,
        .src_port = packet.src_port,
        .dst_port = packet.dst_port,
        .protocol = packet.ip_protocol
    };

    auto now = std::chrono::system_clock::now();
    
    // Get or create flow
    auto& flow = active_flows[key];
    if (flow.total_packets == 0) {
        flow.start_time = now;
    }
    flow.last_packet_time = now;

    // Update statistics
    update_flow_statistics(flow, packet);
    flow.total_packets++;
    flow.total_bytes += packet.ip_length;

    // Check flow direction (CICIDS2017 feature)
    bool is_forward = (packet.src_ip == key.src_ip);
    if (is_forward) {
        flow.fwd_packets++;
    } else {
        flow.bwd_packets++;
    }
}


const std::unordered_map<FlowTracker::FlowKey, FlowTracker::FlowStatistics, 
                        FlowTracker::FlowKeyHash>& 
FlowTracker::get_active_flows() const {
    return active_flows;
}
