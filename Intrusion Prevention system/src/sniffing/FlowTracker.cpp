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



void FlowTracker::update_flow_statistics(const FlowKey& key, FlowStatistics& stats, const NetworkPacket& packet) {
    // Packet size stats
    stats.min_pkt_size = std::min(stats.min_pkt_size, packet.ip_length);
    stats.max_pkt_size = std::max(stats.max_pkt_size, packet.ip_length);
    stats.total_pkt_sizes += packet.ip_length;
    stats.pkt_len_sq_sum += packet.ip_length * packet.ip_length;

    // TCP flag counts
    if (packet.ip_protocol == PacketParser::IP_PROTOCOL_TCP) {
        if (packet.tcp_flags & 0x02) stats.syn_count++;
        if (packet.tcp_flags & 0x01) stats.fin_count++;
        if (packet.tcp_flags & 0x04) stats.rst_count++;
        if (packet.tcp_flags & 0x08) stats.psh_count++;
        if (packet.tcp_flags & 0x10) stats.ack_count++;
    }

    auto now = std::chrono::system_clock::now();
    bool is_forward = (packet.src_ip == key.src_ip);

    // Update direction-specific statistics
    if (is_forward) {
        stats.fwd_packets++;
        stats.fwd_pkt_len_total += packet.ip_length;
        stats.fwd_pkt_len_sq_sum += packet.ip_length * packet.ip_length;
        stats.total_fwd_header_len += packet.ip_header_length;

        if (packet.ip_protocol == PacketParser::IP_PROTOCOL_TCP) {
            stats.fwd_seg_size_total += packet.payload_size;
            stats.fwd_win_bytes_total += packet.tcp_window;
            if (packet.payload_size > 0) {
                stats.act_data_pkt_fwd++;
                stats.min_seg_size_fwd = std::min(stats.min_seg_size_fwd, packet.payload_size);
            }
            if (stats.fwd_packets == 1) {
                stats.init_win_fwd = packet.tcp_window;
            }
        }

        // Forward IAT calculations
        if (stats.fwd_packets > 1) {
            double fwd_iat = std::chrono::duration<double>(now - stats.last_fwd_time).count();
            stats.fwd_total_iat += fwd_iat;
            stats.fwd_iat_sq_sum += fwd_iat * fwd_iat;
            if (fwd_iat > stats.fwd_max_iat) stats.fwd_max_iat = fwd_iat;
            if (stats.fwd_packets == 2 || fwd_iat < stats.fwd_min_iat) {
                stats.fwd_min_iat = fwd_iat;
            }
        }
        stats.last_fwd_time = now;
    } else {
        stats.bwd_packets++;
        stats.bwd_pkt_len_total += packet.ip_length;
        stats.bwd_pkt_len_sq_sum += packet.ip_length * packet.ip_length;
        stats.total_bwd_header_len += packet.ip_header_length;

        if (packet.ip_protocol == PacketParser::IP_PROTOCOL_TCP) {
            stats.bwd_seg_size_total += packet.payload_size;
            stats.bwd_win_bytes_total += packet.tcp_window;
            if (stats.bwd_packets == 1) {
                stats.init_win_bwd = packet.tcp_window;
            }
        }

        // Backward IAT calculations
        if (stats.bwd_packets > 1) {
            double bwd_iat = std::chrono::duration<double>(now - stats.last_bwd_time).count();
            stats.bwd_total_iat += bwd_iat;
            stats.bwd_iat_sq_sum += bwd_iat * bwd_iat;
            if (bwd_iat > stats.bwd_max_iat) stats.bwd_max_iat = bwd_iat;
            if (stats.bwd_packets == 2 || bwd_iat < stats.bwd_min_iat) {
                stats.bwd_min_iat = bwd_iat;
            }
        }
        stats.last_bwd_time = now;
    }

    // Flow-level IAT calculations
    if (stats.total_packets > 0) {
        double iat = std::chrono::duration<double>(now - stats.last_packet_time).count();
        if (stats.min_iat < 0 || iat < stats.min_iat) stats.min_iat = iat;
        if (iat > stats.max_iat) stats.max_iat = iat;
        stats.total_iat += iat;
    }

    stats.last_packet_time = now;
    stats.total_packets++;
    stats.total_bytes += packet.ip_length;
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

    
    update_flow_statistics(key, flow, packet);
}


const std::unordered_map<FlowTracker::FlowKey, FlowTracker::FlowStatistics, 
                        FlowTracker::FlowKeyHash>& 
FlowTracker::get_active_flows() const {
    return active_flows;
}
