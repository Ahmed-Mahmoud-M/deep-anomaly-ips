#include "../../include/sniffing/FlowTracker.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <unordered_map>




void FlowTracker::update_flow_statistics(FlowStatistics& stats, const NetworkPacket& packet) {
    auto now = std::chrono::system_clock::now();
    const uint32_t pkt_size = packet.ip_length;

    // Update basic statistics
    stats.total_packets++;
    stats.total_bytes += pkt_size;
    stats.total_pkt_sizes += pkt_size;
    stats.total_pkt_sizes_sq += pkt_size * pkt_size;
    stats.min_pkt_size = std::min(stats.min_pkt_size, pkt_size);
    stats.max_pkt_size = std::max(stats.max_pkt_size, pkt_size);

    // Update TCP flags if TCP packet
    if (packet.ip_protocol == PacketParser::IP_PROTOCOL_TCP) {
        if (packet.tcp_flags & 0x02) stats.syn_count++;
        if (packet.tcp_flags & 0x01) stats.fin_count++;
        if (packet.tcp_flags & 0x04) stats.rst_count++;
        if (packet.tcp_flags & 0x08) stats.psh_count++;
        if (packet.tcp_flags & 0x10) stats.ack_count++;
        if (packet.tcp_flags & 0x20) stats.urg_count++;
    }

    // Determine direction - we need to compare with the flow's src_ip
    // Since we don't have access to the key here, we'll need to modify our approach
    bool is_forward;
    if (stats.total_packets == 1) {
        // First packet determines the direction
        is_forward = true;
        stats.last_fwd_packet_time = now;
    } else {
        // Subsequent packets: compare with the first packet's direction
        // We can use the fact that forward packets will have the same src_ip
        // as the first packet in the flow
        is_forward = (packet.src_ip == stats.first_packet_src_ip);
    }

    if (is_forward) {
        if (stats.total_packets == 1) {
            stats.first_packet_src_ip = packet.src_ip;
        }
        stats.fwd_packets++;
        stats.fwd_bytes += pkt_size;
        stats.fwd_min_pkt_size = std::min(stats.fwd_min_pkt_size, pkt_size);
        stats.fwd_max_pkt_size = std::max(stats.fwd_max_pkt_size, pkt_size);

        if (stats.last_fwd_packet_time.time_since_epoch().count() > 0) {
            double iat = std::chrono::duration<double, std::micro>(now - stats.last_fwd_packet_time).count();
            stats.fwd_iat_total += iat;
            stats.fwd_iat_max = std::max(stats.fwd_iat_max, iat);
        }
        stats.last_fwd_packet_time = now;
    } else {
        stats.bwd_packets++;
        stats.bwd_bytes += pkt_size;
        stats.bwd_min_pkt_size = std::min(stats.bwd_min_pkt_size, pkt_size);
        stats.bwd_max_pkt_size = std::max(stats.bwd_max_pkt_size, pkt_size);

        if (stats.last_bwd_packet_time.time_since_epoch().count() > 0) {
            double iat = std::chrono::duration<double, std::micro>(now - stats.last_bwd_packet_time).count();
            stats.bwd_iat_total += iat;
            stats.bwd_iat_max = std::max(stats.bwd_iat_max, iat);
        }
        stats.last_bwd_packet_time = now;
    }

    // Update inter-arrival times
    if (stats.last_packet_time.time_since_epoch().count() > 0) {
        double iat = std::chrono::duration<double, std::micro>(now - stats.last_packet_time).count();
        stats.total_iat += iat;
        stats.total_iat_sq += iat * iat;
        stats.min_iat = (stats.min_iat < 0) ? iat : std::min(stats.min_iat, iat);
        stats.max_iat = std::max(stats.max_iat, iat);
        stats.flow_iat_max = std::max(stats.flow_iat_max, iat);
    }
    stats.last_packet_time = now;
}

void FlowTracker::cleanup_expired_flows() {
    auto it = active_flows_.begin();
    while (it != active_flows_.end()) {
        if (is_flow_expired(it->first, it->second)) {
            finalize_flow(it->first, it->second);
            it = active_flows_.erase(it);
        } else {
            ++it;
        }
    }
}

bool FlowTracker::is_flow_expired(const FlowKey& key, const FlowStatistics& stats) const {
    auto now = std::chrono::system_clock::now();
    
    // Inactive timeout
    auto inactive_duration = now - stats.last_packet_time;
    if (inactive_duration > inactive_timeout_) return true;
    
    // Absolute timeout
    auto total_duration = now - stats.start_time;
    if (total_duration > active_timeout_) return true;
    
    // TCP connection closed
    if (key.protocol == PacketParser::IP_PROTOCOL_TCP) {
        if (stats.fin_count >= 2 || stats.rst_count > 0) return true;
    }
    
    return false;
}

void FlowTracker::finalize_flow(const FlowKey& key, const FlowStatistics& stats) {
    completed_flows_.emplace_back(key, stats);
}

const std::unordered_map<FlowTracker::FlowKey, FlowTracker::FlowStatistics, 
                        FlowTracker::FlowKeyHash>& 
FlowTracker::get_active_flows() const {
    return active_flows_;
}

const std::vector<std::pair<FlowTracker::FlowKey, FlowTracker::FlowStatistics>>& 
FlowTracker::get_completed_flows() const {
    return completed_flows_;
}

void FlowTracker::set_timeout(std::chrono::seconds inactive_timeout,
                            std::chrono::seconds active_timeout) {
    inactive_timeout_ = inactive_timeout;
    active_timeout_ = active_timeout;
}
  
