#pragma  once



/*

purpose of that class to --> track networks flow like sequences of packets between two endpoints

FLowKey struct --> used as a unique identifiter for each flow using five tuples (src_ip,dst_ip,src_port,dst_port , protocol)


FlowKeyHash struct >> hash function for FLowkey to use as a key in the unordereed_map 


FLowStats --> track the statistics for a single flow 


*/

#pragma once

#include "PacketParser.hpp"
#include <chrono>
#include <cstdint>
#include <unordered_map>
#include <vector>

class FlowTracker {
public:
    struct FlowKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;

        bool operator==(const FlowKey& other) const;
    };

    struct FlowKeyHash {
        std::size_t operator()(const FlowKey& key) const;
    };

    struct FlowStatistics {
         uint32_t first_packet_src_ip = 0;
        // Timestamps
        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point last_packet_time;
        std::chrono::system_clock::time_point last_fwd_packet_time;
        std::chrono::system_clock::time_point last_bwd_packet_time;

        // Basic counts
        uint32_t total_packets = 0;
        uint64_t total_bytes = 0;
        uint64_t total_pkt_sizes = 0;
        uint64_t total_pkt_sizes_sq = 0;

        // Packet size extremes
        uint32_t min_pkt_size = UINT32_MAX;
        uint32_t max_pkt_size = 0;
        uint32_t fwd_min_pkt_size = UINT32_MAX;
        uint32_t fwd_max_pkt_size = 0;
        uint32_t bwd_min_pkt_size = UINT32_MAX;
        uint32_t bwd_max_pkt_size = 0;

        // TCP flags
        uint32_t syn_count = 0;
        uint32_t fin_count = 0;
        uint32_t rst_count = 0;
        uint32_t psh_count = 0;
        uint32_t ack_count = 0;
        uint32_t urg_count = 0;

        // Timing statistics
        double min_iat = -1.0;
        double max_iat = -1.0;
        double total_iat = 0.0;
        double total_iat_sq = 0.0;
        double fwd_iat_total = 0.0;
        double bwd_iat_total = 0.0;
        double flow_iat_max = 0.0;
        double fwd_iat_max = 0.0;
        double bwd_iat_max = 0.0;

        // Directional tracking
        uint32_t fwd_packets = 0;
        uint64_t fwd_bytes = 0;
        uint32_t bwd_packets = 0;
        uint64_t bwd_bytes = 0;

        // Advanced metrics
        uint32_t fwd_header_len = 0;
        uint32_t bwd_header_len = 0;
        uint32_t subflow_fwd_bytes = 0;
        uint32_t subflow_bwd_bytes = 0;
        uint32_t init_win_bytes_fwd = 0;
        uint32_t init_win_bytes_bwd = 0;
        uint32_t act_data_pkt_fwd = 0;
        uint32_t min_seg_size_fwd = 0;

        // Timing accumulators
        double idle_time_total = 0.0;
        double active_time_total = 0.0;
        uint32_t idle_count = 0;
        uint32_t active_count = 0;
    };

    explicit FlowTracker(
        std::chrono::seconds inactive_timeout = std::chrono::seconds(60),
        std::chrono::seconds active_timeout = std::chrono::seconds(300)
    );

    void process_packet(const NetworkPacket& packet);
    void cleanup_expired_flows();

    const std::unordered_map<FlowKey, FlowStatistics, FlowKeyHash>& get_active_flows() const;
    const std::vector<std::pair<FlowKey, FlowStatistics>>& get_completed_flows() const;

    void set_timeout(
        std::chrono::seconds inactive_timeout,
        std::chrono::seconds active_timeout
    );

private:
    std::chrono::seconds active_timeout_;
    std::chrono::seconds inactive_timeout_;
    
    std::unordered_map<FlowKey, FlowStatistics, FlowKeyHash> active_flows_;
    std::vector<std::pair<FlowKey, FlowStatistics>> completed_flows_;

    bool is_flow_expired(const FlowKey& key, const FlowStatistics& stats) const;
    void update_flow_statistics(FlowStatistics& stats, const NetworkPacket& packet);
    void finalize_flow(const FlowKey& key, const FlowStatistics& stats);
};