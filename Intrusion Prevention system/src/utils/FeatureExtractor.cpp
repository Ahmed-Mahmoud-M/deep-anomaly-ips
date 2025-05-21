#include "../../include/utils/FeatureExtractor.hpp"
#include <cmath> 

FeatureExtractor::Features FeatureExtractor::extract(const FlowTracker::FlowKey& key,
                                                   const FlowTracker::FlowStatistics& stats) const {
    Features features{};
    double duration = std::chrono::duration<double>(
        stats.last_packet_time - stats.start_time).count();

    // Basic Flow Identification
    features.dst_port = key.dst_port;

    // Packet Size Statistics
    features.min_pkt_len = stats.min_pkt_size;
    features.max_pkt_len = stats.max_pkt_size;
    if (stats.total_packets > 0) {
        features.pkt_len_mean = static_cast<double>(stats.total_pkt_sizes) / stats.total_packets;
        features.pkt_len_std = sqrt(
            (static_cast<double>(stats.pkt_len_sq_sum) / stats.total_packets) - 
            pow(features.pkt_len_mean, 2));
        features.pkt_len_var = pow(features.pkt_len_std, 2);
    }

    // Forward Direction Features
    if (stats.fwd_packets > 0) {
        features.tot_len_fwd_pkts = stats.fwd_pkt_len_total;
        features.fwd_pkt_len_mean = static_cast<double>(stats.fwd_pkt_len_total) / stats.fwd_packets;
        features.fwd_pkt_len_std = sqrt(
            (static_cast<double>(stats.fwd_pkt_len_sq_sum) / stats.fwd_packets) - 
            pow(features.fwd_pkt_len_mean, 2));
        
        if (key.protocol == PacketParser::IP_PROTOCOL_TCP) {
            features.avg_fwd_seg_size = static_cast<double>(stats.fwd_seg_size_total) / stats.fwd_packets;
            features.init_win_bytes_fwd = stats.init_win_fwd;
            features.act_data_pkt_fwd = stats.act_data_pkt_fwd;
            features.min_seg_size_fwd = stats.min_seg_size_fwd;
        }
    }

    // Backward Direction Features
    if (stats.bwd_packets > 0) {
        features.bwd_pkt_len_mean = static_cast<double>(stats.bwd_pkt_len_total) / stats.bwd_packets;
        features.bwd_pkt_len_std = sqrt(
            (static_cast<double>(stats.bwd_pkt_len_sq_sum) / stats.bwd_packets) - 
            pow(features.bwd_pkt_len_mean, 2));
        
        if (key.protocol == PacketParser::IP_PROTOCOL_TCP) {
            features.avg_bwd_seg_size = static_cast<double>(stats.bwd_seg_size_total) / stats.bwd_packets;
            features.init_win_bytes_bwd = stats.init_win_bwd;
        }
    }

    // Timing Features
    if (duration > 0) {
        features.flow_bytes_s = stats.total_bytes / duration;
        features.flow_pkts_s = stats.total_packets / duration;
        
        if (stats.total_packets > 1) {
            features.flow_iat_mean = stats.total_iat / (stats.total_packets - 1);
            features.flow_iat_std = sqrt(
                (stats.total_iat * stats.total_iat / (stats.total_packets - 1)) - 
                pow(features.flow_iat_mean, 2));
            features.flow_iat_min = stats.min_iat;
            features.flow_iat_max = stats.max_iat;
        }
        
        if (stats.fwd_packets > 1) {
            features.fwd_iat_mean = stats.fwd_total_iat / (stats.fwd_packets - 1);
            features.fwd_iat_std = sqrt(
                (stats.fwd_iat_sq_sum / (stats.fwd_packets - 1)) - 
                pow(features.fwd_iat_mean, 2));
            features.fwd_iat_min = stats.fwd_min_iat;
            features.fwd_iat_max = stats.fwd_max_iat;
        }
        
        if (stats.bwd_packets > 1) {
            features.bwd_iat_mean = stats.bwd_total_iat / (stats.bwd_packets - 1);
            features.bwd_iat_std = sqrt(
                (stats.bwd_iat_sq_sum / (stats.bwd_packets - 1)) - 
                pow(features.bwd_iat_mean, 2));
            features.bwd_iat_min = stats.bwd_min_iat;
            features.bwd_iat_max = stats.bwd_max_iat;
        }
    }

    // TCP Flags
    features.fwd_psh_flags = stats.psh_count;
    features.fin_flag_cnt = stats.fin_count;
    features.psh_flag_cnt = stats.psh_count;
    features.ack_flag_cnt = stats.ack_count;

    // Header Lengths
    features.fwd_header_len = stats.total_fwd_header_len;
    features.bwd_header_len = stats.total_bwd_header_len;

    // Packet Rates
    if (duration > 0) {
        features.fwd_pkts_s = stats.fwd_packets / duration;
        features.bwd_pkts_s = stats.bwd_packets / duration;
    }

    // Flow Ratios
    if (stats.fwd_packets > 0) {
        features.down_up_ratio = static_cast<double>(stats.bwd_packets) / stats.fwd_packets;
    }
    if (stats.total_packets > 0) {
        features.avg_pkt_size = static_cast<double>(stats.total_bytes) / stats.total_packets;
    }

    // Subflow metrics
    features.subflow_fwd_bytes = stats.fwd_pkt_len_total;

    return features;
}

std::vector<float> FeatureExtractor::to_vector(const Features& features) const {
    return {
        static_cast<float>(features.dst_port),
        features.tot_len_fwd_pkts,
        static_cast<float>(features.fwd_pkt_len_min),
        features.bwd_pkt_length_max,
        static_cast<float>(features.bwd_pkt_length_min),
        features.bwd_pkt_len_mean,
        features.bwd_pkt_len_std,
        features.flow_bytes_s,
        features.flow_pkts_s,
        features.flow_iat_mean,
        features.flow_iat_std,
        static_cast<float>(features.flow_iat_min),
        features.fwd_iat_mean,
        features.fwd_iat_std,
        static_cast<float>(features.fwd_iat_min),
        static_cast<float>(features.bwd_iat_total),
        features.bwd_iat_mean,
        features.bwd_iat_max,
        static_cast<float>(features.fwd_psh_flags),
        static_cast<float>(features.fin_flag_cnt),
        static_cast<float>(features.psh_flag_cnt),
        static_cast<float>(features.ack_flag_cnt),
        static_cast<float>(features.fwd_header_len),
        static_cast<float>(features.bwd_header_len),
        features.fwd_pkts_s,
        features.bwd_pkts_s,
        static_cast<float>(features.min_pkt_len),
        features.max_pkt_len,
        features.pkt_len_mean,
        features.pkt_len_std,
        features.pkt_len_var,
        static_cast<float>(features.down_up_ratio),
        features.avg_pkt_size,
        features.avg_bwd_seg_size,
        features.subflow_fwd_bytes,
        static_cast<float>(features.init_win_bytes_fwd),
        static_cast<float>(features.init_win_bytes_bwd),
        static_cast<float>(features.act_data_pkt_fwd),
        static_cast<float>(features.min_seg_size_fwd),
        features.idle_Std,
        features.fwd_pkt_len_profile,
        features.total_pkts_subflow_profile,
        features.fwd_flow_idle_profile,
        features.flow_duration_norm,
        features.fwd_seg_pkt_profile,
        features.idle_profile,
        features.active_profile
    };
}