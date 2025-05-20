#include "../../include/utils/FeatureExtractor.hpp"


#include <cmath>


using namespace std::chrono;

FeatureExtractor::Features FeatureExtractor::extract(
    const FlowTracker::FlowKey& key,
    const FlowTracker::FlowStatistics& stats) {
    
    Features f;

    //=== Calculate Duration ===//
    float duration_sec = duration<float>(stats.last_packet_time - stats.start_time).count();

    //=== Calculate Base Statistics ===//
    // Packet Length Statistics
    float pkt_len_mean = (stats.total_packets > 0) ? 
        static_cast<float>(stats.total_pkt_sizes) / stats.total_packets : 0.0f;
    float pkt_len_var = (stats.total_packets > 1) ?
        (stats.total_pkt_sizes_sq - (stats.total_pkt_sizes * stats.total_pkt_sizes) / stats.total_packets) 
        / (stats.total_packets - 1) : 0.0f;
    float pkt_len_std = sqrt(pkt_len_var);

    // Flow Timing Statistics
    float flow_iat_mean = (stats.total_packets > 0) ? 
        stats.total_iat / stats.total_packets : 0.0;
    float flow_iat_std = (stats.total_packets > 1) ?
        sqrt((stats.total_iat_sq - (stats.total_iat * stats.total_iat) / stats.total_packets)
        / (stats.total_packets - 1)) : 0.0;

    // Directional Statistics
    float fwd_pkt_len_mean = (stats.fwd_packets > 0) ?
        static_cast<float>(stats.fwd_bytes) / stats.fwd_packets : 0.0f;
    float bwd_pkt_len_mean = (stats.bwd_packets > 0) ?
        static_cast<float>(stats.bwd_bytes) / stats.bwd_packets : 0.0f;

    //=== Calculate Intermediate Values for PCA Features ===//
    // Active Stats
    float active_mean = (stats.active_count > 0) ? 
        stats.active_time_total / stats.active_count : 0.0f;

    // Idle Stats
    float idle_mean = (stats.idle_count > 0) ? 
        stats.idle_time_total / stats.idle_count : 0.0f;
    float idle_std = (stats.idle_count > 1) ?
        sqrt(stats.idle_time_total / stats.idle_count) : 0.0f;

    // Forward IAT
    float fwd_iat_mean = (stats.fwd_packets > 0) ? 
        stats.fwd_iat_total / stats.fwd_packets : 0.0f;
    float fwd_flow_iat_max = (stats.flow_iat_max + fwd_iat_mean) / 2.0f;

    //=== Set Base Features ===//
    f.dst_port = key.dst_port;
    f.tot_len_fwd_pkts = static_cast<float>(stats.fwd_bytes);
    f.fwd_pkt_len_min = stats.min_pkt_size;
    f.bwd_pkt_length_max = static_cast<float>(stats.max_pkt_size);
    f.bwd_pkt_length_min = stats.min_pkt_size;
    f.bwd_pkt_len_mean = bwd_pkt_len_mean;
    f.bwd_pkt_len_std = pkt_len_std; // Using overall std as approximation
    f.flow_bytes_s = (duration_sec > 0) ? stats.total_bytes / duration_sec : 0.0f;
    f.flow_pkts_s = (duration_sec > 0) ? stats.total_packets / duration_sec : 0.0f;
    f.flow_iat_mean = flow_iat_mean;
    f.flow_iat_std = flow_iat_std;
    f.flow_iat_min = static_cast<int64_t>(stats.min_iat * 1e6);
    f.fwd_iat_mean = fwd_iat_mean;
    f.fwd_iat_std = flow_iat_std; // Using flow std as approximation
    f.fwd_iat_min = static_cast<int64_t>(stats.min_iat * 1e6);
    f.bwd_iat_total = static_cast<int64_t>(stats.bwd_iat_total);
    f.bwd_iat_mean = (stats.bwd_packets > 0) ? 
        stats.bwd_iat_total / stats.bwd_packets : 0.0f;
    f.bwd_iat_max = static_cast<float>(stats.bwd_iat_max);
    f.fwd_psh_flags = stats.psh_count;
    f.fin_flag_cnt = stats.fin_count;
    f.psh_flag_cnt = stats.psh_count;
    f.ack_flag_cnt = stats.ack_count;
    f.fwd_header_len = stats.fwd_header_len;
    f.bwd_header_len = stats.bwd_header_len;
    f.fwd_pkts_s = (duration_sec > 0) ? stats.fwd_packets / duration_sec : 0.0f;
    f.bwd_pkts_s = (duration_sec > 0) ? stats.bwd_packets / duration_sec : 0.0f;
    f.min_pkt_len = stats.min_pkt_size;
    f.max_pkt_len = static_cast<float>(stats.max_pkt_size);
    f.pkt_len_mean = pkt_len_mean;
    f.pkt_len_std = pkt_len_std;
    f.pkt_len_var = pkt_len_var;
    f.down_up_ratio = (stats.bwd_packets > 0) ? 
        static_cast<int64_t>(stats.fwd_packets / stats.bwd_packets) : 0;
    f.avg_pkt_size = pkt_len_mean;
    f.avg_bwd_seg_size = bwd_pkt_len_mean;
    f.subflow_fwd_bytes = static_cast<float>(stats.subflow_fwd_bytes);
    f.init_win_bytes_fwd = stats.init_win_bytes_fwd;
    f.init_win_bytes_bwd = stats.init_win_bytes_bwd;
    f.act_data_pkt_fwd = stats.act_data_pkt_fwd;
    f.min_seg_size_fwd = stats.min_seg_size_fwd;
    f.idle_Std = idle_std;

    //=== Calculate PCA Features ===//
    // 1. Active Profile
    f.active_profile = apply_pca<4>(
        {active_mean, idle_std, static_cast<float>(stats.max_pkt_size), 
        static_cast<float>(stats.min_pkt_size)},
        PCA_ACTIVE_WEIGHTS
    );

    // 2. Fwd Packet Length Profile
    f.fwd_pkt_len_profile = apply_pca<3>(
        {static_cast<float>(stats.max_pkt_size), fwd_pkt_len_mean, pkt_len_std},
        PCA_FWD_PKT_WEIGHTS
    );

    // 3. Total Packets Profile
    f.total_pkts_subflow_profile = apply_pca<4>(
        {static_cast<float>(stats.bwd_bytes), static_cast<float>(stats.subflow_bwd_bytes),
         static_cast<float>(stats.fwd_packets), static_cast<float>(stats.bwd_packets)},
        PCA_TOTAL_PKTS_WEIGHTS
    );

    // 4. Idle Mean+Max Profile
    float idle_meanmax = apply_pca<2>(
        {idle_mean, static_cast<float>(stats.max_pkt_size)},
        PCA_IDLE_MEANMAX_WEIGHTS
    );

    // 5. Fwd Flow IAT + Idle Profile
    f.fwd_flow_idle_profile = apply_pca<2>(
        {fwd_flow_iat_max, idle_meanmax},
        PCA_FWD_IDLE_WEIGHTS
    );

    // 6. Flow Duration Normalized
    f.flow_duration_norm = (duration_sec > 0 && fwd_flow_iat_max > 0) ? 
        duration_sec / fwd_flow_iat_max : 0.0f;

    // 7. Fwd Segment-Packet Profile
    f.fwd_seg_pkt_profile = apply_pca<2>(
        {f.avg_pkt_size, pkt_len_mean},
        PCA_SEG_PKT_WEIGHTS
    );

    // 8. Full Idle Profile
    f.idle_profile = apply_pca<3>(
        {idle_mean, static_cast<float>(stats.max_pkt_size), 
         static_cast<float>(stats.min_pkt_size)},
        PCA_IDLE_FULL_WEIGHTS
    );

    return f;
}

std::vector<float> FeatureExtractor::to_vector(const Features& f) const {
    return {
        // Base features (39)
        static_cast<float>(f.dst_port),
        f.tot_len_fwd_pkts,
        static_cast<float>(f.fwd_pkt_len_min),
        f.bwd_pkt_length_max,
        static_cast<float>(f.bwd_pkt_length_min),
        f.bwd_pkt_len_mean,
        f.bwd_pkt_len_std,
        f.flow_bytes_s,
        f.flow_pkts_s,
        static_cast<float>(f.flow_iat_mean),
        static_cast<float>(f.flow_iat_std),
        static_cast<float>(f.flow_iat_min),
        f.fwd_iat_mean,
        f.fwd_iat_std,
        static_cast<float>(f.fwd_iat_min),
        static_cast<float>(f.bwd_iat_total),
        f.bwd_iat_mean,
        f.bwd_iat_max,
        static_cast<float>(f.fwd_psh_flags),
        static_cast<float>(f.fwd_header_len),
        static_cast<float>(f.bwd_header_len),
        f.fwd_pkts_s,
        f.bwd_pkts_s,
        static_cast<float>(f.min_pkt_len),
        f.max_pkt_len,
        f.pkt_len_mean,
        f.pkt_len_std,
        f.pkt_len_var,
        static_cast<float>(f.fin_flag_cnt),
        static_cast<float>(f.psh_flag_cnt),
        static_cast<float>(f.ack_flag_cnt),
        static_cast<float>(f.down_up_ratio),
        f.avg_pkt_size,
        f.avg_bwd_seg_size,
        f.subflow_fwd_bytes,
        static_cast<float>(f.init_win_bytes_fwd),
        static_cast<float>(f.init_win_bytes_bwd),
        static_cast<float>(f.act_data_pkt_fwd),
        static_cast<float>(f.min_seg_size_fwd),
        f.idle_Std,

        // PCA features (7)
        f.active_profile,
        f.fwd_pkt_len_profile,
        f.total_pkts_subflow_profile,
        f.fwd_flow_idle_profile,
        f.flow_duration_norm,
        f.fwd_seg_pkt_profile,
        f.idle_profile
    };
}
