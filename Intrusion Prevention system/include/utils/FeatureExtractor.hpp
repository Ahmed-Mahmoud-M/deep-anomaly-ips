#pragma  once




#include "../sniffing/FlowTracker.hpp"
#include <cstdint>
#include <vector>
#include <array>
class FeatureExtractor{


    struct Features{
        /*Basic features*/


        int64_t dst_port;

        // forward packet metrices

        float tot_len_fwd_pkts; // total length of Fwd packets
        int64_t fwd_pkt_len_min; // Fwd packet length min

        // Backward Packet metrices

        float bwd_pkt_length_max; // Bwd Packet Length Max
        int64_t bwd_pkt_length_min; // Bwd Packet Length Min
        float bwd_pkt_len_mean;    // Bwd Packet Length Mean
        float bwd_pkt_len_std;      // Bwd Packet Length Std


        // FLow tioming

        float flow_bytes_s;  // Flow Bytes/s
        float flow_pkts_s;   // Flow Packets/s
        float flow_iat_mean; // Flow IAT Mean
        float flow_iat_std;  // Flow IAT Std
        int64_t flow_iat_min; // Flow IAT Min



        // forward IAT 
        float  fwd_iat_mean;   // Fwd IAT Mean
        float  fwd_iat_std;    // Fwd IAT Std
        int64_t fwd_iat_min;    // Fwd IAT Min


        // Backward IAT

        int64_t bwd_iat_total; // Bwd IAT total
        float bwd_iat_mean; // Bwd IAT mean
        float bwd_iat_max;  // bwd IAT max



        // TCP FLAGS 

        int64_t fwd_psh_flags; // Fwd PSH Flags
        int64_t fin_flag_cnt;   // FIN Flag Count
        int64_t psh_flag_cnt;   // PSH Flag Count
        int64_t ack_flag_cnt;   // ACK Flag Count


        // Header Metricis 

        int64_t fwd_header_len; 
        int64_t bwd_header_len;


        // Packet Rates 

        float fwd_pkts_s; // Fwd Packets/s
        float bwd_pkts_s; // Bwd Packets/s




        // Packet length statistics 

        int64_t min_pkt_len; // Min Packet Length
        float max_pkt_len;    // Max Packet Length
        float pkt_len_mean;  // Packet Length Mean
        float pkt_len_std;   // Packet Length Std
        float pkt_len_var;  // Packet Length Variance


        // Flow Ratios
        int64_t   down_up_ratio;    // Down/Up Ratio
        float     avg_pkt_size;     // Average Packet Size
        float     avg_bwd_seg_size; // Avg Bwd Segment Size





        //subflow metrics 

        float subflow_fwd_bytes; // subflow fwd bytes

        // window sizes 


        int64_t  init_win_bytes_fwd;// Init_Win_bytes_forward
        int64_t  init_win_bytes_bwd; // Init_Win_bytes_backward
        int64_t act_data_pkt_fwd;  // act_data_pkt_fwd
        int64_t min_seg_size_fwd; // min_seg_size_forward


        // idle stats

        float idle_Std; // Idle std

        // 1. Fwd Packet Length Profile (PCA on Max/Mean/Std)
        float     fwd_pkt_len_profile;        // Explained Variance: 0.9826
        
        // 2. Total Packets and Subflow Bwd Profile (PCA on 4 features)
        float     total_pkts_subflow_profile; // Explained Variance: 0.9999
        
        // 3. Fwd Flow IAT Max and Idle Profile (2-stage PCA)
        float     fwd_flow_idle_profile;      // Explained Variance: 0.9942
        
        // 4. Flow Duration Normalized Feature
        float     flow_duration_norm;         // Derived from Fwd IAT Total
        
        // 5. Fwd Segment-Packet Length Profile (PCA on 2 features)
        float     fwd_seg_pkt_profile;        // Explained Variance: [from PCA6]
        
        // 6. Idle Profile (PCA on Mean/Max/Min)
        float     idle_profile;               // Explained Variance: [from PCA7]
        
        // 7. Active Profile (PCA on Mean/Std/Max/Min) 
        float     active_profile;              // Explained Variance: 0.8266



    };


    Features extract(const FlowTracker::FlowKey&key, const FlowTracker::FlowStatistics &stats);

    std::vector<float>to_vector(const Features& features) const;

   private:
    // PCA Weight Matrices (from your sklearn output)
    static constexpr std::array<std::array<float,4>,1> PCA_ACTIVE_WEIGHTS = {{
        {0.476217f, 0.208681f, 0.784759f, 0.337377f}  // Active Profile
    }};

    static constexpr std::array<std::array<float,3>,1> PCA_FWD_PKT_WEIGHTS = {{
        {0.912097f, 0.213190f, 0.350184f}  // Fwd Packet Length Profile
    }};

    static constexpr std::array<std::array<float,4>,1> PCA_TOTAL_PKTS_WEIGHTS = {{
        {0.707112f, 0.707102f, 0.000234f, 0.000310f}  // Total Packets Profile
    }};

    static constexpr std::array<std::array<float,2>,1> PCA_IDLE_MEANMAX_WEIGHTS = {{
        {0.696139f, 0.717907f}  // Idle Mean+Max Profile
    }};

    static constexpr std::array<std::array<float,2>,1> PCA_FWD_IDLE_WEIGHTS = {{
        {0.583926f, 0.811807f}  // Fwd Flow + Idle Profile
    }};

    static constexpr std::array<std::array<float,2>,1> PCA_SEG_PKT_WEIGHTS = {{
        {0.707107f, 0.707107f}  // Segment + Packet Profile
    }};

    static constexpr std::array<std::array<float,3>,1> PCA_IDLE_FULL_WEIGHTS = {{
        {0.577139f, 0.589575f, 0.565078f}  // Full Idle Profile
    }};
    

    // Helper methods
    template<size_t N>
    float apply_pca(const std::array<float,N>& values, 
                  const std::array<std::array<float,N>,1>& weights) const {
        float result = 0.0f;
        for(size_t i = 0; i < N; ++i) {
            result += values[i] * weights[0][i];
        }
        return result;
    }


};
