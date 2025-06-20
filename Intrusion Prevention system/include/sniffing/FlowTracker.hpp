#pragma  once



/*

purpose of that class to --> track networks flow like sequences of packets between two endpoints

FLowKey struct --> used as a unique identifiter for each flow using five tuples (src_ip,dst_ip,src_port,dst_port , protocol)


FlowKeyHash struct >> hash function for FLowkey to use as a key in the unordereed_map 


FLowStats --> track the statistics for a single flow 


*/


#include "PacketParser.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

class FlowTracker{

    public:
        struct FlowKey{
            uint32_t src_ip;
            uint32_t dst_ip;
            uint16_t src_port;
            uint16_t dst_port;
            uint8_t protocol;
            // allow comparsion between two flow keys to check if they are equal

            bool operator==(const FlowKey& other) const;
        };


        // hash for Flow key
        struct FlowKeyHash{
            std::size_t operator()(const FlowKey &key) const;
        };


        struct FlowStatistics{
            std::chrono::system_clock::time_point start_time;

            std::chrono::system_clock::time_point last_packet_time;



            // basic count for total packets and thier bytes
            uint32_t total_packets = 0;
            uint64_t total_bytes = 0;
            
            
            // Packet size stats
            uint32_t min_pkt_size = UINT32_MAX;
            uint32_t max_pkt_size = 0;
            uint64_t total_pkt_sizes = 0;

            // TCp-specific

            uint32_t syn_count = 0;
            uint32_t fin_count = 0;
            uint32_t rst_count = 0;
            uint32_t psh_count = 0;
            uint32_t ack_count = 0;


            // Timing statistics for cic2017IDS dataset

            double min_iat = -1.0; // interal-arrival time for  measuring how fast packets arrive

            double max_iat = -1.0;

            double total_iat = 0.0;



            // direction tracking for flows 


            uint32_t fwd_packets = 0;// Counts the number of packets sent from the source to the destination.


            uint32_t bwd_packets  = 0; // Counts the number of packets sent from the destination to the source.

            double fwd_total_iat = 0.0;      // Total forward IAT
            double bwd_total_iat = 0.0;      // Total backward IAT
            double fwd_iat_sq_sum = 0.0;     // Sum of squares for forward IAT
            double bwd_iat_sq_sum = 0.0;     // Sum of squares for backward IAT
            double fwd_max_iat = 0.0;        // Max forward IAT
            double bwd_max_iat = 0.0;        // Max backward IAT
            
            // For packet length variance
            uint64_t pkt_len_sq_sum = 0;     // Sum of squares of packet lengths
            
            // For header lengths
            uint32_t total_fwd_header_len = 0;
            uint32_t total_bwd_header_len = 0;
            
            // For TCP window sizes
            uint32_t init_win_fwd = 0;
            uint32_t init_win_bwd = 0;
            uint32_t min_seg_size_fwd = 0;
            
            // Timestamps for idle time calculation
            std::chrono::system_clock::time_point last_fwd_time;
            std::chrono::system_clock::time_point last_bwd_time;

            uint64_t fwd_pkt_len_total = 0;
            uint64_t bwd_pkt_len_total = 0;
            uint64_t fwd_pkt_len_sq_sum = 0;
            uint64_t bwd_pkt_len_sq_sum = 0;
            uint32_t fwd_seg_size_total = 0;
            uint32_t bwd_seg_size_total = 0;
            uint32_t fwd_win_bytes_total = 0;
            uint32_t bwd_win_bytes_total = 0;
            double fwd_iat_total = 0;
            double bwd_iat_total = 0;
            double fwd_min_iat = 0;
            double bwd_min_iat = 0;
            
            uint32_t act_data_pkt_fwd = 0;
            


            
        };


        // explicit constructor for configuration 

        /*
        inactive_timeout: How long to wait (in seconds) before considering a flow "dead" if no packets are seen.

        active_timeout: Maximum lifetime of a flow even if packets are still arriving.

        */
        explicit FlowTracker(
            std::chrono::seconds inactive_timeout = std::chrono::seconds(60),
            std::chrono::seconds active_timeout = std::chrono::seconds(300)
        );

     
        /*
        Main function that receives packets and:

            Identifies their flow.

            Creates/updates the corresponding FlowStats.
        */
        void process_packet(const NetworkPacket &Packet);

        /*
        Removes expired flows (due to timeout) from active_flows_ and stores them in completed_flows.
        */
        void cleanup_expired_flows();


        // getter methods 

        const std::unordered_map<FlowKey, FlowStatistics,FlowKeyHash>& get_active_flows()const;

       const std::vector<FlowTracker::FlowKey>& get_completed_flows()const;



        // flow timeout Configuration
        void set_timout(
        std::chrono::seconds inactive_timeout,
        std::chrono::seconds active_timeout
        );



    
        std::chrono::seconds active_timeout;
        std::chrono::seconds inactive_timeout;
        

        std::unordered_map<FlowKey, FlowStatistics,FlowKeyHash> active_flows;

        std::vector<FlowKey> completed_flows;


        // utils methods 

            //  Check timeout conditions.
        bool is_flow_expired(const FlowKey &key,const FlowStatistics & state)const;
            // Update stats for a flow when a packet arrives
        void update_flow_statistics(const FlowKey& key, FlowStatistics & stats, const NetworkPacket & packet);
        // Move a flow from active to completed.
        void finalize_flow(const FlowKey & key);

 

        
        std::unordered_map<FlowKey, FlowStatistics, FlowKeyHash>& 
        get_active_flows() { return active_flows; }
};



