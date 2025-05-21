#include "Intrusion Prevention system/src/sniffing/PacketCapture.cpp"
#include "Intrusion Prevention system/src/sniffing/PacketParser.cpp"
#include "Intrusion Prevention system/src/sniffing/FlowTracker.cpp"
#include "Intrusion Prevention system/src/utils/FeatureExtractor.cpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <ctime>
#include <mutex>

class CSVLogger {
public:
    CSVLogger(const std::string& filename, bool log_features = false) 
        : log_features(log_features) {
        file.open(filename, std::ios::out | std::ios::app);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open log file: " + filename);
        }
        
        if (file.tellp() == 0) {
            writeHeader();
        }
    }

    ~CSVLogger() {
        if (file.is_open()) {
            file.close();
        }
    }

    void log(const FlowTracker::FlowKey& key, 
            const FlowTracker::FlowStatistics& stats,
            const FeatureExtractor::Features& features) {
        if (!file.is_open()) return;

        std::lock_guard<std::mutex> lock(log_mutex);
        auto timestamp = getTimestamp();

        if (log_features) {
            file << timestamp << ","
                 << PacketParser::ip_to_String(key.src_ip) << ","
                 << key.src_port << ","
                 << PacketParser::ip_to_String(key.dst_ip) << ","
                 << key.dst_port << ","
                 << static_cast<int>(key.protocol) << ","
                 << stats.total_packets << ","
                 << stats.total_bytes << ","
                 << std::chrono::duration<double>(stats.last_packet_time - stats.start_time).count() << ","
                 << stats.fwd_packets << ","
                 << stats.bwd_packets << ","
                 << features.flow_bytes_s << ","
                 << features.flow_pkts_s << ","
                 << features.flow_iat_mean << ","
                 << features.flow_iat_std << ","
                 << features.fwd_iat_mean << ","
                 << features.fwd_iat_std << ","
                 << features.bwd_iat_mean << ","
                 << features.bwd_iat_max << ","
                 << features.fwd_psh_flags << ","
                 << features.fin_flag_cnt << ","
                 << features.psh_flag_cnt << ","
                 << features.ack_flag_cnt << ","
                 << features.fwd_header_len << ","
                 << features.bwd_header_len << ","
                 << features.fwd_pkts_s << ","
                 << features.bwd_pkts_s << ","
                 << features.min_pkt_len << ","
                 << features.max_pkt_len << ","
                 << features.pkt_len_mean << ","
                 << features.pkt_len_std << ","
                 << features.down_up_ratio << ","
                 << features.avg_pkt_size << ","
                 << features.avg_bwd_seg_size << "\n";
        } else {
            file << timestamp << ","
                 << PacketParser::ip_to_String(key.src_ip) << ","
                 << key.src_port << ","
                 << PacketParser::ip_to_String(key.dst_ip) << ","
                 << key.dst_port << ","
                 << static_cast<int>(key.protocol) << ","
                 << stats.total_packets << ","
                 << stats.total_bytes << ","
                 << std::chrono::duration<double>(stats.last_packet_time - stats.start_time).count() << ","
                 << stats.syn_count << ","
                 << stats.fin_count << ","
                 << stats.rst_count << ","
                 << stats.psh_count << ","
                 << stats.ack_count << ","
                 << features.flow_bytes_s << ","
                 << features.flow_pkts_s << "\n";
        }
        file.flush();
    }

    void logPacket(const NetworkPacket& packet) {
        if (!file.is_open()) return;

        std::lock_guard<std::mutex> lock(log_mutex);
        auto timestamp = getTimestamp();

        file << timestamp << ","
             << PacketParser::ip_to_String(packet.src_ip) << ","
             << packet.src_port << ","
             << PacketParser::ip_to_String(packet.dst_ip) << ","
             << packet.dst_port << ","
             << static_cast<int>(packet.ip_protocol) << ","
             << packet.ip_length << ","
             << (packet.ip_protocol == PacketParser::IP_PROTOCOL_TCP ? packet.tcp_flags : 0) << "\n";
        file.flush();
    }

private:
   void writeHeader() {
    file << "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,"
         << "packet_count,byte_count,duration,fwd_packets,bwd_packets,"
         << "flow_bytes_s,flow_pkts_s,flow_iat_mean,flow_iat_std,"
         << "fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,"
         << "bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,"
         << "fwd_psh_flags,fin_flag_cnt,psh_flag_cnt,ack_flag_cnt,"
         << "fwd_header_len,bwd_header_len,fwd_pkts_s,bwd_pkts_s,"
         << "min_pkt_len,max_pkt_len,pkt_len_mean,pkt_len_std,pkt_len_var,"
         << "down_up_ratio,avg_pkt_size,avg_fwd_seg_size,avg_bwd_seg_size,"
         << "subflow_fwd_bytes,subflow_bwd_bytes,"
         << "init_win_bytes_fwd,init_win_bytes_bwd,"
         << "act_data_pkt_fwd,min_seg_size_fwd,"
         << "idle_mean,idle_std,idle_max,idle_min,"
         << "fwd_pkt_len_profile,total_pkts_subflow_profile,"
         << "fwd_flow_idle_profile,flow_duration_norm,"
         << "fwd_seg_pkt_profile,idle_profile,active_profile\n";
}

    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        char buf[20];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now_time));
        return std::string(buf);
    }

    std::ofstream file;
    std::mutex log_mutex;
    bool log_features;
};

void displayFlowInfo(const FlowTracker& tracker, const FeatureExtractor& extractor) {
    const auto& flows = tracker.get_active_flows();
    if (flows.empty()) {
        std::cout << "No active flows\n";
        return;
    }

    std::vector<std::pair<FlowTracker::FlowKey, FlowTracker::FlowStatistics>> sorted_flows(
        flows.begin(), flows.end());
    
    std::sort(sorted_flows.begin(), sorted_flows.end(),
        [](const auto& a, const auto& b) {
            return a.second.total_packets > b.second.total_packets;
        });

    std::cout << "\nTop Flows (" << flows.size() << " total):\n";
    std::cout << "==========================================\n";
    for (size_t i = 0; i < std::min(5UL, sorted_flows.size()); i++) {
        const auto& [key, stats] = sorted_flows[i];
        auto features = extractor.extract(key, stats);
        
        std::cout << i+1 << ". " 
                  << PacketParser::ip_to_String(key.src_ip) << ":" << key.src_port
                  << " → " 
                  << PacketParser::ip_to_String(key.dst_ip) << ":" << key.dst_port
                  << " Proto: " << (key.protocol == PacketParser::IP_PROTOCOL_TCP ? "TCP" : 
                                   key.protocol == PacketParser::IP_PROTOCOL_UDP ? "UDP" : "Other")
                  << "\n   Packets: " << stats.total_packets
                  << " | Bytes: " << stats.total_bytes
                  << " | Duration: " << std::chrono::duration<double>(stats.last_packet_time - stats.start_time).count() << "s"
                  << "\n   Fwd/Bwd: " << stats.fwd_packets << "/" << stats.bwd_packets
                  << " | Rate: " << features.flow_pkts_s << " pkt/s, " 
                  << features.flow_bytes_s/1024 << " KB/s"
                  << "\n   Flags: SYN=" << stats.syn_count << " FIN=" << stats.fin_count 
                  << " RST=" << stats.rst_count << " ACK=" << stats.ack_count
                  << "\n------------------------------------------\n";
    }
}

int main() {
    try {
        // Initialize components
        PacketCapture capture;
        PacketParser parser;
        FlowTracker tracker(std::chrono::seconds(60), std::chrono::seconds(300));
        FeatureExtractor extractor;
        CSVLogger feature_logger("network_features.csv", true);
        CSVLogger packet_logger("packet_log.csv");

        // Configuration
        const std::string interface = "eth0";  // Change to your network interface
        const std::string filter = "tcp or udp or icmp";
        const int stat_interval_sec = 5;

        // Configure capture
        capture.set_interface(interface);
        capture.set_filiter(filter);
        capture.set_promiscuous(true);
        capture.set_timeout(1000);
        
        if (!capture.start_capture()) {
            throw std::runtime_error("Failed to start capture on interface: " + interface);
        }

        std::cout << "Starting network capture on " << interface << " with filter: " << filter << "\n";
        std::cout << "Press Ctrl+C to stop...\n\n";

        // Statistics
        uint32_t total_packets = 0;
        auto last_stat_time = std::chrono::steady_clock::now();
        auto last_feature_time = std::chrono::steady_clock::now();

        // Main capture loop
        while (true) {
            capture.process_next_packet();
            
            if (capture.has_packets()) {
                NetworkPacket packet;
                if (parser.parse_packet(capture.get_current_packet(), packet)) {
                    // Log raw packet
                    packet_logger.logPacket(packet);
                    
                    // Process with flow tracker
                    tracker.process_packet(packet);
                    total_packets++;

                    // Extract and log features periodically
                    auto now = std::chrono::steady_clock::now();
                    if (now - last_feature_time > std::chrono::seconds(1)) {
                        FlowTracker::FlowKey key{
                            packet.src_ip,
                            packet.dst_ip,
                            packet.src_port,
                            packet.dst_port,
                            packet.ip_protocol
                        };

                        const auto& flows = tracker.get_active_flows();
                        auto it = flows.find(key);
                        if (it != flows.end()) {
                            auto features = extractor.extract(key, it->second);
                            feature_logger.log(key, it->second, features);
                        }
                        last_feature_time = now;
                    }
                }
            }

            
            auto now = std::chrono::steady_clock::now();
            if (now - last_stat_time > std::chrono::seconds(stat_interval_sec)) {
                tracker.cleanup_expired_flows();
                
                std::cout << "\n=== Capture Statistics ================\n";
                std::cout << "Total packets processed: " << total_packets << "\n";
                std::cout << "Packets captured: " << capture.get_packets_captured() << "\n";
                std::cout << "Packets dropped: " << capture.get_packets_dropped() << "\n";
                
                displayFlowInfo(tracker, extractor);
                last_stat_time = now;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}