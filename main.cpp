#include "Intrusion Prevention system/src/sniffing/PacketCapture.cpp"
#include "Intrusion Prevention system/src/sniffing/PacketParser.cpp"
#include "Intrusion Prevention system/src/sniffing/FlowTracker.cpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <algorithm>

// Improved display that shows flow information
void display_flow_info(const FlowTracker& tracker) {
    std::cout << "\n Active Flows" << std::endl;
    std::cout << "Total flows: " << tracker.get_active_flows().size() << std::endl;
    
    // Show top 5 flows by packet count
    auto flows = tracker.get_active_flows();
    std::vector<std::pair<FlowTracker::FlowKey, FlowTracker::FlowStatistics>> sorted_flows(
        flows.begin(), flows.end());
    
    std::sort(sorted_flows.begin(), sorted_flows.end(),
        [](const auto& a, const auto& b) {
            return a.second.total_packets > b.second.total_packets;
        });
    
    for (int i = 0; i < std::min(5, (int)sorted_flows.size()); i++) {
        const auto& [key, stats] = sorted_flows[i];
        std::cout << i+1 << ". " 
                  << PacketParser::ip_to_String(key.src_ip) << ":" << key.src_port
                  << " → " 
                  << PacketParser::ip_to_String(key.dst_ip) << ":" << key.dst_port
                  << " (" << stats.total_packets << " pkts, "
                  << stats.total_bytes << " bytes)\n";
    }
    std::cout << "===================" << std::endl;
}

int main() {
    PacketCapture capture;
    PacketParser parser;
    FlowTracker tracker(std::chrono::seconds(60), std::chrono::seconds(300));
    
    // Statistics
    uint32_t total_packets = 0;
    auto last_stat_time = std::chrono::system_clock::now();

    capture.set_interface("eth0");
    capture.set_filiter("tcp");  // Fixed typo from "filiter"
    capture.start_capture();

    while (true) {
        capture.process_next_packet();
        if (capture.has_packets()) {
            NetworkPacket packet;
            if (parser.parse_packet(capture.get_current_packet(), packet)) {
                // Process with flow tracker
                tracker.process_packet(packet);
                total_packets++;
                
                // Display packet details (optional)
                // display_packet_details(packet);
            }
        }
        
        // Periodic cleanup and stats display
        auto now = std::chrono::system_clock::now();
        if (now - last_stat_time > std::chrono::seconds(5)) {
            tracker.cleanup_expired_flows();
            display_flow_info(tracker);
            
            std::cout << "\nTotal packets processed: " << total_packets << std::endl;
            last_stat_time = now;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    return 0;
}