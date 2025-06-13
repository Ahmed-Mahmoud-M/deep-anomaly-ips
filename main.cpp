// Updated main.cpp with socket integration and logging

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <unordered_set>
#include<sstream>

class SimpleLogger {
public:
    enum LogLevel { INFO, WARNING, ERROR };
    
    SimpleLogger(const std::string& filename, bool console_output = true) 
        : console_output_(console_output) {
        file_.open(filename, std::ios::out | std::ios::app);
        if (!file_.is_open()) {
            throw std::runtime_error("Failed to open log file: " + filename);
        }
    }

    ~SimpleLogger() {
        if (file_.is_open()) {
            file_.close();
        }
    }

    void log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        auto timestamp = getTimestamp();
        std::string level_str;
        
        switch(level) {
            case INFO: level_str = "INFO"; break;
            case WARNING: level_str = "WARNING"; break;
            case ERROR: level_str = "ERROR"; break;
        }
        
        std::string log_entry = "[" + timestamp + "] [" + level_str + "] " + message;
        
        if (console_output_) {
            std::cout << log_entry << std::endl;
        }
        
        if (file_.is_open()) {
            file_ << log_entry << std::endl;
            file_.flush();
        }
    }

private:
    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        char buf[20];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now_time));
        return std::string(buf);
    }

    std::ofstream file_;
    std::mutex log_mutex_;
    bool console_output_;
};
class IPBlocker {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(ip);
        
        // Execute iptables command to block the IP
        std::string command = "sudo iptables -A INPUT -s " + ip + " -j DROP";
        system(command.c_str());
    }
    
    bool isBlocked(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_ips_.find(ip) != blocked_ips_.end();
    }
    
    void unblockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.erase(ip);
        
        // Execute iptables command to unblock the IP
        std::string command = "sudo iptables -D INPUT -s " + ip + " -j DROP";
        system(command.c_str());
    }

    size_t getBlockedCount() {
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_ips_.size();
    }

private:
    std::unordered_set<std::string> blocked_ips_;
    std::mutex mutex_;
};

class PythonModelClient {
public:
    PythonModelClient(const std::string& server_ip, int server_port, SimpleLogger& logger) 
        : logger_(logger) {
        sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_ < 0) {
            logger_.log(SimpleLogger::ERROR, "Error opening socket");
            return;
        }
        
        server_.sin_family = AF_INET;
        server_.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip.c_str(), &server_.sin_addr);
        
        if (connect(sockfd_, (struct sockaddr *) &server_, sizeof(server_)) < 0) {
            logger_.log(SimpleLogger::ERROR, "Error connecting to Python model server");
            close(sockfd_);
            sockfd_ = -1;
        } else {
            logger_.log(SimpleLogger::INFO, "Connected to Python model server at " + server_ip + ":" + std::to_string(server_port));
        }
    }
    
    ~PythonModelClient() {
        if (sockfd_ >= 0) {
            close(sockfd_);
        }
    }
    
    bool isConnected() const {
        return sockfd_ >= 0;
    }
    
    std::string predict(const std::string& features) {
        if (!isConnected()) {
            return "error:not_connected";
        }
        
        // Send features to Python server
        int n = write(sockfd_, features.c_str(), features.length());
        if (n < 0) {
            logger_.log(SimpleLogger::ERROR, "Error writing to socket");
            return "error:write_failed";
        }
        
        // Read response
        char buffer[256];
        n = read(sockfd_, buffer, 255);
        if (n < 0) {
            logger_.log(SimpleLogger::ERROR, "Error reading from socket");
            return "error:read_failed";
        }
        
        buffer[n] = '\0';
        return std::string(buffer);
    }

private:
    int sockfd_;
    struct sockaddr_in server_;
    SimpleLogger& logger_;
};

std::string featuresToCSV(const FlowTracker::FlowKey& key, 
                         const FlowTracker::FlowStatistics& stats,
                         const FeatureExtractor::Features& features) {
    std::ostringstream oss;
    oss << PacketParser::ip_to_String(key.src_ip) << ","
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
        << features.avg_bwd_seg_size;
    
    return oss.str();
}

int main() {
    try {
        // Initialize components
        SimpleLogger logger("ids.log", true);
        IPBlocker ip_blocker;
        PacketCapture capture;
        PacketParser parser;
        FlowTracker tracker(std::chrono::seconds(60), std::chrono::seconds(300));
        FeatureExtractor extractor;
        
        // Connect to Python model server
        PythonModelClient model_client("127.0.0.1", 9999, logger);
        
        // Configuration
        const std::string interface = "eth0";  // Change to your network interface
        const std::string filter = "tcp or udp or icmp";
        const int stat_interval_sec = 5;
        const bool enable_blocking = true;

        // Configure capture
        capture.set_interface(interface);
        capture.set_filiter(filter);
        capture.set_promiscuous(true);
        capture.set_timeout(1000);
        
        if (!capture.start_capture()) {
            throw std::runtime_error("Failed to start capture on interface: " + interface);
        }

        logger.log(SimpleLogger::INFO, "Starting network capture on " + interface + " with filter: " + filter);
        logger.log(SimpleLogger::INFO, "Press Ctrl+C to stop...");

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
                    // Log basic packet info
                    logger.log(SimpleLogger::INFO, 
                        "Packet: " + PacketParser::ip_to_String(packet.src_ip) + ":" + 
                        std::to_string(packet.src_port) + " -> " + 
                        PacketParser::ip_to_String(packet.dst_ip) + ":" + 
                        std::to_string(packet.dst_port) + " Proto: " + 
                        std::to_string(static_cast<int>(packet.ip_protocol)) + " Size: " +
                        std::to_string(packet.ip_length));
                    
                    // Process with flow tracker
                    tracker.process_packet(packet);
                    total_packets++;

                    // Extract and send features to model periodically
                    auto now = std::chrono::steady_clock::now();
                    if (now - last_feature_time > std::chrono::seconds(1) && model_client.isConnected()) {
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
                            std::string feature_csv = featuresToCSV(key, it->second, features);
                            
                            // Get prediction from Python model
                            std::string prediction = model_client.predict(feature_csv);
                            
                            if (prediction.find("error:") == std::string::npos) {
                                logger.log(SimpleLogger::INFO, "Model prediction: " + prediction);
                                
                                // Block malicious IPs
                                if (enable_blocking && prediction != "BENIGN") {
                                    std::string src_ip = PacketParser::ip_to_String(key.src_ip);
                                    if (!ip_blocker.isBlocked(src_ip)) {
                                        ip_blocker.blockIP(src_ip);
                                        logger.log(SimpleLogger::WARNING, 
                                            "Blocked IP " + src_ip + " due to " + prediction + " attack");
                                    }
                                }
                            } else {
                                logger.log(SimpleLogger::ERROR, "Model prediction error: " + prediction);
                            }
                        }
                        last_feature_time = now;
                    }
                }
            }

            // Periodic statistics and cleanup
            auto now = std::chrono::steady_clock::now();
            if (now - last_stat_time > std::chrono::seconds(stat_interval_sec)) {
                tracker.cleanup_expired_flows();
                
                std::ostringstream stats_msg;
                stats_msg << "=== Capture Statistics ===\n"
                         << "Total packets processed: " << total_packets << "\n"
                         << "Packets captured: " << capture.get_packets_captured() << "\n"
                         << "Packets dropped: " << capture.get_packets_dropped() << "\n"
                         << "Active flows: " << tracker.get_active_flows().size() << "\n"
                         << "Blocked IPs: " << ip_blocker.getBlockedCount();
                
                logger.log(SimpleLogger::INFO, stats_msg.str());
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