#pragma once


// track network flows (5 tuples: src/dst Ip , src/dst Port, Protocol)



#include "PacketCapture.hpp"
#include <chrono>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

struct FlowKey {

    uint32_t srcIp;
    uint32_t dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t Protocol;

    bool operator == (const FlowKey& other) const; // for the map
};

// hash function for FLowKey

// namespace std {
//     template <> struct hash<FlowKey>{
//         size_t operator()(const FlowKey&key) const;
//     };
// }

struct FlowData {
    uint64_t packetCount;
    uint64_t totalBytes;
    std::chrono::steady_clock::time_point lastSeen;
};



class FlowTracker {
    public:
        void updateFlow(const Packet& packet);
        void removeInactiveFlows (int timeoutsec = 30);
        std::vector<FlowKey> detectPortScans(int threshold = 100);
    

    private:
        std::unordered_map<FlowKey, FlowData> activeFLows;
        std::mutex flowMutex;
};