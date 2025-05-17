#include "../../include/sniffing/FlowTracker.hpp"
#include <chrono>
#include <cstdint>
#include <functional>


// flow equailty operator
bool FlowTracker::FlowKey::operator==(const FlowKey& other) const {

    return src_ip == other.src_ip &&
     dst_ip == other.dst_ip &&
     src_port == other.src_port &&
     dst_port == other.dst_port &&
     protocol == other.protocol;
}


// FLowkey hash implementation 

size_t FlowTracker::FlowKeyHash::operator()(const FlowKey &key) const{
    return std::hash<uint32_t>()(key.src_ip)^
    std::hash<uint32_t>()(key.dst_ip) ^
    std::hash<uint32_t>()(key.src_port) ^
    std::hash<uint32_t>()(key.dst_port) ^
    std::hash<uint32_t>()(key.protocol);
}

// constructor 
FlowTracker::FlowTracker(std::chrono::seconds inactive_timeout, std::chrono::seconds active_timeout): inactive_timeout(inactive_timeout),active_timeout(active_timeout) {}


