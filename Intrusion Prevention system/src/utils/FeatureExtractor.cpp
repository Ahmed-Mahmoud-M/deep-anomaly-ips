#include "../../include/utils/FeatureExtractor.hpp"


#include <numeric>




FeatureExtractor::Features FeatureExtractor::extract(const FlowTracker::FlowKey&key, const FlowTracker::FlowStatistics &stats){
    Features f;

    f.dst_port = key.dst_port;
    

    
}


std::vector<float> FeatureExtractor::to_vector(const Features& f) const {

    return {
        static_cast<float>(f.dst_port),
        
    };
}