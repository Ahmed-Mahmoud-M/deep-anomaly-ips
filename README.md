# 🔐 Deep Anomaly IPS

A hybrid **C++/Python Intrusion Prevention System (IPS)** that leverages real-time packet capturing, deep learning-based anomaly detection, and alert generation. This architecture combines high-performance packet processing with advanced temporal-spatial feature learning using **CNN-LSTM** deep learning models.

> 📈 Achieved a detection accuracy of **98.35%** on the **CIC-IDS 2017** dataset, significantly improving upon the previous best model accuracy of **97.25%** referenced in a major IDS survey paper.

---

##  Overview

This project implements a modular and efficient IPS pipeline to detect anomalous network traffic with high accuracy. The system uses:

- **C++ (Libpcap)** for fast packet capturing and feature extraction.
- **Python (PyTorch)** for deep learning-based anomaly detection.
- A **Unix Domain Socket** bridge to seamlessly connect both components.

---

##  System Architecture

![Architecture Diagram](![image](https://github.com/user-attachments/assets/43727e9d-3f0d-4673-b999-b2cf27736338)


###  Workflow

1. **Network Interface** – Listens to live traffic on a specified interface.
2. **C++ Libpcap Capture** – Captures packets in real time.
3. **C++ Feature Extractor** – Extracts time-based and statistical features.
4. **Unix Domain Socket** – Bridges data from C++ to Python with minimal overhead.
5. **Python CNN-LSTM Model** – Applies deep anomaly detection using a hybrid model:
    - **Conv1D** for cross-feature extraction.
    - **LSTM layers** for temporal behavior modeling.
6. **Alert Generator** – Triggers alerts for detected anomalies.

---

##  Evaluation

- **Dataset Used:** CIC-IDS 2017
- **Performance Metric:** Accuracy, Precision, Recall, F1-score
- **Final Accuracy:** **98.35%**
- **Training:** Adam optimizer + Dropout regularization
- **Architecture Source:** Based on a leading IDS survey paper (previous best model: **97.25%**)

---

##  Technologies

| Layer              | Tools Used        |
|-------------------|-------------------|
| Packet Capture     | C++, libpcap       |
| Feature Extraction | C++                |
| Data Bridge        | Unix Domain Socket |
| Deep Learning      | Python, PyTorch    |
| Model Type         | CNN-LSTM Hybrid    |

---

##  Installation & Run

### CIC-IDS 2017 Dataset – https://www.unb.ca/cic/datasets/ids-2017.html


### Prerequisites

- C++ compiler (g++)
- Python 3.8+
- libpcap development libraries
- PyTorch, NumPy, Pandas, scikit-learn

### Build & Run

```bash
# Compile the C++ packet capture tool
g++ -std=c++17 -o capture capture.cpp -lpcap

# Start the Python model server
python3 model_server.py

# Run the packet capture tool (requires root)
sudo ./capture

