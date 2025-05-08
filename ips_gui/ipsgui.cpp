#include "ipsgui.h"
#include <QInputDialog>

IPSGUI::IPSGUI(QWidget* parent) : QWidget(parent), systemRunning(false), currentFilter("None") {
    QVBoxLayout* layout = new QVBoxLayout(this);

    QLabel* title = new QLabel("🔥 IPS / IDS GUI 🔥", this);
    title->setStyleSheet("font-weight: bold; font-size: 18px;");
    layout->addWidget(title);

    statusLabel = new QLabel("Status: STOPPED", this);
    layout->addWidget(statusLabel);

    filterLabel = new QLabel("Filter: None", this);
    layout->addWidget(filterLabel);

    blockedList = new QListWidget(this);
    layout->addWidget(blockedList);

    QPushButton* startBtn = new QPushButton("Start", this);
    QPushButton* stopBtn = new QPushButton("Stop", this);
    QPushButton* filterBtn = new QPushButton("Set Filter", this);
    QPushButton* blockBtn = new QPushButton("Block IP", this);

    layout->addWidget(startBtn);
    layout->addWidget(stopBtn);
    layout->addWidget(filterBtn);
    layout->addWidget(blockBtn);

    connect(startBtn, &QPushButton::clicked, this, &IPSGUI::startSystem);
    connect(stopBtn, &QPushButton::clicked, this, &IPSGUI::stopSystem);
    connect(filterBtn, &QPushButton::clicked, this, &IPSGUI::setFilter);
    connect(blockBtn, &QPushButton::clicked, this, &IPSGUI::blockIP);
}

void IPSGUI::startSystem() {
    systemRunning = true;
    statusLabel->setText("Status: RUNNING");
}

void IPSGUI::stopSystem() {
    systemRunning = false;
    statusLabel->setText("Status: STOPPED");
}

void IPSGUI::setFilter() {
    bool ok;
    QString filter = QInputDialog::getText(this, "Set Filter", "Enter filter rule:", QLineEdit::Normal, currentFilter, &ok);
    if (ok && !filter.isEmpty()) {
        currentFilter = filter;
        filterLabel->setText("Filter: " + currentFilter);
    }
}

void IPSGUI::blockIP() {
    bool ok;
    QString ip = QInputDialog::getText(this, "Block IP", "Enter IP to block:", QLineEdit::Normal, "", &ok);
    if (ok && !ip.isEmpty()) {
        blockedIPs.append(ip);
        blockedList->addItem(ip);
    }
}
