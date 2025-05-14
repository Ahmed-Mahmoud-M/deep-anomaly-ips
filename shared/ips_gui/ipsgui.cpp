#include "ipsgui.h"
#include <QVBoxLayout>
#include <QMessageBox>
#include <QFont>
#include <QInputDialog>
#include <QFile>
#include <QTextStream>
#include <QIODevice>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QApplication>
#include <QDesktopWidget>
#include <QGuiApplication>
#include <QScreen>



IPSGUI::IPSGUI(QWidget *parent)
    : QWidget(parent)
{
    isMonitoring = false;
    setupUI();
}

void IPSGUI::setupUI()
{
    this->setStyleSheet("background-color: black;");
    
     QScreen *screen = QGuiApplication::primaryScreen();
    QRect screenGeometry = screen->geometry();
    int width = screenGeometry.width() * 0.8;  // 80% من عرض الشاشة
    int height = screenGeometry.height() * 0.8; // 80% من ارتفاع الشاشة
    this->resize(width, height);
    
    QVBoxLayout *layout = new QVBoxLayout(this);

    // Save button layout (top right)
    QHBoxLayout *topSaveLayout = new QHBoxLayout;
    topSaveLayout->addStretch();

    saveButton = new QPushButton("SAVE LOG", this);
    saveButton->setStyleSheet("background-color: #2F4F4F; color: white; font-size: 20px; padding: 10px;");
    saveButton->setFixedSize(140, 40);
    connect(saveButton, &QPushButton::clicked, this, &IPSGUI::saveLog);

    topSaveLayout->addWidget(saveButton);
    layout->addLayout(topSaveLayout);

    // Log viewer
    logViewer = new QTextEdit(this);
    logViewer->setReadOnly(true);
    logViewer->setStyleSheet("background-color: black; color: #A8FF60; font-size: 30px; border-radius: 5px; padding: 10px; font-family: 'Courier New', monospace;");
    layout->addWidget(logViewer);

    // Buttons (Filter, Block IP, Clear)
    setFilterButton = new QPushButton("SET FILTER", this);
    setFilterButton->setStyleSheet("background-color: #1A3D6B; color: white; font-size: 26px; padding: 12px;");
    connect(setFilterButton, &QPushButton::clicked, this, &IPSGUI::setFilter);
    layout->addWidget(setFilterButton);

    blockIPButton = new QPushButton("BLOCK IP", this);
    blockIPButton->setStyleSheet("background-color: black; color: white; font-size: 26px; padding: 12px;");
    connect(blockIPButton, &QPushButton::clicked, this, &IPSGUI::blockIP);
    layout->addWidget(blockIPButton);

    clearLogButton = new QPushButton("CLEAR LOG", this);
    clearLogButton->setStyleSheet("background-color: gray; color: white; font-size: 26px; padding: 12px;");
    connect(clearLogButton, &QPushButton::clicked, this, &IPSGUI::clearLog);
    layout->addWidget(clearLogButton);

    // Start and Stop buttons (bottom, opposite sides)
    QHBoxLayout *buttonLayout = new QHBoxLayout;

    startButton = new QPushButton("START", this);
    startButton->setStyleSheet("background-color: darkgreen; color: white; font-size: 30px;");
    startButton->setFixedSize(170, 50);
    connect(startButton, &QPushButton::clicked, this, &IPSGUI::startMonitoring);
    buttonLayout->addWidget(startButton);

    buttonLayout->addStretch();

    stopButton = new QPushButton("STOP", this);
    stopButton->setStyleSheet("background-color: darkred; color: white; font-size: 30px;");
    stopButton->setFixedSize(170, 50);
    connect(stopButton, &QPushButton::clicked, this, &IPSGUI::stopMonitoring);
    buttonLayout->addWidget(stopButton);

    layout->addLayout(buttonLayout);
    setLayout(layout);
}

void IPSGUI::startMonitoring()
{
    isMonitoring = true;
    logViewer->setTextColor(Qt::green);
    logViewer->append("> Monitoring started...");
}

void IPSGUI::stopMonitoring()
{
    isMonitoring = false;
    logViewer->setTextColor(Qt::red);
    logViewer->append("> Monitoring stopped...");
}

void IPSGUI::setFilter()
{
    bool ok;
    int port = QInputDialog::getInt(this, "Set Filter", "Enter Port to filter (e.g., 80):", 80, 1, 65535, 1, &ok);
    if (ok) {
        logViewer->setTextColor(isMonitoring ? Qt::green : Qt::red);
        logViewer->append("> Filter has been set on Port: " + QString::number(port));
    }
}

void IPSGUI::blockIP()
{
    bool ok;
    QString ip = QInputDialog::getText(this, "Block IP", "Enter IP to block (e.g., 192.168.1.1):", QLineEdit::Normal, "", &ok);
    if (ok && !ip.isEmpty()) {
        logViewer->setTextColor(isMonitoring ? Qt::green : Qt::red);
        logViewer->append("> Blocked IP: " + ip);
    }
}

void IPSGUI::clearLog()
{
    logViewer->clear();
}

void IPSGUI::saveLog() {
    QString logText = logViewer->toPlainText();

    QString fileName = QFileDialog::getSaveFileName(this, "Save Log", QDir::homePath() + "/log_output.txt", "Text Files (*.txt)");
    
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << logText;
            file.close();

            QMessageBox::information(this, "Saved", "Log saved successfully to:\n" + fileName);
        } else {
            QMessageBox::warning(this, "Error", "Failed to save log file.");
        }
    }
}

