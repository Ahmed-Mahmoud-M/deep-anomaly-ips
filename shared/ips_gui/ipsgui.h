#include <QTextEdit>
#include <QPushButton>
#include <QFile>
#include <QTextStream>
#include <QWidget>

class IPSGUI : public QWidget {
    Q_OBJECT

public:
    IPSGUI(QWidget *parent = nullptr);

private slots:
    void startMonitoring();
    void stopMonitoring();
    void setFilter();
    void blockIP();
    void clearLog();
    void saveLog();

private:
    void setupUI();

    QTextEdit *logViewer;
    QPushButton *startButton;
    QPushButton *stopButton;
    QPushButton *setFilterButton;
    QPushButton *blockIPButton;
    QPushButton *clearLogButton;
    QPushButton *saveButton;  
    bool isMonitoring;
};
