#ifndef IPSGUI_H
#define IPSGUI_H

#include <QWidget>
#include <QString>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>
#include <QListWidget>

class IPSGUI : public QWidget {
    Q_OBJECT

public:
    IPSGUI(QWidget* parent = nullptr);

private slots:
    void startSystem();
    void stopSystem();
    void setFilter();
    void blockIP();

private:
    bool systemRunning;
    QString currentFilter;
    QList<QString> blockedIPs;

    QLabel* statusLabel;
    QLabel* filterLabel;
    QListWidget* blockedList;
};

#endif // IPSGUI_H
