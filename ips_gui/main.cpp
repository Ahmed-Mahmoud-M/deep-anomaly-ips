#include <QApplication>
#include "ipsgui.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    IPSGUI window;
    window.setWindowTitle("IPS/IDS GUI");
    window.resize(400, 400);
    window.show();
    return app.exec();
}
