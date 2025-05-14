#include <QApplication>
#include "ipsgui.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    IPSGUI gui;
    gui.show();
    
    return app.exec();
}
