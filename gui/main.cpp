#include <QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName("spu_iso_tool");
    QApplication::setOrganizationName("zecoxao");

    MainWindow w;
    w.show();
    return app.exec();
}
