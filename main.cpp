#include <QCoreApplication>
#include "GGClient.h"


int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    GGClient ggclient;
    return app.exec();
}
