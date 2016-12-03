#include "GGClient.h"

#include <QTimer>
#include <iostream>

GGClient::GGClient()
{
    QTimer* timer = new QTimer(this);
    connect( timer, SIGNAL(timeout()), SLOT(output()) );
    timer->start( 1000 );
}

GGClient::~GGClient()
{}

void GGClient::output()
{
    std::cout << "Hello World!" << std::endl;
}

#include "GGClient.moc"
