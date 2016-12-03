#ifndef GGClient_H
#define GGClient_H

#include <QtCore/QObject>

class GGClient : public QObject
{
    Q_OBJECT

public:
    GGClient();
    virtual ~GGClient();

private slots:
    void output();
};

#endif // GGClient_H
