#include <omnetpp.h>
using namespace omnetpp;

class SecureServer : public cSimpleModule
{
  private:
    int received;
    
  protected:
    virtual void initialize() override {
        received = 0;
        EV << "SERVER: Ready (HTTPS-only)\n";
    }
    
    virtual void handleMessage(cMessage *msg) override {
        received++;
        
        cPacket *pkt = check_and_cast<cPacket*>(msg);
        int id = pkt->par("id").longValue();
        
        EV << "SERVER: Received packet #" << id << " (Total: " << received << ")\n";
        
        cPacket *response = new cPacket("Response");
        response->addPar("encrypted") = true;
        send(response, "port$o");
        
        delete msg;
    }
    
    virtual void finish() override {
        EV << "SERVER: Total received=" << received << "\n";
    }
};

Define_Module(SecureServer);