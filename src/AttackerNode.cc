#include <omnetpp.h>
using namespace omnetpp;

class AttackerNode : public cSimpleModule
{
  private:
    cMessage *attackTimer;
    int attacksSent = 0;
    int attackType = 0;
    
  protected:
    virtual void initialize() override {
        attackTimer = new cMessage("attackTimer");
        scheduleAt(simTime() + par("attackInterval"), attackTimer);
        
        EV << "⚠️ ATTACKER: Malicious node initialized\n";
        EV << "   Will attempt various attacks on the network...\n";
    }
    
    virtual void handleMessage(cMessage *msg) override {
        if (msg == attackTimer) {
            attacksSent++;
            
            // Cycle through different attack types
            attackType = (attackType + 1) % 5;
            
            switch(attackType) {
                case 0:
                    sendUnencryptedPacket();
                    break;
                case 1:
                    sendLowTTLPacket();
                    break;
                case 2:
                    sendSpoofedProtocol();
                    break;
                case 3:
                    sendMalformedPacket();
                    break;
                case 4:
                    sendFloodAttack();
                    break;
            }
            
            // Schedule next attack
            scheduleAt(simTime() + par("attackInterval"), attackTimer);
            
        } else {
            // If we somehow receive a response (shouldn't happen)
            EV << "⚠️ ATTACKER: Unexpectedly received response (attack may have succeeded!)\n";
            delete msg;
        }
    }
    
    void sendUnencryptedPacket() {
        cPacket *pkt = new cPacket("UNENCRYPTED-ATTACK");
        pkt->addPar("encrypted") = false;  // NOT ENCRYPTED!
        pkt->addPar("ttl") = 64;
        pkt->addPar("protocol") = "HTTP";  // Plain HTTP, not HTTPS
        pkt->setByteLength(1024);
        
        send(pkt, "port$o");
        EV << "🔓 ATTACK #" << attacksSent << ": Sent UNENCRYPTED packet (should be blocked)\n";
    }
    
    void sendLowTTLPacket() {
        cPacket *pkt = new cPacket("TTL-ATTACK");
        pkt->addPar("encrypted") = true;
        pkt->addPar("ttl") = 0;  // TTL = 0 (expired!)
        pkt->addPar("protocol") = "HTTPS";
        pkt->setByteLength(512);
        
        send(pkt, "port$o");
        EV << "⏱️ ATTACK #" << attacksSent << ": Sent packet with TTL=0 (should be blocked)\n";
    }
    
    void sendSpoofedProtocol() {
        cPacket *pkt = new cPacket("PROTOCOL-SPOOF");
        pkt->addPar("encrypted") = true;
        pkt->addPar("ttl") = 64;
        pkt->addPar("protocol") = "MALICIOUS";  // Unknown protocol!
        pkt->setByteLength(2048);
        
        send(pkt, "port$o");
        EV << "🎭 ATTACK #" << attacksSent << ": Sent packet with SPOOFED protocol (IDS should detect)\n";
    }
    
    void sendMalformedPacket() {
        cPacket *pkt = new cPacket("MALFORMED-ATTACK");
        // Missing encryption parameter - malformed!
        pkt->addPar("ttl") = 32;
        pkt->setByteLength(512);
        
        send(pkt, "port$o");
        EV << "💀 ATTACK #" << attacksSent << ": Sent MALFORMED packet (missing encryption flag)\n";
    }
    
    void sendFloodAttack() {
        // Send a single unencrypted packet marked as flood
        cPacket *pkt = new cPacket("FLOOD-ATTACK");
        pkt->addPar("encrypted") = false;
        pkt->addPar("ttl") = 64;
        pkt->addPar("protocol") = "FLOOD";
        pkt->setByteLength(256);
        
        send(pkt, "port$o");
        EV << "🌊 ATTACK #" << attacksSent << ": Sent FLOOD attack packet (unencrypted)\n";
    }
    
    virtual void finish() override {
        cancelAndDelete(attackTimer);
        
        EV << "\n=== Attacker Statistics ===\n";
        EV << "Total attacks attempted: " << attacksSent << "\n";
        EV << "Note: All attacks should have been blocked by router!\n";
        
        recordScalar("AttacksAttempted", attacksSent);
    }
};

Define_Module(AttackerNode);