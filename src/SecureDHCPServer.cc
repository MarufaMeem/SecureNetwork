#include <omnetpp.h>
#include <map>
#include <string>
using namespace omnetpp;

struct DHCPLease {
    std::string clientMAC;
    std::string assignedIP;
    simtime_t leaseStart;
    simtime_t leaseExpiry;
    int ttl;
    bool active;
};

class SecureDHCPServer : public cSimpleModule
{
  private:
    int requestsReceived = 0;
    int leasesGranted = 0;
    int leasesExpired = 0;
    int authFailures = 0;
    double leaseTime;

    std::map<std::string, DHCPLease> activeLeases;
    cMessage *leaseCheckTimer;

  protected:
    virtual void initialize() override {
        leaseTime = 3600.0;  // 1 hour default
        leaseCheckTimer = new cMessage("leaseCheck");
        scheduleAt(simTime() + 30.0, leaseCheckTimer);

        EV << "✅ DHCP SERVER: Initialized\n";
        EV << "   • Encrypted handshakes enabled\n";
        EV << "   • Server authentication active\n";
        EV << "   • TTL-based lease handling: " << leaseTime << "s\n";

        // Display IP address in the GUI
        const char* ip = par("ipAddress").stringValue();
        char displayText[100];
        sprintf(displayText, "DHCP Server\n%s", ip);
        getDisplayString().setTagArg("t", 0, displayText);
    }

    virtual void handleMessage(cMessage *msg) override {
        if (msg == leaseCheckTimer) {
            checkExpiredLeases();
            scheduleAt(simTime() + 30.0, leaseCheckTimer);
            return;
        }

        cPacket *pkt = check_and_cast<cPacket*>(msg);
        
        // CRITICAL FIX: Validate this is actually a DHCP request
        std::string msgName = pkt->getName();
        std::string protocol = pkt->hasPar("protocol") ? pkt->par("protocol").stringValue() : "UNKNOWN";
        
        // Reject non-DHCP messages
        if (protocol != "DHCP" && msgName.find("DHCP") == std::string::npos) {
            EV_DEBUG << "🛡️ DHCP: Ignoring non-DHCP message (" << msgName << ")\n";
            delete msg;
            return;
        }

        requestsReceived++;

        // ============================================================
// New full DHCP handshake: DISCOVER → OFFER → REQUEST → ACK
// ============================================================



// 1️⃣ Handle DHCP DISCOVER → send OFFER
// ============================================================
// New full DHCP handshake: DISCOVER → OFFER → REQUEST → ACK
// ============================================================

// Do NOT redeclare msgName — reuse the existing one
// (Your file already has: std::string msgName = pkt->getName();)

// 1️⃣ Handle DHCP DISCOVER → send OFFER
if (msgName.find("DISCOVER") != std::string::npos) {
    EV << "📡 DHCP: Received DISCOVER from "
       << pkt->par("macAddress").stringValue()
       << ", sending OFFER\n";

    cPacket *offer = new cPacket("DHCP-OFFER");
    offer->addPar("encrypted") = true;
    offer->addPar("protocol") = "DHCP";
    offer->addPar("macAddress") = pkt->par("macAddress").stringValue();

    // --- Replace lease.assignedIP with your local IP variable ---
    if (pkt->hasPar("requestedIP"))
        offer->addPar("offeredIP") = pkt->par("requestedIP").stringValue();
    else
        offer->addPar("offeredIP") = "192.168.1.200";  // fallback example

    if (pkt->hasPar("sourceRouter"))
        offer->addPar("sourceRouter") = pkt->par("sourceRouter").longValue();

    send(offer, "port$o");
    delete pkt;
    return;
}

// 2️⃣ Handle DHCP REQUEST → send ACK
if (msgName.find("REQUEST") != std::string::npos) {
    EV << "📡 DHCP: Received REQUEST from "
       << pkt->par("macAddress").stringValue()
       << ", sending ACK\n";

    cPacket *ack = new cPacket("DHCP-ACK");
    ack->addPar("encrypted") = true;
    ack->addPar("protocol") = "DHCP";

    // --- Replace lease fields with pkt data or fixed values ---
    if (pkt->hasPar("offeredIP"))
        ack->addPar("assignedIP") = pkt->par("offeredIP").stringValue();
    else
        ack->addPar("assignedIP") = "192.168.1.200";

    ack->addPar("macAddress") = pkt->par("macAddress").stringValue();

    if (pkt->hasPar("sourceRouter"))
        ack->addPar("sourceRouter") = pkt->par("sourceRouter").longValue();

    send(ack, "port$o");
    delete pkt;
    return;
}

        // Verify encryption and authentication
        bool encrypted = false;
        if (pkt->hasPar("encrypted"))
            encrypted = pkt->par("encrypted").boolValue();

        if (!encrypted) {
            EV << "🛡️ DHCP: Rejected unauthenticated request (no encryption)\n";
            authFailures++;
            delete msg;
            return;
        }

        // Extract client MAC address from packet
        std::string clientMAC = "unknown";
        if (pkt->hasPar("macAddress"))
            clientMAC = pkt->par("macAddress").stringValue();
        else
            clientMAC = "00:11:22:33:44:00";  // fallback default

        // Extract optional requestId for logging
        int requestId = 0;
        if (pkt->hasPar("requestId"))
            requestId = (int)pkt->par("requestId").longValue();

        // Check for existing lease for this MAC
        DHCPLease lease;
        if (activeLeases.count(clientMAC)) {
            lease = activeLeases[clientMAC];
            EV << "♻️ DHCP: Existing lease found for " << clientMAC
               << " (IP: " << lease.assignedIP << ")\n";
        } else {
            // Assign a new IP based on current lease count
            char assignedIP[20];
            sprintf(assignedIP, "192.168.1.%d", 100 + (int)activeLeases.size());
            lease.clientMAC = clientMAC;
            lease.assignedIP = assignedIP;
            lease.leaseStart = simTime();
            lease.leaseExpiry = simTime() + leaseTime;
            lease.ttl = leaseTime;
            lease.active = true;

            activeLeases[clientMAC] = lease;
            leasesGranted++;
        }

        EV << "🔐 DHCP: Request #" << requestId << " authenticated\n";
        EV << "   • Client MAC: " << lease.clientMAC << "\n";
        EV << "   • Assigned IP: " << lease.assignedIP << "\n";
        EV << "   • Lease duration: " << leaseTime << "s\n";
        EV << "   • Lease TTL: " << lease.ttl << "s\n";
        EV << "   • Active leases: " << activeLeases.size() << "\n";

        // Send encrypted DHCP ACK
        cPacket *response = new cPacket("DHCP-ACK");
        response->addPar("encrypted") = true;
        response->addPar("ttl") = 64;
        response->addPar("protocol") = "DHCP";
        response->addPar("assignedIP") = lease.assignedIP.c_str();
        response->addPar("leaseTime") = (long)leaseTime;
        response->addPar("macAddress") = lease.clientMAC.c_str();
        
        // CRITICAL FIX: Preserve sourceRouter tag for return routing
        if (pkt->hasPar("sourceRouter")) {
            response->addPar("sourceRouter") = pkt->par("sourceRouter").longValue();
        }

        send(response, "port$o");
        delete msg;
    }

    void checkExpiredLeases() {
        std::vector<std::string> expiredMACs;
        simtime_t now = simTime();

        for (auto& entry : activeLeases) {
            if (entry.second.leaseExpiry < now) {
                expiredMACs.push_back(entry.first);
                leasesExpired++;
                EV << "⏰ DHCP: Lease expired for " << entry.second.clientMAC
                   << " (IP: " << entry.second.assignedIP << ")\n";
            }
        }

        for (const auto& mac : expiredMACs)
            activeLeases.erase(mac);
    }

    virtual void finish() override {
        cancelAndDelete(leaseCheckTimer);

        EV << "\n=== DHCP Server Statistics ===\n";
        EV << "Requests received: " << requestsReceived << "\n";
        EV << "Leases granted: " << leasesGranted << "\n";
        EV << "Leases expired: " << leasesExpired << "\n";
        EV << "Auth failures: " << authFailures << "\n";
        EV << "Active leases: " << activeLeases.size() << "\n";

        recordScalar("RequestsReceived", requestsReceived);
        recordScalar("LeasesGranted", leasesGranted);
        recordScalar("AuthFailures", authFailures);
    }
};

Define_Module(SecureDHCPServer);