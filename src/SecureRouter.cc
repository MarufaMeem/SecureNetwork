#include <omnetpp.h>
#include <fstream>
#include <map>
#include <vector>

using namespace omnetpp;

// Global DNS query learning table (clientId → source port)
std::map<int, int> dnsQueryTable;

struct RouteEntry {
    int destRouter;
    int nextHopGate;
    int cost;
};

class SecureRouter : public cSimpleModule
{
  private:
    // Configuration
    bool blockUnencrypted;
    bool ttlCheck;
    bool idsEnabled;
    bool ospfEnabled;
    int routerId;
    double ospfUpdateInterval;

    // Statistics
    int packetsForwarded = 0;
    int packetsDropped = 0;
    int ttlExpired = 0;
    int unencryptedBlocked = 0;
    int ospfUpdatesSent = 0;
    int ospfUpdatesReceived = 0;

    // Routing + learning
    std::map<int, RouteEntry> routingTable;
    std::map<int, int> neighborCosts;
    std::map<std::string, int> dhcpLearnTable; // MAC→port
    std::map<int, int> clientPortTable;        // clientId→port (DNS/HTTPS)
    std::map<int, int> dnsServerChoice;        // clientId→DNS server port

    std::ofstream logFile;
    cMessage *ospfTimer = nullptr;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    void sendOSPFUpdate();
    void handleOSPFUpdate(cPacket *pkt);
    int selectOutputGate(int arrivalGate, const std::string& protocol, cPacket *pkt);
    bool isRouterPort(int gateIndex);
};

Define_Module(SecureRouter);

// ================================================================
// INITIALIZE
// ================================================================
void SecureRouter::initialize() {
    blockUnencrypted   = par("blockUnencrypted");
    ttlCheck           = par("ttlCheck");
    idsEnabled         = par("idsEnabled");
    ospfEnabled        = par("ospfEnabled");
    routerId           = par("routerId");
    ospfUpdateInterval = par("ospfUpdateInterval");

    char filename[50];
    sprintf(filename, "router%d_security.log", routerId);
    logFile.open(filename);
    logFile << "=== Router " << routerId << " Security Log ===\n";
    logFile << "Time,Event,Protocol,Details\n";

    char displayText[100];
    sprintf(displayText, "Router %d\n%s", routerId, par("ipAddress").stringValue());
    getDisplayString().setTagArg("t", 0, displayText);

    EV << "========================================\n";
    EV << "ROUTER " << routerId << ": Secure OSPF Router Initialized\n";
    EV << "  Encryption enforcement: " << (blockUnencrypted ? "ENABLED" : "DISABLED") << "\n";
    EV << "  TTL checking: "        << (ttlCheck ? "ENABLED" : "DISABLED") << "\n";
    EV << "  IDS monitoring: "      << (idsEnabled ? "ENABLED" : "DISABLED") << "\n";
    EV << "  OSPF routing: "        << (ospfEnabled ? "ENABLED" : "DISABLED") << "\n";
    EV << "========================================\n";

    for (int i = 0; i < gateSize("port"); i++)
        neighborCosts[i] = 1;

    if (ospfEnabled) {
        ospfTimer = new cMessage("ospfTimer");
        double initialDelay = 0.05 * routerId;
        scheduleAt(simTime() + initialDelay, ospfTimer);
    }
}

// ================================================================
// Helper: Check if gate connects to another router
// ================================================================
bool SecureRouter::isRouterPort(int gateIndex) {
    // Router 1: ports 3,4 connect to other routers
    // Router 2: ports 3,4 connect to other routers  
    // Router 3: ports 0,1 connect to other routers
    if (routerId == 1 || routerId == 2) {
        return (gateIndex == 3 || gateIndex == 4);
    } else if (routerId == 3) {
        return (gateIndex == 0 || gateIndex == 1);
    }
    return false;
}

// ================================================================
// HANDLE MESSAGE
// ================================================================
void SecureRouter::handleMessage(cMessage *msg) {
    if (msg == ospfTimer) {
        sendOSPFUpdate();
        scheduleAt(simTime() + ospfUpdateInterval, ospfTimer);
        return;
    }

    cPacket *pkt = check_and_cast<cPacket*>(msg);
    int arrivalGate = msg->getArrivalGate()->getIndex();

    // Handle OSPF updates (before other processing)
    if (strcmp(pkt->getName(), "OSPF-UPDATE") == 0) {
        handleOSPFUpdate(pkt);
        return;
    }

    // --- Security checks ---
    if (blockUnencrypted) {
        bool encrypted = pkt->hasPar("encrypted") && pkt->par("encrypted").boolValue();
        if (!encrypted) {
            EV << "🛡️ R" << routerId << ": dropped unencrypted packet\n";
            logFile << simTime() << ",BLOCKED,UNENCRYPTED\n";
            unencryptedBlocked++; packetsDropped++;
            delete pkt; return;
        }
    }

    if (ttlCheck && pkt->hasPar("ttl")) {
        int ttl = (int)pkt->par("ttl").longValue();
        if (--ttl <= 0) {
            EV << "🛡️ R" << routerId << ": TTL expired\n";
            logFile << simTime() << ",TTL_EXPIRED,LOOP\n";
            ttlExpired++; packetsDropped++;
            delete pkt; return;
        }
        pkt->par("ttl") = ttl;
    }

    std::string protocol = pkt->hasPar("protocol") ? pkt->par("protocol").stringValue() : "UNKNOWN";

    // CRITICAL FIX: Tag sourceRouter FIRST for Router 3 before any other processing
    if (routerId == 3 && isRouterPort(arrivalGate) && !pkt->hasPar("sourceRouter")) {
        int srcRouter = -1;
        if (arrivalGate == 0) srcRouter = 1;      // from R1
        else if (arrivalGate == 1) srcRouter = 2; // from R2
        
        if (srcRouter > 0) {
            pkt->addPar("sourceRouter") = srcRouter;
            EV_DEBUG << "R3: Tagged packet from R" << srcRouter << " (gate " << arrivalGate << ")\n";
        }
    }

    // IDS check
    if (idsEnabled && protocol != "HTTPS" && protocol != "DHCP" && protocol != "DNS") {
        EV << "⚠️ R" << routerId << " IDS: Suspicious protocol " << protocol << "\n";
        logFile << simTime() << ",SUSPICIOUS," << protocol << "\n";
    }

    // --- Learning (ONLY for valid protocols from client ports) ---
    if (protocol == "DHCP" && pkt->hasPar("macAddress")) {
        std::string mac = pkt->par("macAddress").stringValue();
        std::string name = pkt->getName();
        if (name.find("DISCOVER") != std::string::npos || name.find("REQUEST") != std::string::npos) {
            // Only learn from client-facing ports (NOT router ports)
            if (!isRouterPort(arrivalGate)) {
                dhcpLearnTable[mac] = arrivalGate;
                EV << "📘 R" << routerId << ": learned DHCP MAC " << mac
                   << " on port " << arrivalGate << "\n";
            }
        }
    }

    // Learn client ports for DNS/HTTPS
    if ((protocol == "DNS" || protocol == "HTTPS") && pkt->hasPar("clientId")) {
        std::string pktName = pkt->getName();
        bool isRequest = pktName.find("REQUEST") != std::string::npos || pktName.find("QUERY") != std::string::npos;
        // Only learn from client ports (0-2 for R1 and R2)
        if (isRequest && !isRouterPort(arrivalGate)) {
            int cid = (int)pkt->par("clientId").longValue();
            clientPortTable[cid] = arrivalGate;
            dnsQueryTable[cid]   = arrivalGate;
            EV << "📗 R" << routerId << ": learned clientId " << cid
               << " on port " << arrivalGate << " (" << protocol << ")\n";
        }
    }

    // Tag source router if arriving from router (for ALL non-DHCP protocols)
    // DHCP tagging happens earlier in DHCP learning section
    if (!pkt->hasPar("sourceRouter") && isRouterPort(arrivalGate) && protocol != "DHCP") {
        // Determine which router sent this based on arrival gate
        int srcRouter = -1;
        if (routerId == 3) {
            if (arrivalGate == 0) srcRouter = 1;      // from R1
            else if (arrivalGate == 1) srcRouter = 2; // from R2
        } else if (routerId == 1) {
            if (arrivalGate == 3) srcRouter = 3;      // from R3
            else if (arrivalGate == 4) srcRouter = 2; // from R2
        } else if (routerId == 2) {
            if (arrivalGate == 3) srcRouter = 3;      // from R3
            else if (arrivalGate == 4) srcRouter = 1; // from R1
        }
        
        if (srcRouter > 0) {
            pkt->addPar("sourceRouter") = srcRouter;
        }
    }

    // --- Routing decision ---
    int outGate = selectOutputGate(arrivalGate, protocol, pkt);

    if (outGate >= 0 && outGate < gateSize("port")) {
        EV << "📡 R" << routerId << ": " << protocol
           << " [" << arrivalGate << "→" << outGate << "]\n";
        send(pkt, "port$o", outGate);
        packetsForwarded++;
    } else {
        EV << "⚠️ R" << routerId << ": no valid route for " << protocol << "\n";
        packetsDropped++;
        delete pkt;
    }
}

// ================================================================
// ROUTING LOGIC
// ================================================================
// =====================================================
// Enhanced routing rules for SecureNetworkProject
// =====================================================
int SecureRouter::selectOutputGate(int arrivalGate, const std::string& protocol, cPacket *pkt)
{
    // --- 1️⃣ Client-to-client data forwarding ---
    if (protocol == "DATA") {
        if (routerId == 1) return 4;   // R1 → R2
        if (routerId == 2) return 3;   // R2 → R3
        if (routerId == 3) return 0;   // R3 → final subnet/server
    }

    // --- 2️⃣ DHCP and DNS always route toward server (R3) ---
    if (protocol == "DHCP" || protocol == "DNS") {
        if (routerId == 1) return 3;
        if (routerId == 2) return 3;
        if (routerId == 3) return 2;
    }

    // --- 3️⃣ HTTPS routing toward servers ---
    if (protocol == "HTTPS") {
        if (routerId == 1) return 4;   // R1 → R2
        if (routerId == 2) return 3;   // R2 → R3
        if (routerId == 3) return 2;   // R3 → servers
    }

    // --- 4️⃣ Default OSPF or unknown protocol handling ---
    if (protocol == "OSPF")
        return (routerId % 3); // cycle connections for demonstration

    // --- Fallback: broadcast to all except arrivalGate ---
    for (int i = 0; i < gateSize("port$o"); i++) {
        if (i != arrivalGate)
            return i;
    }

    return -1; // drop if no valid gate found
}

// ================================================================
// OSPF UPDATE - FIXED: Only send to router ports
// ================================================================
void SecureRouter::sendOSPFUpdate() {
    cPacket *ospf = new cPacket("OSPF-UPDATE");
    ospf->addPar("routerId") = routerId;
    ospf->addPar("encrypted") = true;
    ospf->addPar("timestamp") = simTime().dbl();
    ospf->setByteLength(64);

    // CRITICAL FIX: Only send OSPF to router-facing ports
    for (int i = 0; i < gateSize("port"); i++) {
        if (gate("port$o", i)->isConnected() && isRouterPort(i)) {
            send(ospf->dup(), "port$o", i);
        }
    }

    delete ospf;
    ospfUpdatesSent++;
    EV << "📢 R" << routerId << ": sent OSPF update\n";
}

// ================================================================
// HANDLE OSPF
// ================================================================
void SecureRouter::handleOSPFUpdate(cPacket *pkt) {
    int senderId = pkt->hasPar("routerId") ? (int)pkt->par("routerId").longValue() : -1;
    ospfUpdatesReceived++;
    EV << "📥 R" << routerId << ": received OSPF update from R" << senderId << "\n";
    logFile << simTime() << ",OSPF_UPDATE,ROUTING,From R" << senderId << "\n";
    delete pkt;
}

// ================================================================
// FINISH
// ================================================================
void SecureRouter::finish() {
    if (ospfEnabled) cancelAndDelete(ospfTimer);
    EV << "\n========================================\n";
    EV << "ROUTER " << routerId << " Final Statistics\n";
    EV << "  Packets forwarded: " << packetsForwarded << "\n";
    EV << "  Packets dropped: "   << packetsDropped   << "\n";
    EV << "  OSPF updates sent: " << ospfUpdatesSent << "\n";
    EV << "========================================\n";

    logFile << "\nForwarded: " << packetsForwarded << "\nDropped: " << packetsDropped << "\n";
    logFile.close();

    char scalarName[50];
    sprintf(scalarName, "Router%d_Forwarded", routerId);
    recordScalar(scalarName, packetsForwarded);
}