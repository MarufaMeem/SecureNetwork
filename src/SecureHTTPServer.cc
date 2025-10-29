#include <omnetpp.h>
#include <string>

using namespace omnetpp;

class SecureHTTPServer : public cSimpleModule
{
  private:
    int requestsReceived = 0;
    int requestsRejected = 0;
    int unencryptedBlocked = 0;
    std::string serverName;
    std::string serverIP;

  protected:
    // ============================================================
    // INITIALIZE
    // ============================================================
    virtual void initialize() override {
        serverName = par("serverName").stringValue();
        serverIP = par("ipAddress").stringValue();
        
        EV << "✅ HTTP SERVER: " << serverName << " Initialized (HTTPS-only)\n";
        EV << "   • IP Address: " << serverIP << "\n";
        EV << "   • Encryption required\n";
        EV << "   • Rejecting plain HTTP or OSPF packets\n";

        char label[150];
        sprintf(label, "HTTPS Server\n%s\n%s", serverName.c_str(), serverIP.c_str());
        getDisplayString().setTagArg("t", 0, label);
        getDisplayString().setTagArg("i", 1, "green");
    }

    // ============================================================
    // HANDLE MESSAGE
    // ============================================================
    virtual void handleMessage(cMessage *msg) override {
        cPacket *pkt = check_and_cast<cPacket*>(msg);

        std::string protocol = pkt->hasPar("protocol")
                                   ? pkt->par("protocol").stringValue()
                                   : "UNKNOWN";

        // --- Ignore OSPF updates ---
        if (protocol == "OSPF") {
            EV << "🛈 HTTPS SERVER (" << serverName << "): Ignoring OSPF update packet.\n";
            delete pkt;
            return;
        }

        // --- Only process HTTPS ---
        if (protocol != "HTTPS") {
            requestsRejected++;
            EV << "⚠️ HTTP SERVER (" << serverName << "): Rejected non-HTTPS packet (" << protocol << ")\n";
            delete pkt;
            return;
        }

        // --- Validate encryption ---
        bool encrypted = pkt->hasPar("encrypted") && pkt->par("encrypted").boolValue();
        if (!encrypted) {
            unencryptedBlocked++;
            requestsRejected++;
            EV << "🛑 HTTPS SERVER (" << serverName << "): Dropped unencrypted HTTPS attempt\n";
            delete pkt;
            return;
        }

        // --- Validate target matches this server ---
        std::string targetDomain = pkt->hasPar("targetDomain") 
                                      ? pkt->par("targetDomain").stringValue() 
                                      : "";
        std::string targetIP = pkt->hasPar("targetIP") 
                                 ? pkt->par("targetIP").stringValue() 
                                 : "";

        // Check if request is for this server
        bool isCorrectServer = (targetIP == serverIP) || 
                               (targetDomain.find(serverName) != std::string::npos);

        if (!isCorrectServer && !targetIP.empty()) {
            EV << "⚠️ HTTPS SERVER (" << serverName << "): Request for different server (" 
               << targetDomain << " @ " << targetIP << "), ignoring\n";
            delete pkt;
            return;
        }

        // --- Process HTTPS request ---
        requestsReceived++;

        int clientId = pkt->hasPar("clientId") ? (int)pkt->par("clientId").longValue() : -1;
        int requestId = pkt->hasPar("requestId") ? (int)pkt->par("requestId").longValue() : 0;

        EV << "\n╔════════════════════════════════════════╗\n";
        EV << "║ 🌐 HTTPS REQUEST RECEIVED            ║\n";
        EV << "║ Server: " << serverName << "                    ║\n";
        EV << "║ Client: " << clientId << "                            ║\n";
        EV << "║ Request: #" << requestId << "                        ║\n";
        EV << "║ Domain: " << targetDomain << "              ║\n";
        EV << "╚════════════════════════════════════════╝\n";

        // --- Simulate content delivery ---
        std::string content;
        if (serverName == "cisco.com") {
            content = "Welcome to Cisco - Networking Solutions";
        } else if (serverName == "omnet.com") {
            content = "Welcome to OMNeT++ - Network Simulation";
        } else {
            content = "Welcome to " + serverName;
        }

        // --- Build secure response ---
        cPacket *response = new cPacket("HTTPS-RESPONSE");
        response->addPar("protocol") = "HTTPS";
        response->addPar("encrypted") = true;
        response->addPar("ttl") = 64;
        response->addPar("statusCode") = 200;
        response->addPar("message") = "OK";
        response->addPar("serverName") = serverName.c_str();
        response->addPar("content") = content.c_str();

        if (clientId >= 0)
            response->addPar("clientId") = clientId;

        // Preserve source router path for proper routing
        if (pkt->hasPar("sourceRouter"))
            response->addPar("sourceRouter") = pkt->par("sourceRouter").longValue();
        if (pkt->hasPar("sourceGate"))
            response->addPar("sourceGate") = pkt->par("sourceGate").longValue();

        send(response, "port$o");

        EV << "╔════════════════════════════════════════╗\n";
        EV << "║ ✅ HTTPS RESPONSE SENT                ║\n";
        EV << "║ Status: 200 OK                        ║\n";
        EV << "║ Content: " << content.substr(0, 25) << "... ║\n";
        EV << "╚════════════════════════════════════════╝\n\n";

        delete pkt;
    }

    // ============================================================
    // FINISH
    // ============================================================
    virtual void finish() override {
        EV << "\n=== HTTPS Server (" << serverName << ") Statistics ===\n";
        EV << "   ✅ Accepted HTTPS requests: " << requestsReceived << "\n";
        EV << "   ⚠️  Rejected packets:        " << requestsRejected << "\n";
        EV << "   🛑 Blocked unencrypted:     " << unencryptedBlocked << "\n";

        char scalarName[100];
        sprintf(scalarName, "HTTPS_Accepted_%s", serverName.c_str());
        recordScalar(scalarName, requestsReceived);
        
        sprintf(scalarName, "HTTPS_Rejected_%s", serverName.c_str());
        recordScalar(scalarName, requestsRejected);
    }
};

Define_Module(SecureHTTPServer);