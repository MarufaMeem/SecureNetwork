#include <omnetpp.h>
#include <cstring>
#include <string>

using namespace omnetpp;

// ================================================================
// Helper function declarations
// ================================================================
cPacket *encryptDhcpRequest(int clientId, const char *mac);
cPacket *createEncryptedDnsQuery(int clientId, int queryId, const char *domain);
cPacket *createEncryptedHttpsRequest(int clientId, int requestId, const char *targetIP, const char *domain);

// ================================================================
// SecureClient module
// ================================================================
class SecureClient : public cSimpleModule {
  private:
    enum WorkflowStage {
        WAITING,
        DHCP_STAGE,
        DNS_STAGE,
        HTTPS_STAGE,
        COMPLETED_STAGE,
        P2P_STAGE
    };

    enum ClientMode {
        DHCP_ONLY,
        FULL_WORKFLOW
    };

    cMessage *dhcpTimer = nullptr;
    cMessage *dnsTimer = nullptr;
    cMessage *httpTimer = nullptr;
    cMessage *startupTimer = nullptr;
    cMessage *p2pTimer = nullptr;

    int dhcpRequests = 0;
    int dnsQueries = 0;
    int httpRequests = 0;
    int p2pMessagesSent = 0;
    int p2pMessagesReceived = 0;
    std::string assignedIP = "DHCP...";
    bool hasIP = false;
    double startTime = 0;
    std::string macAddress;
    std::string targetDomain;
    std::string resolvedIP;
    ClientMode mode;
    std::string clientName;  // Store the logical client name

    WorkflowStage stage = WAITING;

    void transitionToStage(WorkflowStage newStage);
    void scheduleDnsQuery(simtime_t delay);
    void scheduleHttpRequest(simtime_t delay);
   

  protected:
    virtual void initialize() override {
        const double workflowLead = 0.5;
        startTime = par("startTime").doubleValue() + workflowLead;
        macAddress = par("macAddress").stringValue();
        targetDomain = par("targetDomain").stringValue();
        
        // Extract logical client name from module name (e.g., "client1_1" -> "Client 1-1")
        std::string moduleName = getName();
        if (moduleName.find("client") == 0) {
            // Parse "client1_1" format
            size_t underscore = moduleName.find('_');
            if (underscore != std::string::npos) {
                std::string part1 = moduleName.substr(6, underscore - 6);  // Skip "client"
                std::string part2 = moduleName.substr(underscore + 1);
                clientName = "Client " + part1 + "-" + part2;
            } else {
                clientName = "Client";
            }
        } else {
            clientName = moduleName;
        }
        
        // Determine client mode
        std::string modeStr = par("clientMode").stringValue();
        if (modeStr == "FULL_WORKFLOW") {
            mode = FULL_WORKFLOW;
        } else {
            mode = DHCP_ONLY;
        }

        startupTimer = new cMessage("startup");
        scheduleAt(simTime() + startTime, startupTimer);

        updateDisplay();

        if (mode == FULL_WORKFLOW) {
            EV << "✅ " << clientName << " [ID=" << getId() << "]: FULL_WORKFLOW mode - Target: " << targetDomain << "\n";
        } else {
            EV << "✅ " << clientName << " [ID=" << getId() << "]: DHCP_ONLY mode\n";
        }
        
        if (startTime > 0)
            EV << "   Will start at t=" << startTime << "s\n";
    }

    virtual void handleMessage(cMessage *msg) override {
        if (msg == startupTimer) {
            EV << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
            EV << clientName << " [ID=" << getId() << "]: JOINING NETWORK\n";
            if (mode == FULL_WORKFLOW) {
                EV << "   Mode: FULL_WORKFLOW (DNS + HTTP)\n";
                EV << "   Target: " << targetDomain << "\n";
            } else {
                EV << "   Mode: DHCP_ONLY\n";
            }
            EV << "   Requesting IP from DHCP...\n";
            EV << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

            if (!dhcpTimer) dhcpTimer = new cMessage("dhcpTimer");
            if (!dnsTimer)   dnsTimer  = new cMessage("dnsTimer");
            if (!httpTimer)  httpTimer = new cMessage("httpTimer");
            if (!p2pTimer)   p2pTimer  = new cMessage("p2pTimer");

            transitionToStage(DHCP_STAGE);
            scheduleAt(simTime() + uniform(0.1, 0.5), dhcpTimer);
            return;
        }

        if (msg == dhcpTimer) {
            if (stage != DHCP_STAGE) return;

            if (dhcpRequests == 0) {
                EV_INFO << "CLIENT[" << getId() << "]: Sending DHCP-DISCOVER\n";
                cPacket *disc = new cPacket("DHCP-DISCOVER");
                disc->addPar("encrypted") = true;
                disc->addPar("protocol") = "DHCP";
                disc->addPar("macAddress") = macAddress.c_str();
                send(disc, "port$o");
            } else {
                EV_INFO << "CLIENT[" << getId() << "]: Sending DHCP-REQUEST\n";
                cPacket *req = new cPacket("DHCP-REQUEST");
                req->addPar("encrypted") = true;
                req->addPar("protocol") = "DHCP";
                req->addPar("macAddress") = macAddress.c_str();
                send(req, "port$o");
            }

            dhcpRequests++;
            scheduleAt(simTime() + 3.0, dhcpTimer);
            return;
        }

        if (msg == dnsTimer) {
            if (stage != DNS_STAGE || mode != FULL_WORKFLOW) return;

            dnsQueries++;
            EV_INFO << "CLIENT[" << getId() << "]: 🔍 Resolving domain: " << targetDomain << "\n";
            send(createEncryptedDnsQuery(getId(), dnsQueries, targetDomain.c_str()), "port$o");
            updateDisplay();
            return;
        }

        if (msg == httpTimer) {
            if (stage != HTTPS_STAGE || mode != FULL_WORKFLOW) return;
            if (!hasIP || resolvedIP.empty()) {
                scheduleHttpRequest(1.0);
                return;
            }

            httpRequests++;
            EV_INFO << "CLIENT[" << getId() << "]: 🌐 Accessing " << targetDomain 
                    << " at " << resolvedIP << "\n";
            send(createEncryptedHttpsRequest(getId(), httpRequests, resolvedIP.c_str(), targetDomain.c_str()), "port$o");
            updateDisplay();
            return;
        }

        // P2P Timer - for client1_1 to send message to client2_1
        if (msg == p2pTimer) {
            if (getId() == 2) {  // client1_1
                // Send P2P message to client2_1 (clientId=5)
                sendP2PMessage(5, "Hello from client1_1!");
                EV << "CLIENT[" << getId() << "]: 💬 Sent P2P message to CLIENT[5]\n";
            }
            return;
        }

        // Handle received packets
        cPacket *pkt = check_and_cast<cPacket*>(msg);
        std::string msgName = pkt->getName();
        std::string protocol = pkt->hasPar("protocol") ? pkt->par("protocol").stringValue() : "UNKNOWN";

        // Ignore OSPF updates
        if (msgName.find("OSPF") != std::string::npos || protocol == "OSPF") {
            EV_DEBUG << "CLIENT[" << getId() << "]: Ignoring OSPF routing message\n";
            delete pkt;
            return;
        }
        
        // Handle P2P messages
        if (protocol == "P2P") {
            p2pMessagesReceived++;
            int srcClientId = pkt->hasPar("srcClientId") ? (int)pkt->par("srcClientId").longValue() : -1;
            std::string message = pkt->hasPar("message") ? pkt->par("message").stringValue() : "";
            
            EV << "\n╔══════════════════════════════════════╗\n";
            EV << "║ CLIENT[" << getId() << "]: P2P MESSAGE RECEIVED ║\n";
            EV << "║ From: CLIENT[" << srcClientId << "]                    ║\n";
            EV << "║ Message: " << message.substr(0, 20) << "║\n";
            EV << "╚══════════════════════════════════════╝\n\n";
            
            // Send acknowledgment back
            if (getId() == 5) {  // client2_1 replies to client1_1
                scheduleAt(simTime() + 0.5, p2pTimer);
            }
            
            delete pkt;
            return;
        }
        
        if (msgName == "DHCP-OFFER") {
            EV << "CLIENT[" << getId() << "]: Received DHCP-OFFER, sending DHCP-REQUEST\n";
            cPacket *req = new cPacket("DHCP-REQUEST");
            req->addPar("encrypted") = true;
            req->addPar("protocol") = "DHCP";
            req->addPar("macAddress") = macAddress.c_str();
            
            // Copy the offered IP to request
            if (pkt->hasPar("offeredIP")) {
                req->addPar("offeredIP") = pkt->par("offeredIP").stringValue();
            }
            
            send(req, "port$o");
            delete pkt;
            return;
        }

        // DHCP Response handling
        if (msgName == "DHCP-ACK" && protocol == "DHCP" && !hasIP) {
            if (pkt->hasPar("assignedIP")) {
                assignedIP = pkt->par("assignedIP").stringValue();
                hasIP = true;

                EV << "\n╔══════════════════════════════════════╗\n";
                EV << "║ CLIENT[" << getId() << "]: IP ASSIGNED: " << assignedIP << " ║\n";
                EV << "╚══════════════════════════════════════╝\n\n";
                
                if (dhcpTimer && dhcpTimer->isScheduled())
                    cancelEvent(dhcpTimer);

                if (mode == FULL_WORKFLOW) {
                    transitionToStage(DNS_STAGE);
                    scheduleDnsQuery(0.5);
                } else {
                    transitionToStage(COMPLETED_STAGE);
                    EV << "CLIENT[" << getId() << "]: ✅ DHCP_ONLY mode complete\n";
                }
            }
        }
        // DNS Response handling
        else if (msgName == "DNS-RESPONSE" && protocol == "DNS") {
            if (stage == DNS_STAGE && pkt->hasPar("resolvedIP")) {
                resolvedIP = pkt->par("resolvedIP").stringValue();
                std::string domain = pkt->hasPar("domain") ? pkt->par("domain").stringValue() : targetDomain;
                
                EV << "\n╔══════════════════════════════════════╗\n";
                EV << "║ CLIENT[" << getId() << "]: DNS RESOLVED        ║\n";
                EV << "║ " << domain << " → " << resolvedIP << "    ║\n";
                EV << "╚══════════════════════════════════════╝\n\n";
                
                transitionToStage(HTTPS_STAGE);
                scheduleHttpRequest(0.5);
            }
        }
        // HTTPS Response handling
        else if (msgName == "HTTPS-RESPONSE" && protocol == "HTTPS") {
            if (stage == HTTPS_STAGE) {
                std::string serverName = pkt->hasPar("serverName") ? pkt->par("serverName").stringValue() : targetDomain;
                int statusCode = pkt->hasPar("statusCode") ? (int)pkt->par("statusCode").longValue() : 200;
                
                EV << "\n╔══════════════════════════════════════╗\n";
                EV << "║ CLIENT[" << getId() << "]: HTTPS SUCCESS      ║\n";
                EV << "║ Server: " << serverName << "             ║\n";
                EV << "║ Status: " << statusCode << " OK                  ║\n";
                EV << "╚══════════════════════════════════════╝\n\n";
                
                transitionToStage(COMPLETED_STAGE);
                
                // ✅ NEW: Start P2P communication after HTTP completes
                // Client1_1 waits a bit longer to ensure client2_1 is also done
                if (getId() == 2) {  // client1_1
                    EV << "CLIENT[" << getId() << "]: ⏳ Waiting for peer to complete...\n";
                    scheduleAt(simTime() + 3.5, p2pTimer);  // Wait ~3.5s for client2_1 to finish
                }
            }
        }
        else {
            EV_DEBUG << "CLIENT[" << getId() << "]: Ignoring message '" 
                     << msgName << "' with protocol '" << protocol << "'\n";
        }

        updateDisplay();
        delete pkt;
    }

    void sendP2PMessage(int destClientId, const std::string& message) {
        p2pMessagesSent++;
        
        cPacket *pkt = new cPacket("P2P-MESSAGE");
        pkt->addPar("protocol") = "P2P";
        pkt->addPar("encrypted") = true;
        pkt->addPar("ttl") = 64;
        pkt->addPar("srcClientId") = getId();
        pkt->addPar("destClientId") = destClientId;
        pkt->addPar("message") = message.c_str();
        pkt->setByteLength(512);
        
        send(pkt, "port$o");
    }

    void updateDisplay() {
        const char *color = "grey";
        std::string stageLabel;

        switch (stage) {
            case WAITING: {
                bool scheduledStart = startTime > simTime().dbl();
                stageLabel = scheduledStart ? "Waiting" : "Waiting";
                color = "grey";
                break;
            }
            case DHCP_STAGE:
                stageLabel = "DHCP";
                color = "yellow";
                break;
            case DNS_STAGE:
                stageLabel = "DNS (" + targetDomain + ")";
                color = "cyan";
                break;
            case HTTPS_STAGE:
                stageLabel = "HTTPS (" + targetDomain + ")";
                color = "orange";
                break;
            case P2P_STAGE:
                stageLabel = "P2P Communication";
                color = "blue";
                break;
            case COMPLETED_STAGE:
                if (mode == FULL_WORKFLOW) {
                    if (p2pMessagesSent > 0 || p2pMessagesReceived > 0) {
                        stageLabel = "✓ Complete + P2P";
                    } else {
                        stageLabel = "✓ Complete";
                    }
                    color = "green";
                } else {
                    stageLabel = "✓ DHCP Only";
                    color = "green";
                }
                break;
        }

        char buf[200];
        if (hasIP && mode == FULL_WORKFLOW) {
            sprintf(buf, "%s\n%s\nIP: %s\n→ %s", clientName.c_str(), stageLabel.c_str(), 
                    assignedIP.c_str(), targetDomain.c_str());
        } else if (hasIP) {
            sprintf(buf, "%s\n%s\nIP: %s", clientName.c_str(), stageLabel.c_str(), assignedIP.c_str());
        } else {
            sprintf(buf, "%s\n%s", clientName.c_str(), stageLabel.c_str());
        }

        getDisplayString().setTagArg("t", 0, buf);
        getDisplayString().setTagArg("i", 1, color);
    }

    virtual void finish() override {
        if (startupTimer) cancelAndDelete(startupTimer);
        if (dhcpTimer) cancelAndDelete(dhcpTimer);
        if (dnsTimer) cancelAndDelete(dnsTimer);
        if (httpTimer) cancelAndDelete(httpTimer);
        if (p2pTimer) cancelAndDelete(p2pTimer);

        EV << "\n=== " << clientName << " [ID=" << getId() << "] Final Stats ===\n";
        EV << "Mode: " << (mode == FULL_WORKFLOW ? "FULL_WORKFLOW" : "DHCP_ONLY") << "\n";
        EV << "IP: " << assignedIP << "\n";
        if (mode == FULL_WORKFLOW) {
            EV << "Target: " << targetDomain << " → " << resolvedIP << "\n";
            EV << "DNS queries: " << dnsQueries << " | HTTPS requests: " << httpRequests << "\n";
            EV << "P2P messages sent: " << p2pMessagesSent << " | received: " << p2pMessagesReceived << "\n";
        }
        EV << "DHCP requests: " << dhcpRequests << "\n";
        
        recordScalar("P2P_MessagesSent", p2pMessagesSent);
        recordScalar("P2P_MessagesReceived", p2pMessagesReceived);
    }
};

Define_Module(SecureClient);

// ================================================================
// Member function definitions
// ================================================================
void SecureClient::transitionToStage(WorkflowStage newStage) {
    stage = newStage;
    updateDisplay();
}

void SecureClient::scheduleDnsQuery(simtime_t delay) {
    if (!dnsTimer) return;
    if (dnsTimer->isScheduled())
        cancelEvent(dnsTimer);
    scheduleAt(simTime() + delay, dnsTimer);
}

void SecureClient::scheduleHttpRequest(simtime_t delay) {
    if (!httpTimer) return;
    if (httpTimer->isScheduled())
        cancelEvent(httpTimer);
    scheduleAt(simTime() + delay, httpTimer);
}

// ================================================================
// Helper function definitions
// ================================================================
cPacket *encryptDhcpRequest(int clientId, const char *mac) {
    cPacket *pkt = new cPacket("DHCP-DISCOVER");
    pkt->addPar("encrypted") = true;
    pkt->addPar("ttl") = 64;
    pkt->addPar("protocol") = "DHCP";
    pkt->addPar("clientId") = clientId;
    pkt->addPar("macAddress") = mac;
    return pkt;
}

cPacket *createEncryptedDnsQuery(int clientId, int queryId, const char *domain) {
    cPacket *pkt = new cPacket("DNS-QUERY");
    pkt->addPar("encrypted") = true;
    pkt->addPar("ttl") = 64;
    pkt->addPar("protocol") = "DNS";
    pkt->addPar("clientId") = clientId;
    pkt->addPar("queryId") = queryId;
    pkt->addPar("domain") = domain;
    pkt->setByteLength(256);
    return pkt;
}

cPacket *createEncryptedHttpsRequest(int clientId, int requestId, const char *targetIP, const char *domain) {
    cPacket *pkt = new cPacket("HTTPS-REQUEST");
    pkt->addPar("encrypted") = true;
    pkt->addPar("ttl") = 64;
    pkt->addPar("protocol") = "HTTPS";
    pkt->addPar("clientId") = clientId;
    pkt->addPar("requestId") = requestId;
    pkt->addPar("targetIP") = targetIP;
    pkt->addPar("targetDomain") = domain;
    pkt->setByteLength(1024);
    return pkt;
}