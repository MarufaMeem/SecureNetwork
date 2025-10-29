#include <omnetpp.h>
#include <map>
#include <queue>
#include <string>

using namespace omnetpp;

struct DNSQuery {
    simtime_t timestamp;
    std::string sourceIP;
    int clientId;
};

class SecureDNSServer : public cSimpleModule
{
  private:
    int queriesReceived = 0;
    int queriesBlocked = 0;
    int spoofingAttempts = 0;
    int queriesPerSecond = 0;

    int maxQueriesPerSecond;
    bool rateLimitEnabled;
    bool spoofingProtection;

    std::queue<DNSQuery> recentQueries;
    std::map<std::string, int> queryCountPerIP;
    std::map<std::string, std::string> dnsRecords; // Domain -> IP mapping
    cMessage *rateLimitTimer = nullptr;

  protected:
    // ===============================================================
    // INITIALIZE
    // ===============================================================
    virtual void initialize() override {
        maxQueriesPerSecond = 10;
        rateLimitEnabled = true;
        spoofingProtection = true;

        // Initialize DNS records
        dnsRecords["cisco.com"] = "192.168.1.100";
        dnsRecords["www.cisco.com"] = "192.168.1.100";
        dnsRecords["omnet.com"] = "192.168.1.101";
        dnsRecords["www.omnet.com"] = "192.168.1.101";
        dnsRecords["example.com"] = "93.184.216.34";
        dnsRecords["google.com"] = "142.250.190.14";

        rateLimitTimer = new cMessage("rateLimitReset");
        scheduleAt(simTime() + 1.0, rateLimitTimer);

        EV << "✅ DNS SERVER: Initialized (DNS-over-HTTPS)\n";
        EV << "   • Encryption: ENABLED\n";
        EV << "   • Rate limit: " << maxQueriesPerSecond << " queries/sec\n";
        EV << "   • Spoofing protection: ENABLED\n";
        EV << "   • DNS Records loaded: " << dnsRecords.size() << "\n";
        EV << "     - cisco.com → " << dnsRecords["cisco.com"] << "\n";
        EV << "     - omnet.com → " << dnsRecords["omnet.com"] << "\n";

        const char *ip = par("ipAddress").stringValue();
        char label[100];
        sprintf(label, "DNS Server\n%s", ip);
        getDisplayString().setTagArg("t", 0, label);
        getDisplayString().setTagArg("i", 1, "blue");
    }

    // ===============================================================
    // HANDLE MESSAGE
    // ===============================================================
    virtual void handleMessage(cMessage *msg) override {
        if (msg == rateLimitTimer) {
            resetRateLimits();
            scheduleAt(simTime() + 1.0, rateLimitTimer);
            return;
        }

        cPacket *pkt = check_and_cast<cPacket*>(msg);

        // Ignore OSPF updates
        if (pkt->hasPar("protocol") &&
            strcmp(pkt->par("protocol").stringValue(), "OSPF") == 0) {
            EV << "🛈 DNS SERVER: Ignoring OSPF update packet.\n";
            delete pkt;
            return;
        }

        // Encryption protection
        bool encrypted = pkt->hasPar("encrypted") && pkt->par("encrypted").boolValue();
        if (spoofingProtection && !encrypted) {
            EV << "🛡️ DNS: Blocked unencrypted spoof attempt\n";
            spoofingAttempts++;
            queriesBlocked++;
            delete pkt;
            return;
        }

        // Extract metadata
        int clientId = pkt->hasPar("clientId") ? (int)pkt->par("clientId").longValue() : -1;
        int queryId  = pkt->hasPar("queryId")  ? (int)pkt->par("queryId").longValue()  : 0;
        std::string domain = pkt->hasPar("domain") ? pkt->par("domain").stringValue() : "unknown";
        std::string sourceIP = pkt->hasPar("sourceIP") ? pkt->par("sourceIP").stringValue() : "0.0.0.0";

        // Rate limiting per IP
        if (rateLimitEnabled) {
            queryCountPerIP[sourceIP]++;
            if (queryCountPerIP[sourceIP] > maxQueriesPerSecond) {
                EV << "🚫 DNS: Rate limit exceeded for " << sourceIP << "\n";
                queriesBlocked++;
                delete pkt;
                return;
            }
        }

        queriesReceived++;
        
        EV << "\n┌────────────────────────────────────┐\n";
        EV << "│ 🔍 DNS QUERY #" << queryId << "                   │\n";
        EV << "│ Client: " << clientId << "                       │\n";
        EV << "│ Domain: " << domain << "              │\n";
        EV << "└────────────────────────────────────┘\n";

        // Add to recent queue for monitoring
        DNSQuery entry = {simTime(), sourceIP, clientId};
        recentQueries.push(entry);

        // Resolve domain name
        std::string resolvedIP = "0.0.0.0";
        bool found = false;
        
        if (dnsRecords.count(domain) > 0) {
            resolvedIP = dnsRecords[domain];
            found = true;
        } else {
            // Default fallback for unknown domains
            resolvedIP = "93.184.216.34"; // example.com
        }

        EV << "┌────────────────────────────────────┐\n";
        if (found) {
            EV << "│ ✅ DNS RESOLUTION SUCCESS        │\n";
        } else {
            EV << "│ ⚠️  DNS DEFAULT RESPONSE          │\n";
        }
        EV << "│ " << domain << " → " << resolvedIP << "  │\n";
        EV << "└────────────────────────────────────┘\n\n";

        // Create secure response
        cPacket *response = new cPacket("DNS-RESPONSE");
        response->addPar("protocol") = "DNS";
        response->addPar("encrypted") = true;
        response->addPar("ttl") = 64;
        response->addPar("resolvedIP") = resolvedIP.c_str();
        response->addPar("domain") = domain.c_str();
        response->addPar("verified") = true;
        response->addPar("clientId") = clientId;

        if (pkt->hasPar("sourceRouter"))
            response->addPar("sourceRouter") = pkt->par("sourceRouter").longValue();
        if (pkt->hasPar("sourceGate"))
            response->addPar("sourceGate") = pkt->par("sourceGate").longValue();

        send(response, "port$o");

        EV << "📤 DNS: Sent response to clientId=" << clientId << "\n\n";

        delete pkt;
    }

    // ===============================================================
    // RATE LIMIT RESET
    // ===============================================================
    void resetRateLimits() {
        queryCountPerIP.clear();
        simtime_t cutoff = simTime() - 10.0;
        while (!recentQueries.empty() && recentQueries.front().timestamp < cutoff)
            recentQueries.pop();
        queriesPerSecond = 0;
    }

    // ===============================================================
    // FINISH
    // ===============================================================
    virtual void finish() override {
        cancelAndDelete(rateLimitTimer);

        EV << "\n=== DNS Server Statistics ===\n";
        EV << "Queries received:    " << queriesReceived << "\n";
        EV << "Blocked (rate/spoof):" << queriesBlocked << "\n";
        EV << "Spoofing attempts:   " << spoofingAttempts << "\n";
        EV << "\nDomain Resolution Summary:\n";
        EV << "  cisco.com → " << dnsRecords["cisco.com"] << "\n";
        EV << "  omnet.com → " << dnsRecords["omnet.com"] << "\n";

        recordScalar("QueriesReceived", queriesReceived);
        recordScalar("QueriesBlocked", queriesBlocked);
        recordScalar("SpoofingAttempts", spoofingAttempts);
    }
};

Define_Module(SecureDNSServer);