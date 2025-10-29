package simulations;

// ------------------- SIMPLE MODULES -------------------
simple SecureClient
{
    parameters:
        @display("i=device/pc");
        string ipAddress = default("");
        string macAddress = default("");
        double startTime @unit(s) = default(0s);
        string clientMode = default("DHCP_ONLY"); // FULL_WORKFLOW or DHCP_ONLY
        string targetDomain = default(""); // Domain to resolve (e.g., cisco.com, omnet.com)
    gates:
        inout port;
}

simple SecureRouter
{
    parameters:
        @display("i=abstract/router");
        bool blockUnencrypted = default(true);
        bool ttlCheck = default(true);
        bool idsEnabled = default(true);
        bool ospfEnabled = default(true);
        int routerId;
        string ipAddress = default("");
        double ospfUpdateInterval @unit(s) = default(10s);
    gates:
        inout port[];   // router has vector gates for flexible mesh + services
}

simple AttackerNode
{
    parameters:
        @display("i=device/pc;is=s");
        double attackInterval @unit(s) = default(3s);
    gates:
        inout port;
}

simple SecureDHCPServer
{
    parameters:
        @display("i=device/server");
        string ipAddress = default("192.168.1.10");
    gates:
        inout port;
}

simple SecureDNSServer
{
    parameters:
        @display("i=device/server");
        string ipAddress = default("192.168.1.11");
    gates:
        inout port;
}

simple SecureHTTPServer
{
    parameters:
        @display("i=device/server");
        string ipAddress = default("192.168.1.12");
        string serverName = default("www.example.com");
    gates:
        inout port;
}

// ------------------- NETWORK DEFINITION -------------------
network SecureNetworkProject
{
    parameters:
        @display("bgb=1400,900");

    submodules:
        // ---------- Clients on Router1 ----------
        client1_1: SecureClient {
            @display("p=100,200;i=device/pc,green");
            startTime = 0s;
            clientMode = "FULL_WORKFLOW";
            targetDomain = "cisco.com";
        }
        
        client1_2: SecureClient {
            @display("p=100,350");
            startTime = 5s;
            clientMode = "DHCP_ONLY";
        }
        
        client1_3: SecureClient {
            @display("p=100,500");
            startTime = 10s;
            clientMode = "DHCP_ONLY";
        }

        // ---------- Clients on Router2 ----------
        client2_1: SecureClient {
            @display("p=100,650;i=device/pc,cyan");
            startTime = 3s;
            clientMode = "FULL_WORKFLOW";
            targetDomain = "omnet.com";
        }
        
        client2_2: SecureClient {
            @display("p=100,800");
            startTime = 15s;
            clientMode = "DHCP_ONLY";
        }

        // ---------- Attacker Node ----------
        attacker: AttackerNode {
            @display("p=250,800;i=device/pc,red");
        }

        // ---------- Routers ----------
        router1: SecureRouter {
            @display("p=450,350");
            routerId = 1;
            ipAddress = "10.0.0.1";
        }

        router2: SecureRouter {
            @display("p=450,700");
            routerId = 2;
            ipAddress = "10.0.0.2";
        }

        router3: SecureRouter {
            @display("p=850,500");
            routerId = 3;
            ipAddress = "10.0.0.3";
        }

        // ---------- Servers on Router3 ----------
        dhcpServer: SecureDHCPServer {
            @display("p=1200,300");
            ipAddress = "192.168.1.10";
        }

        dnsServer: SecureDNSServer {
            @display("p=1200,450");
            ipAddress = "192.168.1.11";
        }

        httpServer1: SecureHTTPServer {
            @display("p=1200,550;i=device/server,gold");
            ipAddress = "192.168.1.100";
            serverName = "cisco.com";
        }
        
        httpServer2: SecureHTTPServer {
            @display("p=1200,650;i=device/server,blue");
            ipAddress = "192.168.1.101";
            serverName = "omnet.com";
        }

    connections allowunconnected:
        // ---------- Router1: 3 clients ----------
        client1_1.port <--> {delay=1ms; datarate=100Mbps;} <--> router1.port++;
        client1_2.port <--> {delay=1ms; datarate=100Mbps;} <--> router1.port++;
        client1_3.port <--> {delay=1ms; datarate=100Mbps;} <--> router1.port++;

        // ---------- Router2: 2 clients + attacker ----------
        client2_1.port <--> {delay=1ms; datarate=100Mbps;} <--> router2.port++;
        client2_2.port <--> {delay=1ms; datarate=100Mbps;} <--> router2.port++;
        attacker.port  <--> {delay=1ms; datarate=100Mbps;} <--> router2.port++;

        // ---------- Router mesh ----------
        router1.port++ <--> {delay=2ms; datarate=100Mbps;} <--> router3.port++;
        router2.port++ <--> {delay=2ms; datarate=100Mbps;} <--> router3.port++;
        router1.port++ <--> {delay=2ms; datarate=100Mbps;} <--> router2.port++;

        // ---------- Servers on Router3 ----------
        router3.port++ <--> {delay=1ms; datarate=100Mbps;} <--> dhcpServer.port;   // gate 2
        router3.port++ <--> {delay=1ms; datarate=100Mbps;} <--> dnsServer.port;    // gate 3
        router3.port++ <--> {delay=1ms; datarate=100Mbps;} <--> httpServer1.port;  // gate 4
        router3.port++ <--> {delay=1ms; datarate=100Mbps;} <--> httpServer2.port;  // gate 5
}
