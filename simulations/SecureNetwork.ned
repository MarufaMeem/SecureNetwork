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
        // Beautiful gradient background with soft terrain texture
        @display("bgb=1800,1100;bgi=background/terrain,s;bgg=100;bgs=10");

    submodules:
        // ========== CLIENTS - LEFT SIDE (ROUTER1) ==========
        // Using laptop icons with soft, pleasant colors
        client1_1: SecureClient {
            @display("p=516,194;i=device/laptop,#FFB84D,100;t=💻 Client 1-1nFULL WORKFLOWn→ cisco.com");
            startTime = 0s;
            clientMode = "FULL_WORKFLOW";
            targetDomain = "cisco.com";
        }

        client1_2: SecureClient {
            @display("p=255,273;i=device/laptop,#87CEEB,80;t=💻 Client 1-2nDHCP ONLY");
            startTime = 5s;
            clientMode = "DHCP_ONLY";
        }

        client1_3: SecureClient {
            @display("p=169,507;i=device/laptop,#87CEEB,80;t=💻 Client 1-3nDHCP ONLY");
            startTime = 10s;
            clientMode = "DHCP_ONLY";
        }

        // ========== CLIENTS - LEFT SIDE (ROUTER2) ==========
        client2_1: SecureClient {
            @display("p=255,767;i=device/laptop,#9370DB,100;t=💻 Client 2-1nFULL WORKFLOWn→ omnet.com");
            startTime = 3s;
            clientMode = "FULL_WORKFLOW";
            targetDomain = "omnet.com";
        }

        client2_2: SecureClient {
            @display("p=377,979;i=device/laptop,#87CEEB,80;t=💻 Client 2-2nDHCP ONLY");
            startTime = 15s;
            clientMode = "DHCP_ONLY";
        }

        // ========== ATTACKER NODE ==========
        attacker: AttackerNode {
            @display("p=649,979;i=device/pc,#FF6B6B,90;t=⚠️ ATTACKERn⚡ Malicious Node");
        }

        // ========== ROUTERS (CORE LAYER) ==========
        // Larger, more prominent with teal/cyan/purple gradient colors
        router1: SecureRouter {
            @display("p=650,375;i=abstract/router,#4ECDC4,150;t=🛡️ Router 1\\n10.0.0.1\\nSecure Gateway");
            routerId = 1;
            ipAddress = "10.0.0.1";
        }

        router2: SecureRouter {
            @display("p=650,750;i=abstract/router,#45B7D1,150;t=🛡️ Router 2\\n10.0.0.2\\nSecure Gateway");
            routerId = 2;
            ipAddress = "10.0.0.2";
        }

        router3: SecureRouter {
            @display("p=1100,550;i=abstract/router,#956FFF,180;t=⭐ Router 3 (HUB)\\n10.0.0.3\\nCore Distribution");
            routerId = 3;
            ipAddress = "10.0.0.3";
        }

        // ========== SERVERS - RIGHT SIDE ==========
        // Color-coded by service type with nice pastel/vibrant colors
        dhcpServer: SecureDHCPServer {
            @display("p=1396,194;i=device/server,#FFD93D,120;t=🔧 DHCP Servern192.168.1.10nIP Assignment");
            ipAddress = "192.168.1.10";
        }

        dnsServer: SecureDNSServer {
            @display("p=1594,374;i=device/server,#6BCB77,120;t=🌐 DNS Servern192.168.1.11nName Resolution");
            ipAddress = "192.168.1.11";
        }

        httpServer1: SecureHTTPServer {
            @display("p=1592,672;i=device/server,#4D96FF,120;t=🔒 HTTPS Serverncisco.comn192.168.1.100");
            ipAddress = "192.168.1.100";
            serverName = "cisco.com";
        }

        httpServer2: SecureHTTPServer {
            @display("p=1461,882;i=device/server,#C77DFF,120;t=🔒 HTTPS Servernomnet.comn192.168.1.101");
            ipAddress = "192.168.1.101";
            serverName = "omnet.com";
        }

    connections allowunconnected:
        // ========== ROUTER1 CLIENTS (TEAL/CYAN GRADIENT) ==========
        // Thicker, smoother lines with hex colors
        client1_1.port <--> {  delay = 1ms; datarate = 100Mbps;@display("ls=#4ECDC4,4"); } <--> router1.port++;
        client1_2.port <--> {  delay = 1ms; datarate = 100Mbps;@display("ls=#87CEEB,3"); } <--> router1.port++;
        client1_3.port <--> {  delay = 1ms; datarate = 100Mbps;@display("ls=#87CEEB,3"); } <--> router1.port++;

        // ========== ROUTER2 CLIENTS (BLUE/PURPLE GRADIENT) ==========
        client2_1.port <--> {  delay = 1ms; datarate = 100Mbps;@display("ls=#9370DB,4"); } <--> router2.port++;
        client2_2.port <--> {  delay = 1ms; datarate = 100Mbps;@display("ls=#87CEEB,3"); } <--> router2.port++;
        attacker.port <--> {  delay = 1ms; datarate = 100Mbps;@display("ls=#FF6B6B,3,da"); } <--> router2.port++;

        // ========== ROUTER MESH (THICK GRADIENT BACKBONE) ==========
        // Extra thick lines for the core backbone
        router1.port++ <--> {  delay = 2ms; datarate = 1Gbps;@display("ls=#FFD93D,6"); } <--> router3.port++;
        router2.port++ <--> {  delay = 2ms; datarate = 1Gbps;@display("ls=#45B7D1,6"); } <--> router3.port++;
        router1.port++ <--> {  delay = 2ms; datarate = 1Gbps;@display("ls=#956FFF,5,da"); } <--> router2.port++;

        // ========== SERVERS (COLORED BY SERVICE TYPE) ==========
        // Matching colors with their respective servers
        router3.port++ <--> {  delay = 1ms; datarate = 1Gbps;@display("ls=#FFD93D,4"); } <--> dhcpServer.port;
        router3.port++ <--> {  delay = 1ms; datarate = 1Gbps;@display("ls=#6BCB77,4"); } <--> dnsServer.port;
        router3.port++ <--> {  delay = 1ms; datarate = 1Gbps;@display("ls=#4D96FF,4"); } <--> httpServer1.port;
        router3.port++ <--> {  delay = 1ms; datarate = 1Gbps;@display("ls=#C77DFF,4"); } <--> httpServer2.port;
}
