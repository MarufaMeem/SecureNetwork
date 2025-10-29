# NetSentinel Enterprise Defense Simulator

NetSentinel is a teaching project for OMNeT++ 6.2. It shows how a small office network can stay secure even when an attacker is on the wire. Three routers sit between everyday clients and core services, and every hop insists on encrypted traffic. An attacker module keeps throwing bad packets at the network so you can watch the defenses respond.

## Main Pieces
- **Secure routers** (`src/SecureRouter.cc`) check packet encryption, drop expired TTLs, trade encrypted OSPF routes, and write simple CSV logs such as `router1_security.log`.
- **Client workflow** (`src/SecureClient.cc`) requests an IP address, resolves a name, and fetches a web page, all over encrypted channels.
- **Core services** (`src/SecureDHCPServer.cc`, `src/SecureDNSServer.cc`, `src/SecureHTTPServer.cc`) only accept secure requests and record basic counters.
- **Attacker node** (`src/AttackerNode.cc`) sends five easy-to-understand attacks (unencrypted traffic, low TTL, spoofing, malformed packets, flood) so you can test what happens.
- **Network layout** (`src/simulations/SecureNetwork.ned`) wires together five clients, three routers, an attacker, and the secure servers inside a clear diagram.

## How It Plays Out
1. Clients power up at staggered times.
2. Each client gets a DHCP lease, asks DNS-over-HTTPS for a name, and then makes an HTTPS request.
3. Routers keep notes on every packet and stop anything that is unencrypted, spoofed, or expired.
4. The attacker keeps firing new tricks so you can confirm the routers stay strict.

## Quick Start

### What You Need
- OMNeT++ 6.2 installed and working.
- The usual OMNeT++ build shell (`mingwenv.cmd` on Windows, `source setenv` on Linux/macOS).

### Build Steps
```bash
# open the OMNeT++ build shell first
cd SecureNetworkProject
make MODE=debug      # or MODE=release
```
The compiled program lands in `out/<toolchain>-<mode>/SecureNetworkProject_dbg.exe` (Windows example).

### Run the Simulation
```bash
./out/clang-debug/SecureNetworkProject_dbg.exe -u Qtenv -n src;src/simulations omnetpp.ini
```
- `-u Qtenv` launches the graphical viewer. Swap in `Cmdenv` for command-line mode.
- The `-n` option lists folders that hold NED files. Add more paths if you move things.

Inside the IDE you can import the project, build it, and run the `SecureEnterpriseNetwork` configuration from `omnetpp.ini`.

## Watching the Results
- Router log files (`router1_security.log`, etc.) show timestamped events like dropped packets and OSPF updates.
- OMNeT++ scalars (in the `out/` folder or the IDE “Scalars” tab) capture totals for leases, DNS queries, HTTPS requests, and attacks.
- Increase the simulation time in `omnetpp.ini` if you want longer runs (default is `sim-time-limit = 100s`).

## Customize It
- Add new attack styles by editing `AttackerNode.cc`.
- Change router behavior (turn IDS off, alter OSPF timers, etc.) by adjusting parameters in `SecureNetwork.ned` or `omnetpp.ini`.
- Drop in new services by creating another simple module and connecting it to Router3.

## Folder Map
```
SecureNetworkProject/
├─ src/
│  ├─ AttackerNode.cc
│  ├─ SecureClient.cc
│  ├─ SecureDHCPServer.cc
│  ├─ SecureDNSServer.cc
│  ├─ SecureHTTPServer.cc
│  ├─ SecureRouter.cc
│  └─ simulations/
│     ├─ SecureNetwork.ned
│     └─ omnetpp.ini
├─ PROJECT_SUMMARY.md
└─ README.md
```

## License
No license is bundled. Add your own before sharing the project.
