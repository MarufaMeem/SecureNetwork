\# Secure Enterprise Network Simulation - Complete Implementation



\## ✅ Fully Implemented Features:



\### 1. Secure DHCP

\- ✅ Encrypted handshakes

\- ✅ Server authentication

\- ✅ TTL-based lease handling

\- ✅ Automatic lease expiration

\- ✅ Rogue server prevention



\### 2. Secure DNS (DNS-over-HTTPS)

\- ✅ Encrypted responses

\- ✅ Spoofing protection

\- ✅ Rate limiting (100 queries/sec)

\- ✅ Query tracking

\- ✅ DNSSEC-like verification



\### 3. Secure HTTP

\- ✅ HTTPS-only enforcement

\- ✅ Encrypted communication

\- ✅ HTTP rejection

\- ✅ Status code responses



\### 4. OSPF-Based Router Enforcement

\- ✅ Blocks unencrypted traffic

\- ✅ TTL checks (loop prevention)

\- ✅ IDS-like monitoring

\- ✅ OSPF routing updates

\- ✅ Encrypted OSPF messages

\- ✅ Multi-hop routing

\- ✅ Security logging per router



\### 5. Network Security

\- ✅ Cross-layer security policies

\- ✅ Encryption enforcement at every hop

\- ✅ TTL decrementation

\- ✅ Attack detection and blocking

\- ✅ Comprehensive logging



\### 6. Attack Simulation

\- ✅ Unencrypted packet attacks

\- ✅ TTL manipulation

\- ✅ Protocol spoofing

\- ✅ Malformed packets

\- ✅ Flood attacks



\## Network Topology:

\- 1 Legitimate Client

\- 1 Attacker Node

\- 3 OSPF Routers (mesh topology)

\- 3 Secure Servers (DHCP, DNS, HTTP)



\## Security Logs Generated:

\- router1\_security.log

\- router2\_security.log

\- router3\_security.log



\## Statistics Collected:

\- Packets forwarded/dropped per router

\- Authentication failures

\- Lease management

\- Rate limiting violations

\- Spoofing attempts

\- OSPF update exchanges



\## How to Run:

```bash

cd simulations

../out/clang-debug/SecureNetworkProject\_dbg.exe -u Qtenv

```



\## Project demonstrates:

✅ Modern enterprise network security

✅ Protocol-level encryption

✅ Router-enforced security policies

✅ Dynamic routing with OSPF

✅ IDS functionality

✅ Attack resilience

