## Internet Simulator (Kali)
in ~/commandes:
- run with ./runInet.sh
    -> on WinXP, default inetsim page in browser 
- run tcpdump
(-> run other tools)
- run malware
(revert snapshot)

- stop with ./stopInet.sh
    -> on WinXP, real internet in browser 

-> check used ports
    - list all destination ports

tshark -r capture.pcap -Y 'tcp || udp' -T fields -e tcp.dstport -e udp.dstport | tr '\t' '\n' | grep -E '^[0-9]+$' | sort -n | uniq

- replace protocol in simulation with netcat
    - compare with service in /etc/inetsim/inetsim.conf

tshark -r capture.pcap -Y 'tcp || udp' -T fields -e tcp.dstport -e udp.dstport | tr '\t' '\n' | grep -E '^[0-9]+$' | sort -n | uniq | while read p; do grep -nE "^[[:space:]]*#?[a-zA-Z_]+_bind_port[[:space:]]+$p([[:space:]]|$)" /etc/inetsim/inetsim.conf; done

    - comment start_service <service>
    - run nc -l -p <port>

(-> run other tools)
- run malware



## Analyse TcpDump
- Better in wireshark (pcap file)
- lookf for DNS lookup
- Follow TCP Stream



