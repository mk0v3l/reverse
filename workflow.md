# Dynamic Analysis
## Host-Based IOC
4 tools : CaptureBat, regShot, AutoRun, ProcExplorer

## Network-Based IOC
3 tools : TcpDump, Wireshark, InetSim

# Static Analysis
2 tools : OllyDbg, Ghidra

### Workflow Dynamic Analysis Infection
- WinXP - Pre Malware
    - Open AutoRun
        - save clean state -> before.arn
    - Open regShot
        - 1st Shot (clean state)
    - Open CaptureBat (maybe change extenstion of filename txt -> xyz)
    - Open ProcExplorer

-> snapshot clean ready

### Kali
- Check Internet conditions (routing + InetSim)
- (active/deactive routing)
- (run/stop InetSim)
- run TcpDump


### WinXP - Malware
- run malware
    - Wait untill end of attack

### WinXP - Post Malware
- Close CaptureBat (-> e:\cap.txt)
- RegShot 
    - 2nd Shot
    - compare (-> e:\~res.txt)
- Autorun
    - Refresh
    - Compare to before.arn
- ProcExplorer
    - look process explorer window
    - analyze created child process
    - (save process dump)

### Kali
- stop TcpDump

-> Revert snaphot to clean state

### Workflow Dynamic Analysis Results
- Wireshark
- CaptureBat
- RegShot
- AutoRun
- ProcExplorer
