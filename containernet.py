#!/usr/bin/python

from containernet.net import Containernet
from containernet.node import DockerSta
from containernet.cli import CLI
from containernet.term import makeTerm
from mininet.log import info, setLogLevel

from mininet.node import Controller

def topology():
    net = Containernet(controller=Controller)

    info('*** Adding docker containers for stations \n')
    sta1 = net.addStation('sta1', ip='10.0.2.210', mac='00:02:00:00:00:10',
                          cls=DockerSta, dimage="luigi:latest",cpu_shares=10) #DEVICE - PASSENGER
    sta2 = net.addStation('sta2', ip='10.0.2.220', mac='00:02:00:00:00:20',
                          cls=DockerSta, dimage="luigi:latest",cpu_shares=10) #DEVICE - STAFF (ON BOARD)
    sta3 = net.addStation('sta3', ip='10.0.2.230', mac='00:02:00:00:00:30',
                          cls=DockerSta, dimage="luigi:latest",cpu_shares=10) #EXTERNAL WEB SERVICE - INTERNET BOUNDARY
                          
    info('*** Adding access points \n')                      
    ap1 = net.addAccessPoint('ap1',ssid='ap1-ssid') #WIFI ACCESS POINT - VLAN WIFIREG
    ap2 = net.addAccessPoint('ap2',ssid='ap2-ssid') #WIFI ACCESS POINT - VLAN WIFI_PDB
    ap3 = net.addAccessPoint('ap3',ssid='ap3-ssid') #ICOMERA
    
    info('*** Adding docker containers for hosts \n')
    d1 = net.addDocker('d1', ip="10.0.1.10/24", mac="00:00:00:00:00:01", dimage="luigi:latest",defaultRoute='via 10.0.1.1',cpu_shares=10) #TOD
    d3 = net.addDocker('d3', ip="10.0.1.30/24", mac="00:00:00:00:00:03", dimage="luigi:latest",defaultRoute='via 10.0.1.1',cpu_shares=10) #DIAGNOSTIC SERVER - NO TELE
    d5 = net.addDocker('d5', ip="10.0.1.50/24", mac="00:00:00:00:00:05", dimage="luigi:latest",defaultRoute='via 10.0.1.1',cpu_shares=10) #CCU
    d7 = net.addDocker('d7', ip="10.0.1.70/24", mac="00:00:00:00:00:07", dimage="luigi:latest",defaultRoute='via 10.0.1.1',cpu_shares=10) #DIAGNOSTIC SERVER - SI TELE
    d9 = net.addDocker('d9', ip="10.0.1.90/24", mac="00:00:00:00:00:09", dimage="luigi:latest",defaultRoute='via 10.0.1.1',cpu_shares=10) #DIS REMOTE TERMINAL
    d11 = net.addDocker('d11', ip="10.0.1.110/24", mac="00:00:00:00:00:11", dimage="luigi:latest",defaultRoute='via 10.0.1.1',cpu_shares=10) #DRIVER INFORMATION SYSTEMS 
    d13 = net.addDocker('d13', ip="10.0.1.130/24", mac="00:00:00:00:00:13", dimage="luigi:latest",defaultRoute='via 10.0.1.1',cpu_shares=10) #ACTUATORS + MVB BUS
    d15 = net.addDocker('d15', ip="10.0.1.150/24", mac="00:00:00:00:00:15", dimage="luigi:latest",defaultRoute='via 10.0.1.1',cpu_shares=10) #DIAGNOSTIC SERVER DI TERRA - INTRANET BOUNDARY 
    d17 = net.addDocker('d17', ip="10.0.1.170/24", mac="00:00:00:00:00:17", dimage="luigi:latest",defaultRoute='via 10.0.1.1',cpu_shares=10) #ATTACKER1 
    
    d2 = net.addDocker('d2', ip="10.0.2.20/24", mac="00:00:00:00:00:02", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #CAMERAS
    d4 = net.addDocker('d4', ip="10.0.2.40/24", mac="00:00:00:00:00:04", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #TELEPHONE
    d6 = net.addDocker('d6', ip="10.0.2.60/24", mac="00:00:00:00:00:06", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #SENSORS
    d8 = net.addDocker('d8', ip="10.0.2.80/24", mac="00:00:00:00:00:08", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #MEDIA SERVER
    d10 = net.addDocker('d10', ip="10.0.2.100/24", mac="00:00:00:00:00:10", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #SPEAKER
    d12 = net.addDocker('d12', ip="10.0.2.120/24", mac="00:00:00:00:00:12", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #MONITOR
    d14 = net.addDocker('d14', ip="10.0.2.140/24", mac="00:00:00:00:00:14", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #LED PANEL
    d16 = net.addDocker('d16', ip="10.0.2.160/24", mac="00:00:00:00:00:16", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #WEB SERVICE TRENITALIA - INTRANET BOUNDARY
    d18 = net.addDocker('d18', ip="10.0.2.180/24", mac="00:00:00:00:00:18", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #ATTACKER2
    d20 = net.addDocker('d20', ip="10.0.2.200/24", mac="00:00:00:00:00:20", dimage="luigi:latest",defaultRoute='via 10.0.2.1',cpu_shares=10) #OBOE
    
    info('*** Adding docker containers for router \n')
    r1 = net.addDocker('r1', dimage="qemu:latest",mem_limit="2048m",cpu_shares=100) #ROUTER CONNECTING THE PIS NETWORK AND THE TCMS NETWORK
    
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1') #SWITCH TCMS NETWORK
    s2 = net.addSwitch('s2') #SWITCH PIS NETWORK
    
    info('*** Creating links\n')
    net.addLink(r1,s1)
    net.addLink(r1,s2)
    
    net.addLink(d1,s1)
    net.addLink(d3,s1)
    net.addLink(d5,s1)
    net.addLink(d7,s1)
    net.addLink(d9,s1)
    net.addLink(d11,s1)
    net.addLink(d13,s1)
    net.addLink(d15,s1)
    net.addLink(d17,s1)
        
    net.addLink(d2,s2)
    net.addLink(d4,s2)
    net.addLink(d6,s2)
    net.addLink(d8,s2)
    net.addLink(d10,s2)
    net.addLink(d12,s2)
    net.addLink(d14,s2)
    net.addLink(d16,s2)
    net.addLink(d18,s2)
    net.addLink(d20,s2)
    
    
    #net.addLink(sta1,ap1)
    #net.addLink(sta2,ap2)
    #net.addLink(sta3,ap3)
    net.addLink(ap1,s2)
    net.addLink(ap2,s2)
    net.addLink(ap3,s2)
    
    
    c0 = net.addController('c0')

    info('*** Configuring WiFi nodes\n')
    net.configureWifiNodes()

    info('*** Starting network\n')
    net.start()
    
    r1.cmd("ifconfig r1-eth0 0")
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ifconfig r1-eth0 hw ether 00:00:00:00:01:01")
    r1.cmd("ifconfig r1-eth1 hw ether 00:00:00:00:01:02")
    r1.cmd("ip addr add 10.0.1.1/24 brd + dev r1-eth0")
    r1.cmd("ip addr add 10.0.2.1/24 brd + dev r1-eth1")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    d20.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
          
    d20.cmd("iperf -s -p 2233 &")
    d20.cmd("iperf -s -p 4455 &")
    d20.cmd("iperf -s -p 5566 &")
    d20.cmd("iperf -s -p 6677 &")
    d20.cmd("iperf -s -p 7788 &")
    d20.cmd("iperf -s -p 8899 &")
    d20.cmd("iperf -s -p 9900 &")
    d20.cmd("iperf -s -p 9901 &")
    d20.cmd("httperf --hog --server 10.0.2.80 --port 80 --uri /home/treno2.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    d20.cmd("httperf --hog --server 10.0.2.160 --port 80 --uri /home/treno3.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    d20.cmd("httperf --hog --server 10.0.1.70 --port 80 --uri /treno5.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    d20.cmd("httperf --hog --server 10.0.1.30 --port 80 --uri /treno1.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    d20.cmd("iperf -c 10.0.2.230 -p 9900 -t 300 -b 0.02M -l 800 &")
    d20.cmd("iperf -c 10.0.2.230 -p 9901 -u -t 300 -b 0.01M -l 900 &")

    
    sta1.cmd("httperf --hog --server 10.0.2.80 --port 80 --uri /treno6.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")   
    sta2.cmd("httperf --hog --server 10.0.2.80 --port 80 --uri /treno7.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    sta3.cmd("iperf -s -p 9900 &")
    sta3.cmd("iperf -s -p 9901 &")
    
        
    d1.cmd("iperf -s -p 1122 &")
    d1.cmd("iperf -s -p 3344 &") 
    d1.cmd("httperf --hog --server 10.0.1.30 --port 80 --uri /treno3.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")               
    d3.cmd("python3 -m http.server 80 &")
    d3.cmd("iperf -s -p 3030 &")
    d3.cmd("httperf --hog --server 10.0.2.80 --port 80 --uri /home/treno4.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    d5.cmd("iperf -c 10.0.1.30 -p 3030 -t 300 -b 0.01M -l 250 &")
    d5.cmd("iperf -c 10.0.1.70 -p 7070 -t 300 -b 0.002M -l 300 &")
    d5.cmd("iperf -c 10.0.1.50 -p 5050 -t 300 -b 0.001M -l 450 &")
    d5.cmd("httperf --hog --server 10.0.1.30 --port 80 --uri /treno4.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    d7.cmd("python3 -m http.server 80 &")
    d7.cmd("iperf -s -p 7070 &")
    d7.cmd("httperf --hog --server 10.0.1.150 --port 80 --uri /treno5.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    d9.cmd("httperf --hog --server 10.0.1.110 --port 80 --uri /treno6.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    d11.cmd("iperf -s -p 1011 &")
    d11.cmd("python -m http.server 80 &")
    d13.cmd("iperf -c 10.0.1.110 -p 1011 -u -t 300 -b 0.002M -l 975 &")
    d13.cmd("iperf -s -p 5050 &")
    d15.cmd("python -m http.server 80 &")
    

    d2.cmd("iperf -c 10.0.1.10 -p 1122 -t 600 -b 0.01M -l 500 &")
    d2.cmd("iperf -c 10.0.1.10 -p 3344 -u -t 600 -b 0.02M -l 1400 &")
    d4.cmd("iperf -c 10.0.2.200 -p 2233 -u -t 600 -b 0.001M -l 1000 &")
    d6.cmd("iperf -c 10.0.2.200 -p 4455 -t 600 -b 0.002M -l 700 &")
    d6.cmd("iperf -c 10.0.2.200 -p 5566 -u -t 600 -b 0.001M -l 1100 &")
    d8.cmd("python3 -m http.server 80 &")
    d8.cmd("httperf --hog --server 10.0.1.30 --port 80 --uri /home/treno3.jpg --rate 1 --num-conn 300 --num-call 1 --timeout 10 &")
    d10.cmd("iperf -c 10.0.2.200 -p 6677 -u -t 600 -b 0.001M -l 1200 &")
    d12.cmd("iperf -c 10.0.2.200 -u -p 7788 -u -t 600 -b 0.001M -l 1300 &")
    d14.cmd("iperf -c 10.0.2.200 -p 8899 -u -t 600 -b 0.003M -l 950 &")
    d16.cmd("python3 -m http.server 80 &")


    s1.cmd("ovs-ofctl add-flow s1 priority=1,arp,actions=flood")
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_dst=00:00:00:00:01:01,actions=output:1")
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.10,actions=output:2")
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.30,actions=output:3")  
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.50,actions=output:4")
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.70,actions=output:5")
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.90,actions=output:6")        
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.110,actions=output:7")
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.130,actions=output:8")        
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.150,actions=output:9")
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.170,actions=output:10")
        

    s2.cmd("ovs-ofctl add-flow s2 priority=1,arp,actions=flood")
    s2.cmd("ovs-ofctl add-flow s2 priority=65535,ip,dl_dst=00:00:00:00:01:02,actions=output:1")
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.20,actions=output:2")
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.40,actions=output:3")        
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.60,actions=output:4")
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.80,actions=output:5")
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.100,actions=output:6")        
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.120,actions=output:7")
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.140,actions=output:8")
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.160,actions=output:9")
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.180,actions=output:10")
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.200,actions=output:11")    

    #sta1.cmd('iw dev sta1-wlan0 connect ap1-ssid') 
    #sta2.cmd('iw dev sta2-wlan0 connect ap2-ssid')
    #sta3.cmd('iw dev sta3-wlan0 connect ap3-ssid')
    

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()

