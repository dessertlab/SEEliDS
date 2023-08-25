#!/usr/bin/python3

from scapy.all import *
import pandas as pd
import numpy as np
import threading
import os
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from sklearn.metrics import pairwise_distances
from sklearn import metrics
from sklearn.metrics import DistanceMetric
import logging
import datetime

print("\n")
pid = os.getpid()
print("The pid of the Intrusion Detection System is: ",pid)

time = []
sourceIP = []
destinationIP = []
protocol = []
sourcePort = []
destinationPort = []

synFlag = 0
ackFlag = 0
synAckFlag = 0
pshFlag = 0
rstFlag = 0
finFlag = 0
urgFlag = 0
httpTraffic = 0
lenght = 0
lenghtAvg = 0
lenghtStd = 0
meanInterArrivalTime = 0
totalPkt = 0
udpPkt = 0
tcpPkt = 0
icmpPkt = 0
httpPkt = 0
totalBytes = 0
udpBytes = 0
tcpBytes = 0
icmpBytes = 0
httpBytes = 0
interArrivalTime = []

contH1d=0
contH2d=0
contH3d=0
contH4d=0
contH5d=0
contH6d=0
contH7d=0
contH8d=0
contH9d=0
contH10d=0
contH12d=0
contH14d=0
contH16d=0
contH17d=0
contH18d=0
contSTA1d=0
contSTA2d=0
contSTA3d=0

contH20s=0
contH20d=0
contH1s=0
contH2s=0
contH3s=0
contH4s=0
contH5s=0
contH6s=0
contH7s=0
contH8s=0
contH9s=0
contH10s=0
contH12s=0
contH14s=0
contH16s=0
contH17s=0
contH18s=0
contSTA1s=0
contSTA2s=0
contSTA3s=0

lClass=[]
lContH1d=[]
lContH2d=[]
lContH3d=[]
lContH4d=[]
lContH5d=[]
lContH6d=[]
lContH7d=[]
lContH8d=[]
lContH9d=[]
lContH10d=[]
lContH12d=[]
lContH14d=[]
lContH16d=[]
lContH17d=[]
lContH18d=[]
lContSTA1d=[]
lContSTA2d=[]
lContSTA3d=[]
lContH20d=[]

lContH1s=[]
lContH2s=[]
lContH3s=[]
lContH4s=[]
lContH5s=[]
lContH6s=[]
lContH7s=[]
lContH8s=[]
lContH9s=[]
lContH10s=[]
lContH12s=[]
lContH14s=[]
lContH16s=[]
lContH17s=[]
lContH18s=[]
lContSTA1s=[]
lContSTA2s=[]
lContSTA3s=[]
lContH20s=[]

lLenght = []
lLenghtAvg = []
lLenghtStd = []
lTotalPkt = []
lTcpPkt = []
lUdpPkt = []
lIcmpPkt = []
lHttpPkt = []
lTotalBytes = []
lUdpBytes = []
lTcpBytes = []
lIcmpBytes = []
lHttpBytes = []
lLenghtAvg = []
lLenghtSdv = []
lMeanInterArrivalTime = []
lSourcePort = []
lDestinationPort = []
lSynFlag = []
lAckFlag = []
lSynAckFlag = []
lPshFlag = []
lRstFlag = []
lFinFlag = []
lUrgFlag = []
lHttpTraffic = []
appoggio=[]

y=0
features = []
classPrediction = []

print("SNIFFING PACKETS.......")

def intercetta_pacchetto(pkt):
    
    global time,sourceIP,destinationIP,protocol,lenght,sourcePort,destinationPort,synFlag,ackFlag,synAckFlag,pshFlag,rstFlag,finFlag,urgFlag, httpTraffic,totalPkt,udpPkt,tcpPkt,icmpPkt,httpPkt,totalBytes,udpBytes,tcpBytes,icmpBytes,httpBytes,contH1s,contH3s,contH5s,contH7s,contH9s,contH2s,contH4s,contH6s,contH8s,contH10s,contH12s,contH14s,contH16s,contH1d,contH3d,contH5d,contH7d,contH9d,contH2d,contH4d,contH6d,contH8d,contH10d,contH12d,contH14d,contH16d,contH20s,contH20d,contH18s,contH18d,contH17s,contH17d,contSTA1s,contSTA2s,contSTA3s,contSTA1d,contSTA2d,contSTA3d
    
    if IP in pkt:
        time.append(pkt[IP].time)
        sourceIP.append(pkt[IP].src)
        if pkt[IP].src == "10.0.1.10":
            contH1s +=1
        if pkt[IP].src == "10.0.1.30":
            contH3s +=1
        if pkt[IP].src == "10.0.1.70":
            contH7s +=1
        if pkt[IP].src == "10.0.1.170":
            contH17s +=1
        if pkt[IP].src == "10.0.2.200":
            contH20s +=1
        if pkt[IP].src == "10.0.2.120":
            contH12s +=1
        if pkt[IP].src == "10.0.2.140":
            contH14s +=1
        if pkt[IP].src == "10.0.2.160":
            contH16s +=1
        if pkt[IP].src == "10.0.2.180":
            contH18s +=1
        if pkt[IP].src == "10.0.2.20":
            contH2s +=1
        if pkt[IP].src == "10.0.2.40":
            contH4s +=1
        if pkt[IP].src == "10.0.2.60":
            contH6s +=1 
        if pkt[IP].src == "10.0.2.80":
            contH8s +=1     
        if pkt[IP].src == "10.0.2.100":
            contH10s +=1
        if pkt[IP].src == "10.0.2.210":
            contSTA1s +=1 
        if pkt[IP].src == "10.0.2.220":
            contSTA2s +=1     
        if pkt[IP].src == "10.0.2.230":
            contSTA3s +=1            
        destinationIP.append(pkt[IP].dst)
        if pkt[IP].dst == "10.0.1.10":
            contH1d +=1
        if pkt[IP].dst == "10.0.1.30":
            contH3d +=1
        if pkt[IP].dst == "10.0.1.70":
            contH7d +=1
        if pkt[IP].dst == "10.0.1.170":
            contH17d +=1
        if pkt[IP].dst == "10.0.2.120":
            contH12d +=1
        if pkt[IP].dst == "10.0.2.140":
            contH14d +=1
        if pkt[IP].dst == "10.0.2.160":
            contH16d +=1
        if pkt[IP].dst == "10.0.2.180":
            contH18d +=1
        if pkt[IP].dst == "10.0.2.200":
            contH20d +=1
        if pkt[IP].dst == "10.0.2.20":
            contH2d +=1
        if pkt[IP].dst == "10.0.2.40":
            contH4d +=1 
        if pkt[IP].dst == "10.0.2.60":
            contH6d +=1
        if pkt[IP].dst == "10.0.2.80":
            contH8d +=1
        if pkt[IP].dst == "10.0.2.100":
            contH10d +=1
        if pkt[IP].dst == "10.0.2.210":
            contSTA1d +=1
        if pkt[IP].dst == "10.0.2.220":
            contSTA2d +=1
        if pkt[IP].dst == "10.0.2.230":
            contSTA3d +=1
        protocol.append(pkt[IP].proto)
        lenght += pkt[IP].len
        totalPkt += 1
        
        if TCP in pkt:
            sourcePort.append(pkt[TCP].sport)
            destinationPort.append(pkt[TCP].dport)
            tcpPkt += 1
            tcpBytes += pkt[IP].len
            if (pkt[TCP].sport == 80 or pkt[TCP].dport == 80):
                httpTraffic += 1
                httpPkt += 1
                httpBytes += pkt[IP].len
            synFlag += int(pkt[TCP].flags.S)
            ackFlag += int(pkt[TCP].flags.A)
            synAckFlag += int(pkt[TCP].flags.SA)
            pshFlag += int(pkt[TCP].flags.P)
            rstFlag += int(pkt[TCP].flags.R)
            finFlag += int(pkt[TCP].flags.F)
            urgFlag += int(pkt[TCP].flags.U)
            
        if UDP in pkt:
            sourcePort.append(pkt[UDP].sport)
            destinationPort.append(pkt[UDP].dport)
            udpPkt += 1
            udpBytes += pkt[IP].len
            
        if ICMP in pkt:
            sourcePort.append(0)
            destinationPort.append(0)
            icmpPkt += 1
            icmpBytes += pkt[IP].len


      
def aggiornaFeatures():

  global totalPkt,lenght,totalPkt,tcpPkt,udpPkt,httpPkt,icmpPkt,tcpBytes,udpBytes,httpBytes,icmpBytes,lTotalPkt,lLenght,lLenghtAvg,lTotalPkt,lTcpPkt,lUdpPkt,lHttpPkt,lIcmpPkt,lTotalBytes,lTcpBytes,lUdpBytes,lHttpBytes,lIcmpBytes,synFlag,ackFlag,synAckFlag,pshFlag,rstFlag,finFlag,urgFlag,lSynFlag,lAckFlag,lSynAckFlag,lPshFlag,lRstFlag,lFinFlag,lUrgFlag,httpTraffic,lHttpTraffic,lContH1d,lContH2d,lContH3d,lContH4d,lContH5d,lContH6d,lContH7d,lContH8d,lContH9d,lContH10d,lContH1s,lContH2s,lContH3s,lContH4s,lContH5s,lContH6s,lContH7s,lContH8s,lContH9s,lContH10s,contH1s,contH3s,contH5s,contH7s,contH9s,contH2s,contH4s,contH6s,contH8s,contH10s,contH1d,contH3d,contH5d,contH7d,contH9d,contH2d,contH4d,contH6d,contH8d,contH10d,lenghtAvg,lLenghtAvg,time,interArrivalTime,meanInterarrivalTime,appoggio,lenghtStd,lLenghtStd,contH17s,contH17d,lContH17s,lConth17d,contH18s,contH18d,lContH18s,lContH18d,contH20s,contH20d,lContH20s,lContH20d,contH12s,contH12d,lContH12s,lContH12d,contH14s,contH14d,lContH14s,lContH14d,contH16s,contH16d,lContH16s,lContH16d,lClass,lContSTA1s,lContSTA2s,lContSTA3s,lContSTA1d,lContSTA2d,lContSTA3d,contSTA1s,contSTA1d,contSTA2s,contSTA2d,contSTA3s,contSTA3d,features,y,classPrediction
  
  threading.Timer(1.0, aggiornaFeatures).start()
  
  lLenght.append(lenght)
  appoggio.append(lenght)
     
  if len(appoggio) == 0:
    lenghtAvg = 0
  else:
    lenghtAvg = round(np.mean(lLenght),3)
  
  lLenghtAvg.append(lenghtAvg)
  
  if len(appoggio) == 0:
    lenghtStd=0
  else:
    lenghtStd = round(np.std(lLenght),3)
    
  lLenghtStd.append(lenghtStd)  
    
  appoggio.clear()

  lTotalPkt.append(totalPkt)
  lTcpPkt.append(tcpPkt)
  lUdpPkt.append(udpPkt)
  lHttpPkt.append(httpPkt)
  lIcmpPkt.append(icmpPkt)
  lTcpBytes.append(tcpBytes)
  lUdpBytes.append(udpBytes)
  lHttpBytes.append(httpBytes)
  lIcmpBytes.append(icmpBytes)
  lContH1d.append(contH1d)
  lContH2d.append(contH2d)
  lContH3d.append(contH3d)
  lContH4d.append(contH4d)
  lContH5d.append(contH5d)
  lContH6d.append(contH6d)
  lContH7d.append(contH7d)
  lContH8d.append(contH8d)
  lContH9d.append(contH9d)
  lContH10d.append(contH10d)
  lContH12d.append(contH12d)
  lContH14d.append(contH14d)
  lContH16d.append(contH16d)
  lContH17d.append(contH17d)
  lContH18d.append(contH18d)
  lContSTA1d.append(contSTA1d)
  lContSTA2d.append(contSTA2d)
  lContSTA3d.append(contSTA3d)
  lContH20d.append(contH20d)
  lContH1s.append(contH1s)
  lContH2s.append(contH2s)
  lContH3s.append(contH3s)
  lContH4s.append(contH4s)
  lContH5s.append(contH5s)
  lContH6s.append(contH6s)
  lContH7s.append(contH7s)
  lContH8s.append(contH8s)
  lContH9s.append(contH9s)
  lContH10s.append(contH10s)
  lContH12s.append(contH12s)
  lContH14s.append(contH14s)
  lContH16s.append(contH16s)
  lContH17s.append(contH17s)
  lContH18s.append(contH18s)
  lContSTA1s.append(contSTA1s)
  lContSTA2s.append(contSTA2s)
  lContSTA3s.append(contSTA3s)
  lContH20s.append(contH20s)
  contH1d=0
  contH2d=0
  contH3d=0
  contH4d=0
  contH5d=0
  contH6d=0
  contH7d=0
  contH8d=0
  contH9d=0
  contH10d=0
  contH12d=0
  contH14d=0
  contH16d=0
  contH17d=0
  contH18d=0
  contSTA1d=0
  contSTA2d=0
  contSTA3d=0
  contH20d=0  
  contH1s=0
  contH2s=0
  contH3s=0
  contH4s=0
  contH5s=0
  contH6s=0
  contH7s=0
  contH8s=0
  contH9s=0
  contH10s=0
  contH12s=0
  contH14s=0
  contH16s=0
  contSTA1s=0
  contSTA2s=0
  contSTA3s=0
  contH20s=0
  lenght=0
  lenghtAvg=0
  tcpPkt=0
  udpPkt=0
  icmpPkt=0
  httpPkt=0
  tcpBytes=0
  udpBytes=0
  httpBytes=0
  icmpBytes=0
  contH17s=0
  contH18s=0
  
  lSynFlag.append(synFlag)
  lAckFlag.append(ackFlag)
  lSynAckFlag.append(synAckFlag)
  lPshFlag.append(pshFlag)
  lRstFlag.append(rstFlag)
  lFinFlag.append(finFlag)
  lUrgFlag.append(urgFlag)
  lHttpTraffic.append(httpTraffic)
  synFlag = 0
  ackFlag = 0
  synAckFlag = 0
  pshFlag = 0
  rstFlag = 0
  finFlag = 0
  urgFlag = 0
  httpTraffic = 0
  
  totalPkt=0
  lClass.append(0)
  

    
  for i in range(len(time)):
    if time[i]-time[i-1] < 0:
        interArrivalTime.append(0)
    else:
        interArrivalTime.append(time[i]-time[i-1])

  if len(interArrivalTime) == 0:
    meanInterArrivalTime = 0
  else:
    meanInterArrivalTime = round(np.mean(interArrivalTime),6)
    
  lMeanInterArrivalTime.append(meanInterArrivalTime)
  
  print("\n")
  y += 1
  print("Second: ",y)
  df = pd.DataFrame({"src 10.0.1.10":lContH1s,"src 10.0.1.30":lContH3s,"src 10.0.1.70":lContH7s,"src 10.0.1.170":lContH17s,"src 10.0.2.20":lContH2s,"src 10.0.2.80":lContH8s,"src 10.0.2.160":lContH16s,"src 10.0.2.180":lContH18s,"dst 10.0.1.10":lContH1d,"dst 10.0.1.30":lContH3d,"dst 10.0.1.70":lContH7d,"dst 10.0.1.170":lContH17d,"dst 10.0.2.20":lContH2d,"dst 10.0.2.80":lContH8d,"dst 10.0.2.160":lContH16d,"dst 10.0.2.180":lContH18d,"dst 10.0.2.200":lContH20d,"Lenght Tot.Pkt":lLenght,"Lenght Avg":lLenghtAvg,"Lenght Std":lLenghtStd,"Total #Pkt":lTotalPkt,"TCP #Pkt":lTcpPkt,"UDP #Pkt":lUdpPkt,"HTTP #Pkt":lHttpPkt,"ICMP #Pkt":lIcmpPkt,"TCP Bytes":lTcpBytes,"UDP Bytes":lUdpBytes,"HTTP Bytes":lHttpBytes,"ICMP Bytes":lIcmpBytes,"Syn Flag":lSynFlag,"Ack Flag":lAckFlag,"SynAck Flag":lSynAckFlag,"Psh Flag":lPshFlag,"Rst Flag":lRstFlag,"Fin Flag":lFinFlag,"Urg Flag":lUrgFlag,"Class":lClass})

  df.to_csv("LegitimateDataset.csv", index=False) 
  print("I finished writing the .csv file with the traffic sniffed on the network EVERY SECOND")

aggiornaFeatures()             
pkt = sniff(iface="r1-eth1",filter="tcp or udp or icmp",prn=intercetta_pacchetto)
#pkt = sniff(iface=["s2-eth1","s2-eth2","s2-eth3","s2-eth4","s2-eth5","s2-eth6","s2-eth7","s2-eth8","s2-eth9","s2-eth10","s2-eth11","s2-eth12","s2-eth13","s2-eth14"],filter="tcp or udp or icmp",prn=intercetta_pacchetto)

