FROM tianon/qemu

RUN apt-get update && apt-get install -y \
    net-tools \
    iputils-ping \
    iproute2 \
    telnet telnetd \
    iperf \
    httperf \
    tcpdump \
    hping3 \
    scapy \ 
    python3-pip \
    procps \
    cpulimit \
    iw \
    powertop
    
RUN pip3 install pandas scikit-learn    
    
COPY sniffing.py /home/sniffing.py
COPY ids.py /home/ids.py
COPY kmeans.py /home/kmeans.py
COPY DatasetBenigno.csv /home/DatasetBenigno.csv
COPY DatasetCompleto.csv /home/DatasetCompleto.csv
COPY centroidi.csv /home/centroidi.csv
COPY calcoloMetriche.py /home/calcoloMetriche.py
COPY treno1.jpg /home/treno1.jpg
COPY treno2.jpg /home/treno2.jpg
COPY treno3.jpg /home/treno3.jpg
COPY treno4.jpg /home/treno4.jpg
COPY treno5.jpg /home/treno5.jpg
COPY treno6.jpg /home/treno6.jpg
COPY treno7.jpg /home/treno7.jpg
COPY treno8.jpg /home/treno8.jpg     

CMD /bin/bash
