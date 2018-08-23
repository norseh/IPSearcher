#!/bin/bash
#arp-scan -f nets.txt -B 7M -R -g -I eth0
#IPs=$(sudo arp-scan --localnet --quiet --ignoredups | gawk '/([a-f0-9]{2}:){5}[a-f0-9]{2}/ {print $1}')
#netdiscover -S -f -i eth0

RANGEFAST="/tmp/rangeFAST.txt"
RANGESLOW="/tmp/rangeSLOW.txt"
RANGESALL="/tmp/rangesALL.txt"
RANGE192="192.168.0.0/16"
RANGE172="172.16.0.0/12"
RANGE10="10.0.0.0/8"
INTERFACE="eth0"
INTERFACESPEED=$(ethtool eth0 | grep "Speed: " | awk '{print $2}')
INTERFACEDUPLEX=$(ethtool eth0 | grep "Duplex: " | awk '{print $2}')
TEMPARP="/tmp/tempARP.txt"
RANGESDETECTED="/tmp/rangesDETECTED.txt"
IPSDETECTED="/tmp/ipsDETECTED.txt"
GWLIST="/tmp/gwLIST.txt"

# Deletes the temp file with rapid networks (ARP resolution)
if [ -f $RANGEFAST ]; then rm -rf $RANGEFAST; fi
if [ -f $RANGESLOW ]; then rm -rf $RANGESLOW; fi
if [ -f $RANGESALL ]; then rm -rf $RANGESALL; fi
if [ -f $TEMPARP ]; then rm -rf $TEMPARP; fi
if [ -f $RANGESDETECTED ]; then rm -rf $RANGESDETECTED; fi
if [ -f $IPSDETECTED ]; then rm -rf $IPSDETECTED; fi
if [ -f $GWLIST ]; then rm -rf $GWLIST; fi

# Create files with Ranges
echo $RANGE192 >> $RANGEFAST
echo $RANGE192 >> $RANGESLOW
echo $RANGE192 >> $RANGESALL
echo $RANGE172 >> $RANGEFAST
echo $RANGE172 >> $RANGESLOW
echo $RANGE172 >> $RANGESALL
echo $RANGE10 >> $RANGESLOW
echo $RANGE10 >> $RANGESALL

dhclient $INTERFACE
#ethtool -p $INTERFACE 5
ADDRESS=$(ifconfig $INTERFACE | grep -i "inet " | awk '{print $2}')
APIPA=$(ifconfig $INTERFACE | grep -i "inet " | awk '{print $2}'| cut -d "." -f 1)

if [[ ($APIPA == "169") || ($ADDRESS == "" ) ]]; then
  ifconfig $INTERFACE 0.0.0.0
  timeout 3m netdiscover -S -f -i $INTERFACE -P | tee $TEMPARP
  NUMBERIPS=$(grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" $TEMPARP | wc -l)
  if [[ $NUMBERIPS -lt 1 ]]; then
    arp-scan -f $RANGESALL -B 7M -g -I $INTERFACE -q | awk '{print $1}' | tee $TEMPARP
  fi
cat $TEMPARP | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | awk -F "." '{print $1"."$2"."$3}' | uniq >> $RANGESDETECTED
  cat $TEMPARP | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" >> $IPSDETECTED
  VALID=0
  while read line; do
    #Method 1 - complete range
    #SEQ=$(1 254)
    #
    #for i in $SEQ; do
    #  a
    #done
    #
    #Method 2 - random address
    while [ $VALID -ne 1 ]; do
      LAST=$(shuf -i 1-254 -n 1)
      TEMPIP="$line.$LAST"
      if [ $(cat $IPSDETECTED | grep -i $TEMPIP -c) -eq 0 ]; then
        VALID=1
        break
      fi
    done
    if [[ $VALID -eq 1 ]]; then break; fi
  done < $RANGESDETECTED
  # ATRIBUIR endereço IP
  ifconfig $INTERFACE $TEMPIP/24
  #Gateway detection
  #while read line; do
  #  GW=$(nmap -sn $line --script ip-forwarding --script-args='target=8.8.8.8' | grep -i " has ip ")
  #  if [[ $GW != "" ]]; then
  #    route add default gw $line
  #    echo "DEFAUT GW: $line"
  #  fi
  #done < $IPSDETECTED
  echo "IP Temp: $TEMPIP"
  NUMBERGW=0
  while [ NUMBERGW -eq 0 ]; do
    nmap -sn $TEMPIP/24 --script ip-forwarding --script-args='target=8.8.8.8' | grep -i " has ip " -B 6 | grep -i nmap | awk '{print $5}' >> $GWLIST
    nmap -sn $TEMPIP/24 --script ip-forwarding --script-args='target=9.9.9.9' | grep -i " has ip " -B 6 | grep -i nmap | awk '{print $5}' >> $GWLIST
    nmap -sn $TEMPIP/24 --script ip-forwarding --script-args='target=1.1.1.1' | grep -i " has ip " -B 6 | grep -i nmap | awk '{print $5}' >> $GWLIST
    NUMBERGW=$(cat $GWLIST | wc -l)
    if [ $NUMBERGW -gt 0 ]; then break fi
  done
  if [ $NUMBERGW -le 2 ]; then
    GW=$(cat $GWLIST)
    echo "DEFAUT GW: $GW"
    ip route add default via $GW
  else
    BESTGW=""
    BESTPACKETLOSS=100
    while read line; do
      ip route add default via $line
      PACKETLOSS=$(ping -c 7 8.8.8.8 | grep -i loss | awk '{print $6}' | cut -d "%" -f 1)
      if [ $PACKETLOSS -le $BESTPACKETLOSS ]; then
        BESTPACKETLOSS=$PACKETLOSS
        BESTGW=$line
      done
      ip route del default
    done < $GWLIST
    ip route add default via $BESTGW
  fi
fi
