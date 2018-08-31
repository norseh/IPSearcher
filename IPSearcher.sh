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
GWFILELIST="/tmp/gwFILELIST.txt"
BESTGWFILELIST="/tmp/bgwFILELIST.txt"

# Deletes the temp files
if [ -f $RANGEFAST ]; then rm -rf $RANGEFAST; fi
if [ -f $RANGESLOW ]; then rm -rf $RANGESLOW; fi
if [ -f $RANGESALL ]; then rm -rf $RANGESALL; fi
if [ -f $TEMPARP ]; then rm -rf $TEMPARP; fi
if [ -f $RANGESDETECTED ]; then rm -rf $RANGESDETECTED; fi
if [ -f $IPSDETECTED ]; then rm -rf $IPSDETECTED; fi
if [ -f $GWFILELIST ]; then rm -rf $GWFILELIST; fi

# Create files with Ranges
echo $RANGE192 >> $RANGEFAST
echo $RANGE192 >> $RANGESLOW
echo $RANGE192 >> $RANGESALL
echo $RANGE172 >> $RANGEFAST
echo $RANGE172 >> $RANGESLOW
echo $RANGE172 >> $RANGESALL
echo $RANGE10 >> $RANGESLOW
echo $RANGE10 >> $RANGESALL

# Simpliest method is try dhcp (obviously)
ADDRESS=$(ifconfig $INTERFACE | grep -i "inet " | awk '{print $2}')
APIPA=$(ifconfig $INTERFACE | grep -i "inet " | awk '{print $2}'| cut -d "." -f 1)
if [[ ($APIPA == "169") || ($ADDRESS == "" ) ]]; then
    ip addr flush dev $INTERFACE
    dhclient $INTERFACE
fi
# DHCP works?
DHCPPACKETLOSS=$(ping -c 7 8.8.8.8 | grep -i loss | awk -F " packet loss" '{print $1}' | rev | awk '{print $1}' | rev | cut -d "%" -f 1)
if [ "$DCHPPACKETLOSS" == '' ]; then DHCPPACKETLOSS=100;fi
if [ $DHCPPACKETLOSS -lt 40 ]; then exit;fi
ADDRESS=$(ifconfig $INTERFACE | grep -i "inet " | awk '{print $2}')
APIPA=$(ifconfig $INTERFACE | grep -i "inet " | awk '{print $2}'| cut -d "." -f 1)
if [[ ($APIPA == "169") || ($ADDRESS == "" ) ]]; then

  # If APIPA or none address is detected, the active scan for an address is started
  ifconfig $INTERFACE 0.0.0.0

  # Collecting arp resolution for a short range of time
  timeout 3m netdiscover -S -f -i $INTERFACE -P | tee $TEMPARP
  NUMBERIPS=$(grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" $TEMPARP | wc -l)

  # If any IP address was detected the longest way is activated (scan full RFC1918)
  if [[ $NUMBERIPS -lt 1 ]]; then
    arp-scan -f $RANGESALL -B 2M -g -I $INTERFACE -q | awk '{print $1}' | tee $TEMPARP
  fi
  cat $TEMPARP | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | awk -F "." '{print $1"."$2"."$3}' | uniq >> $RANGESDETECTED
  cat $TEMPARP | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" >> $IPSDETECTED

  # Start checking for an unused IP address in the range detected
  echo "192.168.0" >> $RANGESDETECTED
  VALID=0
  GLOBALPACKETLOSS=100
  while read LINERANGES; do
    VALID=0
    while [ $VALID -ne 1 ]; do
      LAST=$(shuf -i 1-254 -n 1)
      TEMPIP="$LINERANGES.$LAST"
      if [ $(cat $IPSDETECTED | grep -i $TEMPIP -c) -eq 0 ]; then
        VALID=1 # Unused IP address was detected
      fi
    done

    # If exist only one IP address (mac resolution) recognized, so we can
    # presume that this is the correct network to search an default gateway
    #if [[ $VALID -eq 1 ]]; then break; fi
    ifconfig $INTERFACE $TEMPIP/24

    #Gateway detection
    NUMBERGW=0
    ITERATION=0
    while [[ ($NUMBERGW -eq 0) && ($ITERATION -lt 4) ]]; do
      nmap -sn $TEMPIP/24 --script ip-forwarding --script-args='target=8.8.8.8' | grep -i " has ip " -B 6 | grep -i nmap | awk '{print $5}' >> $GWFILELIST
      cat $GWFILELIST
      nmap -sn $TEMPIP/24 --script ip-forwarding --script-args='target=9.9.9.9' | grep -i " has ip " -B 6 | grep -i nmap | awk '{print $5}' >> $GWFILELIST
      cat $GWFILELIST
      nmap -sn $TEMPIP/24 --script ip-forwarding --script-args='target=1.1.1.1' | grep -i " has ip " -B 6 | grep -i nmap | awk '{print $5}' >> $GWFILELIST
      cat $GWFILELIST

      ls -lah $GWFILELIST
      cat $GWFILELIST
      GWLIST=$(cat $GWFILELIST | awk '!i[$0]++' )
      echo "${GWLIST}" | awk '!i[$0]++'
      echo "${GWLIST}" | awk '!i[$0]++' |  wc -l
      NUMBERGW=$(echo "${GWLIST}" | awk '!i[$0]++' | wc -l )
      if [[ $(echo $GWLIST | wc -m ) -le 6 ]]; then
        NUMBERGW=0;
      fi
      echo $LINERANGES
      echo "${NUMBERGW}"
      if [ $NUMBERGW -gt 0 ]; then
        break
      fi
      ITERATION=$(($ITERATION + 1))
     done
      BESTGW=""
      BESTPACKETLOSS=100
      cat $GWFILELIST | awk '!i[$0]++' | tee $BESTGWFILELIST
      cat $BESTGWFILELIST
      while read LINEGATEWAYS; do
        ip route add default via $LINEGATEWAYS
        PACKETLOSS=$(ping -c 7 8.8.8.8 | grep -i loss | awk -F " packet loss" '{print $1}' | rev | awk '{print $1}' | rev | cut -d "%" -f 1)
        if [ "$PACKETLOSS" == '' ]; then PACKETLOSS=100;fi
        if [ $PACKETLOSS -lt $BESTPACKETLOSS ]; then
          BESTPACKETLOSS=$PACKETLOSS
          BESTGW=$LINEGATEWAYS
          BESTIP=$TEMPIP
	  if [ $BESTPACKETLOSS -lt $GLOBALPACKETLOSS ]; then
	    IPGLOBAL=$BESTIP
	    GWGLOBAL=$BESTGW
	    GLOBALPACKETLOSS=$BESTPACKETLOSS
	  fi
	fi
        ip route del default
      done < $BESTGWFILELIST
  done < $RANGESDETECTED
  ifconfig $INTERFACE $IPGLOBAL/24
  ip route add default via $GWGLOBAL
fi
