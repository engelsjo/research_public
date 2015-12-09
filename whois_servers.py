"""
Python module to track the whois server of each top level domain
"""
import os
import subprocess
import sys

zonefiles = "../data/zonefiles/"
no_whois = {}
no_server = []
invalid_ip = []

other_exceptions = []
nbr_of_whois = 0
nbr_of_not_whois = 0

with open("../data/whois_servers.data", "w") as whois_servers_data_file:
	whois_servers_data_file.write("TLD : WHOIS-SERVER : FILENAME\n")
	for zonefile in os.listdir(zonefiles):
		sys.stdout.write('.')
		with open(zonefiles + zonefile, 'r') as file_handle:
			try:
				first_line = file_handle.readline()
				tld = first_line.split('.')[0]
				tld = '.' + tld
				info = subprocess.check_output("ruby-whois -t 10 {}".format(tld), shell=True)
				if "Unable to find a WHOIS server for " in info:
					no_server.append(tld)
					raise Exception("{}".format(info))
				if "Server definitions might be outdated" in info:
					invalid_ip.append(tld)
					raise Exception("{}".format(info))
				if "This query returned 1 object " in info and "whois:" not in info:
					raise Exception("whois info already available for {}".format(tld))
				whois_parts = info.split()

				whois_index = whois_parts.index('whois:')

				whois_servers_data_file.write("{} : {} : {}\n".format(tld, whois_parts[whois_index + 1], zonefile))
			except ValueError as e:
				no_whois[tld] = zonefile
			except Exception as e:
				other_exceptions.append(e)


	if other_exceptions: 
		whois_servers_data_file.write("No WHOIS Servers: {}\n".format(no_server))
		whois_servers_data_file.write("Invalid IP: {}\n".format(invalid_ip))
		whois_servers_data_file.write(other_exceptions)

	whois_servers_data_file.write("\n\n ****** No whois record: ********\n")
	for tld in no_whois.keys():
		whois_servers_data_file.write("{} : {}\n".format(tld, no_whois[tld]))
	whois_servers_data_file.write("no whois server listed length: {}".format(len(no_whois.keys())))
	print("")


