"""
Python module to determine parking name-servers
"""
import sys
import gzip

predefined_servers = ["sedoparking", "internettraffic", "cashparking", "fabulous", "dsredirection", "above", "parkingcrew", "ztomy", "fastpark", "voodoo", "rookdns", "bodis", "domainapps", "trafficz", "pql"]

parking_servers = {
	"sedoparking" : 0,
	"internettraffic" : 0,
	"cashparking" : 0,
	"fabulous" : 0,
	"dsredirection" : 0,
	"above" : 0,
	"parkingcrew" : 0,
	"ztomy" : 0,
	"fastpark" : 0,
	"voodoo" : 0,
	"rookdns" : 0,
	"bodis" : 0,
	"domainapps" : 0,
	"trafficz" : 0,
	"pql" : 0
}

domain_lines_tally = 0


def main(argv):
	"""
	Main driver method
	"""
	global domain_lines_tally
	global parking_servers
	global predefined_servers
	if len(argv) < 3:
		print("You need to pass the file to observe for parking servers, and a destination to write the file too")
		sys.exit(1)
	#otherwise, lets parse the file for the name servers
	file_to_parse = argv[1]
	file_to_write = argv[2]
	with gzip.open(file_to_parse, "r") as fileh:
		for line in fileh:
			line_parts = line.split()
			if len(line_parts) != 3: continue
			if line_parts[1].lower() != "ns": continue
			domain_lines_tally += 1
			domain = line_parts[0]
			ns = line_parts[2]
			if "sedoparking" in ns.lower():
				parking_servers["sedoparking"] += 1
			elif "internettraffic" in ns.lower():
				parking_servers["internettraffic"] += 1
			elif "cashparking" in ns.lower():
				parking_servers["cashparking"] += 1
			elif "fabulous" in ns.lower():
				parking_servers["fabulous"] += 1
			elif "dsredirection" in ns.lower():
				parking_servers["dsredirection"] += 1
			elif "above" in ns.lower():
				parking_servers["above"] += 1
			elif "parkingcrew" in ns.lower():
				parking_servers["parkingcrew"] += 1
			elif "ztomy" in ns.lower():
				parking_servers["ztomy"] += 1
			elif "fastpark" in ns.lower():
				parking_servers["fastpark"] += 1
			elif "voodoo" in ns.lower():
				parking_servers["voodoo"] += 1
			elif "rookdns" in ns.lower():
				parking_servers["rookdns"] += 1
			elif "bodis" in ns.lower():
				parking_servers["bodis"] += 1
			elif "domainapps" in ns.lower():
				parking_servers["domainapps"] += 1
			elif "trafficz" in ns.lower():
				parking_servers["trafficz"] += 1
			elif "pql" in ns.lower():
				parking_servers["pql"] += 1
			elif "parked" in ns.lower():
				if ns.lower() not in parking_servers.keys():
					parking_servers[ns.lower()] = 1
				else:
					parking_servers[ns.lower()] += 1
			elif "parking" in ns.lower():
				if ns.lower() not in parking_servers.keys():
					parking_servers[ns.lower()] = 1
				else:
					parking_servers[ns.lower()] += 1
			elif "park" in ns.lower():
				if ns.lower() not in parking_servers.keys():
					parking_servers[ns.lower()] = 1
				else:
					parking_servers[ns.lower()] += 1
	#write out results to a file
	with open(file_to_write, "w") as fileh:
		parked_count = 0
		predefined_servers_count = 0
		for key in parking_servers:
			if key in predefined_servers:
				predefined_servers_count += parking_servers[key]
			parked_count += parking_servers[key]
			fileh.write("Parking Server: {}   Count: {}\n".format(key, parking_servers[key]))
		fileh.write("Predefined(%): {}/{} .... {}%\n".format(predefined_servers_count, parked_count, (predefined_servers_count / (parked_count * 1.0))))
		fileh.write("Total Lines checked: {}\n".format(domain_lines_tally))



if __name__ == "__main__":
	main(sys.argv)