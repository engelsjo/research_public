"""
Python script to gather whois registrant information
"""

import os
import subprocess
import sys


class Whois_Parser:
	def __init__(self, dfp="../data/", wsf="../data/whois_servers.data"):
		self.data_file_path = dfp
		self.whois_server_file = wsf
		self.server_info = {}
		self.errors = []
		self.readWhoisServers()
		self.output = None
		self.attempted = False
		self.predefined_servers = ["sedoparking", "internettraffic", "cashparking", 
								"fabulous", "dsredirection", "above", "parkingcrew", 
								"ztomy", "fastpark", "voodoo", "rookdns", "bodis", 
								"domainapps", "trafficz", "pql"]

	def readWhoisServers(self):
		"""
		helper method to read in the whois server data file
		"""
		with open(self.whois_server_file) as ws_fp:
			for line in ws_fp:
				line_parts = line.split(":")
				if len(line_parts) != 3:
					continue
				if line == "TLD : WHOIS-SERVER : FILENAME":
					continue
				self.server_info[line_parts[0].strip()] = (line_parts[1].strip(), line_parts[2].strip())

	################ Methods dealing with Whois Creation Date #################

	def getCreationDate(self, domain, whoisServer):
		"""
		method to get the creation date from whois
		"""
		if self.output == None and self.attempted:
			#we already tried whois and got nothing, so don't try again
			return None
		#only call whois if we havnt done so already
		if self.output == None:
			self.attempted = True
			cmd = "whois -h {} {}".format(whoisServer, domain)
			self.output = subprocess.check_output(cmd, shell=True)
		if "TLD is not supported." in self.output:
			raise Exception("TLD: {} is not supported".format(domain))
		else:
			if "Creation Date:" in self.output:
				whois_parts = self.output.split("\n")
				for line in whois_parts:
					if "Creation Date" in line:
						return line
			else:
				raise Exception("Creation Date is not available for: {}".format(domain))

	def isCreationOlderThan(domain, whoisServer, xYears):
		"""
		@parameter xYears: The number of years you are checking to see if it is older than...
		@return boolean --
		Method returns if a whois date is older than xYears
		"""
		try:
			creationDateStr = self.getCreationDate(domain, whoisServer)
			datePart = createDateStr.split(":")[1].strip()
			datePieces = datePart.split("-")
			dYear = datePieces[0]
			return (2015 - int(xYears)) >= int(dYear)
		except Exception as e:
			self.errors.append(Exception("Failed to check older than for domain: {}".format(domain)))

	def zoneFileCreationDates(self, zonefile, whoisServer):
		"""
		@param zonefile: the path to the zone file you wish to get create dates for
		@param whoisServer: whois server for tld of interest
		@return createDates: a list of tuples where index 0 is a command string, and index 1 is the create date
		"""
		createDates = []
		with open(zonefile, "r") as zone_file:
			zone_file_contents = [zone_line for zone_line in zone_file]
			for zfile_line in zone_file_contents:
				zfile_line_parts = zfile_line.split()
				if len(zfile_line_parts) >= 4:
					if zfile_line_parts[3] == "ns":
						cmdString = "whois -h {} {}".format(whoisServer, zfile_line_parts[0][:-1])
						try:
							if len(zfile_line_parts[0][:-1].split(".")) <= 1:
								continue #dont want to get creation date for the actual tld
							if len(createDates) > 0:
								if createDates[len(createDates) - 1][0] == cmdString:
									continue #dont want to run the same command twice
							createDate = self.getCreationDate(zfile_line_parts[0][:-1], whoisServer)
							createDates.append((cmdString , createDate))
						except Exception as e:
							print("Error for cmd: {}".format(cmdString))
							self.errors.append(e)
		return createDates
	
	def allZoneFilesCreationDates(self):
		"""
		@return retVal: a dictionary with tlds as keys. And each key's value is a list of the creation dates for that file
		"""
		for tld in sorted(self.server_info.keys()):
			tldFile = self.server_info[tld][1]
			whoisServer = self.server_info[tld][0]
			tldFilePath = "{}zonefiles/{}".format(self.data_file_path, tldFile)
			zoneFileCreateData = self.zoneFileCreationDates(tldFilePath, whoisServer)
			for data in zoneFileCreateData:
				print(data[0])
				print(data[1])

	def isWhoisPrivacyProtected(self, domain, whoisServer):
		"""
		@return true if the whois is privacy protected, false otherwise
		"""
		if self.output == None and self.attempted:
			#we already tried whois and got nothing, so don't try again
			return None
		if self.output == None:
			self.attempted = True
			self.output = subprocess.check_output("whois -h {} {}".format(whoisServer, domain), shell=True)
		return "privacy" in self.output

	def isParking(self, domain, whoisServer):
		"""
		@return true if the whois info shows that it belongs to one of 15 popular parking whois_servers
		"""
		if self.output == None and self.attempted:
			#we already tried whois and got nothing, so don't try again
			return None
		if self.output == None:
			self.attempted = True
			self.output = subprocess.check_output("whois -h {} {}".format(whoisServer, domain), shell=True)
		output_as_list = self.output.split()
		for park_server in self.predefined_servers:
			if park_server in output_as_list:
				return True
		return False

	def getErrors(self):
		"""
		returns a list of all the commands / exceptions thrown during program execution
		"""
		return self.errors

if __name__ == "__main__":
	try:
		if len(sys.argv) != 2:
			print("You must pass a url to get whois info from")
			sys.exit(1)
		#parse the domain passed
		domain = sys.argv[1]
		domain_parts = domain.split('.')
		if len(domain_parts) == 0:
			#nothing was passed that can be parsed
			sys.exit(1)
		tld = domain_parts[len(domain_parts) - 1]
		wsp = Whois_Parser()
		whois_server = wsp.server_info['.' + tld][0]
		#now get the creation date for the url passed
		creation_date = wsp.getCreationDate(domain, whois_server)
		print(creation_date)
		#wsp.allZoneFilesCreationDates()
		#server = wsp.server_info[".xn--ngbc5azd"][0]
		#print (str(wsp.isParking("xn-----0sdndbq6jzdcek.xn--ngbc5azd.", server)))
	except KeyboardInterrupt as e:
		print("\nuser has terminated the program")
	except Exception as e:
		print("Exception finding the creation date. Perhaps we dont know the whois server in self.server_info")
		print(e)
