"""
Python module for navigating x percent of alexa top n
"""

# TODO: format all the tld files to be just a list of domains without nameservers, tlds etc... make the name of the file the tld...
# TODO.. which files are gzipped and which ones are not.
# TODO, gather a list of all the TLD files we have access to into a file to be read by gatherTLDsWeHave
# 

import sys
import os
from random import randint
from tldparser import clTldParser
from webpage_info import WebPageInfoGetter
from whois_registrant import Whois_Parser

class Domain(object):
	def __init__(self, domain, alexa_rank, cw=[], ca=[], n=-1, ih=-1, r=-1, cd=None, privacy_prot=None, ip=None, tld=""):
		#domain does not have the TLD attached!
		self.value = domain
		self.rank = alexa_rank
		self.candidates_within = []
		self.candidates_across = []
		self.nilsimsa = -1
		self.image_hash = -1
		self.redirects = -1
		self.creation_date = None
		self.privacy_prot = None
		self.is_parking = None
		self.tld = ""

class Alexa_Reader(clTldParser):
	def __init__(self, fp, rand_int):
		clTldParser.__init__(self, "", False)
		self.alexa_filepath = fp
		self.alexa_nbr_touse = int(rand_int)
		self.tlds_we_have = {}
		self.tlds_we_need = {}
		self.whois_servers = {}
		self.current_zone = {}
		self.prev_zone = {}
		self.next_zone = {}
		self.web_exceptions = []
		self.whois_exceptions = []
		self.current_com_val = -1
		self.current_tld_in_mem = None
		self.zone_folders_path = "/home/engelsjo/Documents/Research/tld_file_parser/data/zonefiles"
		self.com_folders_path = "/home/engelsjo/Documents/Research/tld_file_parser/data/comzonefile/splitfiles"
		self.com_files_path = "/home/engelsjo/Documents/Research/tld_file_parser/data/comzonefile/lengths"
		self.curr_path = "/home/engelsjo/Documents/Research/tld_file_parser/src"

	def gatherTLDsWeHave(self, filepath):
		"""
		@param filepath: the path to a file containing all the TLDs that we have, and the path to the file of that TLD
		@return void: this just assigns all our the TLDs we have access to, to an instance var.
		"""
		with open(filepath, "r") as fh:
			for line in fh:
				if ":" not in line: continue
				line_parts = line.split(':')
				tld = line_parts[0]
				file_path = line_parts[1]
				self.tlds_we_have[tld] = file_path

	def parseFile(self):
		"""
		@return a python list of Domain objects that from the alexa top 50k
		"""
		domains_to_parse = []
		with open(self.alexa_filepath, "r") as fh:
			for i, e in enumerate(fh):
					line_parts = e.split(',')
					rand_nbr = int(line_parts[2])
					if rand_nbr == self.alexa_nbr_touse:
						# gather the data for this domain
						try:
							full_domain = line_parts[1].strip()
							full_domain_parts = full_domain.split('.')
							tld = full_domain_parts[-1]
							domain_piece = ""
							for j in range(len(full_domain_parts ) - 1):
								domain_piece += full_domain_parts[j] + '.'
							domain_piece = domain_piece[:-1]
							d = Domain(domain_piece, i, tld=tld)
							domains_to_parse.append(d)
						except:
							continue
					else:
						continue
		return domains_to_parse

	def processDomain(self, domain):
		"""
		@param domain: a Domain object that we want information for.
		@return a Domain object stuffed with all the contents that we need except the candidates across.
		"""
		tld = domain.tld

		# get the web and whois content into our domains
		domain = self.getDomainWebandWhois(domain)

		# get candidates within the domains TLD
		candidates_within = []
		if tld == "com":
			# we can get the candidates from memory, but we need to have special logic for the massive com file
			if self.current_com_val != len(domain.value) or self.current_tld_in_mem != "com": # wrong com stuff in memory... need to reset
				# reload memory contents.
				self.loadCOMIntoMemory(self.com_folders_path, len(domain.value))
				self.current_com_val = len(domain.value)
				self.current_tld_in_mem = "com"
			candidates_within = self.findCandidatesWithinTLD(domain, tld)
		elif tld in self.tlds_we_have.keys():
			# we can get the candidates from whatever is in memory
			tld_file = self.tlds_we_have[tld]
			tld_file_path = self.zone_folders_path + '/' + tld_file
			if self.current_tld_in_mem != tld: # dont have right stuff in memory, need to reset
				# reload memory contents
				self.loadFileIntoMemory(tld_file_path)
				self.current_tld_in_mem = tld
			candidates_within =  self.findCandidatesWithinTLD(domain, tld)
		else:
			# we have to use nslookups to determine candidates
			candidates_within = self.findCandidatesWOFile(domain, tld)

		# return the processed domain object - NOTE candidates from across domains will be processed in another step
		return Domain(domain.value.lower(), domain.rank, candidates_within, [], domain.nilsimsa, domain.image_hash, domain.redirects, domain.creation_date, domain.privacy_prot, domain.is_parking, tld)

	def recordInfoForDomains(self, domains_hash):
		"""
		@param domains: a python hashmap of all of the data.
		"""
		# write them out by alex_rank order
		with open("/home/engelsjo/Documents/Research/tld_file_parser/data/alexa.data", "w") as fh:
			for key in domains_hash.keys():
				domains = domains_hash[key]
				# first print out all the information for this domain
				domains.sort(key=lambda x: x.rank)
				for domain in domains:
					fh.write("*Domain: {}".format(domain.value))
					fh.write("TLD: {}".format(domain.tld))
					fh.write("Alexa: {}".format(domain.rank))
					fh.write("Nilsimsa: {}".format(domain.nilsimsa))
					fh.write("Image: {}".format(domain.image_hash))
					fh.write("Redirects: {}".format(domain.redirects))
					fh.write("Creation: {}".format(domain.creation_date))
					fh.write("PrivacyProtected: {}".format(domain.privacy_prot))
					fh.write("ParkingNS: {}".format(domain.is_parking))
					fh.write("--CandidatesWithinTLD:")
					for can in domain.candidates_within:
						fh.write("-Candidate: {}".format(can.value))
						fh.write("TLD: {}".format(can.tld))
						fh.write("Nilsimsa: {}".format(can.nilsimsa))
						fh.write("Image: {}".format(can.image_hash))
						fh.write("Redirects: {}".format(can.redirects))
						fh.write("Creation: {}".format(can.creation_date))
						fh.write("PrivacyProtected: {}".format(can.privacy_prot))
						fh.write("ParkingNS: {}".format(can.is_parking))
					fh.write("---CandidatesAcross:")
					for can in domain.candidates_across:
						fh.write("-Candidate: {}".format(can.value))
						fh.write("TLD: {}".format(can.tld))
						fh.write("Nilsimsa: {}".format(can.nilsimsa))
						fh.write("Image: {}".format(can.image_hash))
						fh.write("Redirects: {}".format(can.redirects))
						fh.write("Creation: {}".format(can.creation_date))
						fh.write("PrivacyProtected: {}".format(can.privacy_prot))
						fh.write("ParkingNS: {}".format(can.is_parking))

	def recordErrors(self):
		"""
		simple log file that dumps a count of any errors we receieved for sanity checks
		"""
		# TODO: flesh this out more once i have a better idea of what kind of errors I will have.
		with open("/home/engelsjo/Documents/Research/tld_file_parser/src/error.log", "w") as fh:
			fh.write(self.web_exceptions)
			fh.write(self.whois_exceptions)

	def sortDomainsByTLDAndLength(self, domains):
		"""
		@param domains: A python list of Domain objects that we will sort by TLD and length.
		@param ret_domains: a python hashmap. The keys are the TLDs and the values are a list of Domains for that TLD in the alexa top 50 k
		"""
		# first separate the domains by tld
		tld_to_domains = {}
		for dom in domains:
			tld = dom.tld
			if tld not in tld_to_domains:
				tld_to_domains[tld] = [dom]
			else:
				tld_to_domains[tld].append(dom)

		# next sort all the separate lists by length of the domain -- only useful for the COM TLD
		for tld in tld_to_domains.keys():
			tld_domains = tld_to_domains[tld]
			tld_domains.sort(key = lambda x: len(x.value))
			tld_to_domains[tld] = tld_domains

		return tld_to_domains

	def findCandidatesWithinTLD(self, domain, tld):
		"""
		@param domain: a Domain object containing the domain that you want to find candidates for.
		@param tld: a top level domain for the domain you are trying to find candidates for.
		@return a python list of Domain objects that are not yet populated with data.
		@summary this method is used to find all the candidates within my TLD when i have a file.
		"""
		domain_val = domain.value
		gtypos = self._generate_typos_inhash(domain_val).keys()
		candidates = []
		for typo in gtypos:
			if self.isDomainCandidate(typo):
				d = Domain(typo, -1, [], [], -1, -1, -1, None, None, None, tld)
				candidates.append(d)
		return candidates

	def findCandidatesWOFile(self, domain, tld):
		"""
		@param domain: a Domain object containing the domain that you want to find candidates for.
		@param tld: a top level domain for the domain you are trying to find candidates for.
		@return a python list of Domain objects - that will still need to be populated with data.
		@summary this method is used to find all the candidates within my TLD when i dont have a file.
		"""
		gtypos = self._generate_typos_inhash(domain.value).keys()
		candidates = []
		for typo in gtypos:
			typo_domain_str = typo + '.' + domain.tld
			if self.hasNameServer(typo_domain_str):
				# CANDIDATE because the typo has a NS!!!!!!
				d = Domain(typo, -1, [], [], -1, -1, -1, None, None, None, domain.tld)
				candidates.append(d)
		return candidates

	def findCandidatesAcrossDomains(self, domains, minNonCom, maxNonCom):
		"""
		@param domains: a hashmap of domains key is the tld, value is a list of Domain objects.
		@param minNonCom: an integer of the minimum non com url length
		@param maxNonCom: an integer of the max non com url length
		@return a hashmap of Domains key is the tld, value is a list of Domain objects.
		@summary search for @domain throughout all the zone files that we have.
		"""
		#first determine all the files that we will have to load up into memory
		non_com_tlds =  os.listdir(self.zone_folders_path)
		for i, e in enumerate(non_com_tlds):
			non_com_tlds[i] = self.zone_folders_path + '/' + e

		com_files =  os.listdir(self.com_files_path)
		com_tlds = []
		for com_file in com_files:
			com_num = com_file.split('_')[1]
			com_num = int(com_num.split('.')[0])
			if com_num >= minNonCom and com_num <= maxNonComa:
				com_tlds.append(self.com_files_path + '/' + com_file)
		all_files = non_com_tlds + com_tlds

		#next begin looping through these files loading them up into memory
		for f in all_files:
			self.loadFileIntoMemory(f)
			for key_tld in domains.keys():
				lDomains = domains[key]
				for i, d in enumerate(lDomains):
					if self.isDomainCandidate(d) and d.tld != "domain in memory... fix this.":
						d.candidates_across.append(d)
						lDomains[i] = d
				domains[key_tld] = lDomains

		return domains

	def populateAllCandidates(self, candidates):
		"""
		@param candidates a python list of Domain objects for all the candidates.
		@return the same list of candidates, only populated with web and whois content.
		@note: at this point I am not populating the alexa rank and the candidates of the candidates.
		I certainly dont think we need 'candidates of candidates'... I am less sure about if we need the alexa rank or not.
		"""
		for index, candidate in enumerate(candidates):
			#populate the candidate
			populatedCandidate = self.getDomainWebandWhois(candidate)

			#overwrite the old empty candidate
			candidates[index] = populatedCandidate
		return candidates

	def getDomainWebContent(self, domain):
		"""
		@param domain: a Domain object containing the domain that you want web_content for.
		@return a hashmap of all the webcontent for this domain.
		"""
		url = domain.value + '.' + domain.tld
		try:
			wpg = WebPageInfoGetter(url)
			wpg.setUpGetter(url)
		except Exception as e:
			self.web_exceptions.append(e)
		try:
			nilsimsa = wpg.getNilsimsaHash(url, False)
		except Exception as e:
			nilsimsa = -1
			self.web_exceptions.append(e)
		try:
			image = wpg.getImageHash(url, False)
		except Exception as e:
			image = -1
			self.web_exceptions.append(e)
		try:
			redirects = wpg.getNumberOfRedirects(url, False)
		except Exception as e:
			redirects = -1
			self.web_exceptions.append(e)
		return {"nilsimsa" : nilsimsa, "image" : image, "redirects" : redirects}

	def getDomainWhois(self, domain):
		"""
		@param domain: a Domain object containing the domain that you want whois_content for.
		@return a hashmap of all the webcontent for this domain.
		"""
		domain_val = domain.value
		tld = domain.tld
		url = domain_val + '.' + tld
		#next we grab all the whois content
		try:
			whois_parser = Whois_Parser()
			whois_server = self.whois_servers[tld]
		except Exception as e:
			self.whois_exceptions.append(e)
		try:
			creation_date = whois_parser.getCreationDate(url, whois_server)
		except Exception as e:
			creation_date = None
			self.whois_exceptions.append(e)
		try:
			privacy_prot = whois_parser.isWhoisPrivacyProtected(url, whois_server)
		except Exception as e:
			privacy_prot = None
			self.whois_exceptions.append(e)
		try:
			is_parking = whois_parser.isParking(url, whois_server)
		except Exception as e:
			is_parking = None
			self.whois_exceptions.append(e)
		return {"creation_date" : creation_date, "privacy_prot" : privacy_prot, "is_parking" : is_parking}

	def getDomainWebandWhois(self, domain):
		"""
		@param domain. A Domain object containing the domain you want web and whois content for.
		@return a Domain object with both the web and whois content populated.
		"""
		web_content = self.getDomainWebContent(domain)
		nilsimsa = web_content["nilsimsa"]
		image_hash = web_content["image"]
		redirects = web_content["redirects"]
		whois_content = self.getDomainWhois(domain)
		creation_date = whois_content["creation_date"]
		privacy_prot = whois_content["privacy_prot"]
		is_parking = whois_content["is_parking"]
		# return the processed domain object - NOTE candidates will be processed later
		return Domain(domain.value.lower(), domain.rank, [], [], nilsimsa, image_hash, redirects, creation_date, privacy_prot, is_parking, domain.tld)

	def getWhoisServersForTLDs(self, domains):
		"""
		@param domains: a python List of Domain objects that we want to get whois servers for.
		@ return void
		@ summary: This stuffs the whois servers for each tld we care about in an instance var.
		"""
		# gather all of our TLD's
		tlds = []
		for domain in domains:
			tld = domain.tld
			if tld not in tlds:
				tlds.append(tld)
		
		# gather the whois servers for all the TLDs
		for TLD in tlds:
			cmd = "ruby-whois -t 10 .{}".format(TLD)
			try:
				info = subprocess.check_output(cmd, shell=True)
				if "Unable to find a WHOIS server for " in info:
					self.whois_servers[TLD] = None
					continue
				if "Server definitions might be outdated" in info:
					self.whois_servers[TLD] = None
					continue
				if "This query returned 1 object " in info and "whois:" not in info:
					self.whois_servers[TLD] = None
				whois_parts = info.split()
				whois_index = whois_parts.index('whois:')
				self.whois_servers[TLD] = whois_parts[whois_index + 1]
			except ValueError as e:
				self.whois_servers[TLD] = None
				continue
			except Exception as e:
				self.whois_servers[TLD] = None
				continue

			# write all the whois servers out to a log file... we wont read this log in... but it helps for debugging.
			with open("/home/engelsjo/Documents/Research/tld_file_parser/src/whois_servers.log", "w") as fh:
				for TLD in self.whois_servers:
					fh.write("{} : {}".format(TLD, self.whois_servers[TLD]))

	def loadFileIntoMemory(self, filepath):
		"""
		@param filepath: the path to the tld file we want to load into memory.
		@return void
		@summary populates instance variables with content from zone file
		"""
		# reset old memory
		self.prev_zone = self.next_zone = self.current_zone = {}
		self.current_zone = self.loadFiles([filepath])

	def loadCOMIntoMemory(self, filepath, length):
		"""
		@param filepath: the path to the directory holding all the com files.
		@param length: The length of the current COM domains you are parsing.
		@summary populates instance variables with content from zone file
		"""
		min_len = length - 1
		max_len = length + 1
		# reset old memory
		self.current_zone = self.prev_zone = self.next_zone = {}
		
		# first figure out which com folder I need to cd into.
		com_dirs = os.listdir(filepath)
		dir_holding_files = ""
		for com_dir in com_dirs:
			dir_range = com_dir.split("_")[1]
			dir_min = int(dir_range.split('-')[0])
			dir_max = int(dir_range.split('-')[1])
			if length >= dir_min and length <= dir_max:
				dir_holding_files = com_dir
				break
		filepath += '/{}'.format(dir_holding_files)

		# next gather all the gzipped com files in the found folder.
		com_zips = os.listdir(filepath)
		for com_zip in com_zips:
			zip_num_and_extension = com_zip.split("_")[1]
			file_num = int(zip_num_and_extension.split('.')[0])
			if file_num == length:
				# load this file into the current instance var
				curr_file_path = filepath + '/' + com_zip
				self.current_zone = self.loadFiles([curr_file_path])
			elif file_num == min_len:
				prev_file_path = filepath + '/' + com_zip
				self.prev_zone = self.loadFiles([prev_file_path])
			elif file_num == max_len:
				next_file_path = filepath + '/' + com_zip
				self.next_zone = self.loadFiles([next_zone])

	def loadFiles(self, filesList):
		"""
		@param filesList: a python list of filepaths that will be loaded into our hash table
		@retVal: returns a python hashmap of the domain contents that we have loaded up.
		"""
		retVal = {}
		for f in filesList:
			#debug tip
			#if len(f) == 1:
			#	print("Are you sure you passed filesList as a list parameter???")
			with gzip.open(f, "r") as fileh:
				for line in fileh:
					domainName = line.strip()
					retVal[domainName.lower()] = True
		return retVal

	def isDomainCandidate(self, domain):
		"""
		@param domain: a Domain object that we are checking for candidacy
		@return True if a candidate, False if not.
		Checks if the domain passed is loaded in memory aka.. a viable candidate
		"""
		try:
			x = self.prev_zone[domain.value]
		except KeyError as e:
			x = False
		try:
			y = current_zone[domain.value]
		except KeyError as e:
			y = False
		try:
			z = next_zone[domain.value]
		except KeyError as e:
			z = False
		return (x or y or z)

	def hasNameServer(self, url):
		"""
		@param url: The url to check if we can find a nameServer
		"""
		info = subprocess.check_output("nslookup {}".format(url), shell=True, timeout=10)
		if "** server can't find" in info.lower():
			# no nameserver for this url
			return False
		else:
			return True

	def findMinAndMaxDomainLength(self, domains):
		"""
		@param domains: A python list of Domain objects that are not com
		I want to figure out what the largest com file I will have to load up into memory is.
		"""
		minDomain = len(min(domains, key = lambda x: len(x.value)).value)
		maxDomain = len(max(domains, key = lambda x: len(x.value)).value)
		return (minDomain, maxDomain)

def main(args):
	if len(args) != 3:
		print("invalid arguments")
		sys.exit(1)
	# grab the command line arguments
	alexa_path = args[1]
	if not os.path.isfile(alexa_path):
		print("invalid path to alexa file")
		sys.exit(2)
	rand_int = args[2]
	ar = Alexa_Reader(alexa_path, rand_int)
	
	# grab the domains of interest by random selection using an already formatted alexa list with probabilities
	domains = ar.parseFile()
	domains_hash = ar.sortDomainsByTLDAndLength(domains)

	# gather the whois servers we will need, and also the TLD files that we have
	ar.gatherTLDsWeHave()
	ar.getWhoisServersForTLDs(domains)

	# gather information for our domains except candidates from across domains which is handled separately for speed sake
	for key in domains_hash.keys():
			tld_domains = domains_hash[key]
			processed_domains = []
			for domain in tld_domains:
				processed_domain = ar.processDomain(domain)
				processed_domains.append(processed_domain)
			# overwrite the old domains with ones that are content filled.
			# at this point the only thing missing is the candidates from across domains
			domains_hash[key] = processed_domain

	# gather all the candidates from across domains
	non_com_domains = []
	for key in domains_hash.keys():
		if key != "com":
			non_com_domains += domains_hash[key]
	minDLen, maxDLen = ar.findMinAndMaxDomainLength(non_com_domains)
	# next we gather the domains from across tlds
	domains_hash = ar.findCandidatesAcrossDomains(domains_hash, minDLen, maxDLen)

	#finally we gather web info for all of our candidates.
	for key_tld in domains_hash.keys():
		domains_for_tld = domains_hash[key_tld]
		for i, e in enumerate(domains_for_tld):
			domains_for_tld[i].candidates_within = self.populateAllCandidates(e.candidates_within)
			domains_for_tld[i].candidates_across = self.populateAllCandidates(e.candidates_across)
		domains_hash[key_tld] = domains_for_tld

	# we now record our data
	ar.recordInfoForDomains(domains_hash)	
	ar.recordErrors()
	sys.exit(0)

if __name__ == "__main__":
	main(sys.argv)



