import os
import os.path
import gzip
import sys
from webpage_info import WebPageInfoGetter
from whois_registrant import Whois_Parser
#from alexa_list import Alexa_Reader

#TODO Questions:

class clTldParser(object):
	def __init__(self, data_path, download_files):
		#path to all tld data
		self.data_files = data_path
		#non-alphanumeric chars that can be in domains
		self.valid_replace_chars = ["-", "_"]
		#hash-table of actual domains for current tld
		self.current_tld_domains = {}
		self.ctypos = []
		self.download = download_files
		self.recordCtypos=False
		self.recordDomainInfo=True
		#self.alexa_reader = Alexa_Reader("somefilepath")
		#self.alexa_reader.readListIntoMemory(500)

	############################# PUBLIC API METHODS ######################

	def download_files(self, path_to_downloader):
		"""
		@param path_to_downloader the path to the download api module
		"""
		os.system("python {}".format(path_to_downloader))


	def unzip_files(self, path_to_zips):
		"""
		@param path_to_zips the path to the gzipped tlds
		@return a list of unzipped file names
		"""
		unzipped_files = []
		all_files = os.listdir(self.data_files)
		for entry in all_files:
			if ".gz" in entry:
				os.system("gunzip {}/{}".format(self.data_files, entry))
		all_files = os.listdir(self.data_files)
		for entry in all_files:
			if ".gz" not in entry:
				unzipped_files.append("{}/{}".format(self.data_files, entry))
		return unzipped_files


	def collect_all_data(self):
		"""
		Method that collects all data
		"""
		tld_no_ns_records = []
		tld = ''
		#download the files using downloader module
		if self.download: self.download_files("{}/../download.py".format(self.data_files))
		#unzip all gzipped files
		#unzipped_files = self.unzip_files(self.data_files)
		#read through all lines in each file
		for zone_file_name in os.listdir(self.data_files): #loop through all data files
			if '.gz' not in zone_file_name:
				continue
			with gzip.open(self.data_files + '/' + zone_file_name) as zone_file:
				for i, line in enumerate(zone_file): #loop through all lines in data file storing in memory
					line_parts = line.split()
					domain_name_from_line = line_parts[0]
					domain_name_from_line = domain_name_from_line[:-1] #get rid of trailing period
					if i == 0: #save off the actual tld
						tld = domain_name_from_line
					#TODO: validate if this domain is a valid site
					if domain_name_from_line not in self.current_tld_domains and line_parts[3] == 'ns' and domain_name_from_line != tld:
						self.current_tld_domains[domain_name_from_line] = [zone_file_name] #TODO: store info in this list
			if len(self.current_tld_domains.keys()) == 0:
				tld_no_ns_records.append(tld)
				continue #no ns records found in the file... continue
			#self._generate_ctypos()
			#*********************** BEGIN DATA RECORDING **************************
			#record the number of candidate typos within a top level domain
			#self._record_numberof_ctypos("../../data/candidate-typos-quantity.data", self.recordCtypos)
			#gather domain specific info
			for domain in self.current_tld_domains.keys():
				self._record_domain_info(domain, tld, "/home/engelsjo/Documents/Research/tld_file_parser/data/{}.data".format(self.current_tld_domains[domain][0][:-3]), self.recordDomainInfo)	
			#clear all the memory for the next zone file
			self.ctypos = [] #reset for next file
			self.current_tld_domains = {} #reset for next file
		self._record_no_ns_records(tld_no_ns_records, "/home/engelsjo/Documents/Research/tld_file_parser/data/no_ns_lines.data")


	############################# PRIVATE HELPER METHODS ###################

	def _record_numberof_ctypos(self, filename, switch=True):
		"""
		Method that writes the number of ctypos existing within each tld
		@param filename: the name of the file you want to write to.
		@param switch: set this to false if you dont want to write to this file
		"""
		if not switch:
			return
		with open(filename, 'a') as candidate_data_file:
			domain_parts = self.current_tld_domains.keys()[0].split(".")
			for elem in reversed(domain_parts):
				if elem != '':
					tld = elem
					break;
			candidate_data_file.write("Zone file for tld: {}\n".format(tld))
			candidate_data_file.write("Total Number of domains in tld = {}\n".format(len(self.current_tld_domains.keys())))
			candidate_data_file.write("Number of candidate typos = {}\n".format(len(self.ctypos)))
			percent = ((len(self.ctypos) * 1.0) / (len(self.current_tld_domains.keys()) * 1.0)) * 100.0
			candidate_data_file.write("Percent of domains that are candidates = {}%\n\n".format(percent))

	def _record_no_ns_records(self, tld_no_ns_records, filename, switch=True):
		"""
		Record the tld that have no domains with ns 
		"""
		if not switch:
			return
		with open(filename, 'a') as no_ns_file:
			for tld in tld_no_ns_records:
				no_ns_file.write("No NS for TLD: {}\n".format(tld))

	def _record_domain_info(self, a_domain, a_tld, a_file, switch=True):
		"""
		Record all information for a domain 
		"""
		exceptions = []
		domain_ctypos = self._generate_ctypos_for_domain(a_domain)
		#first we grab all the content we can via loading up the url
		try:
			wpg = WebPageInfoGetter(a_domain)
			wpg.setUpGetter(a_domain)
		except Exception as e:
			exceptions.append(e)
		try:
			nilsimsa = wpg.getNilsimsaHash(a_domain, False)
		except Exception as e:
			nilsimsa = None
			exceptions.append(e)
		try:
			image = wpg.getImageHash(a_domain, False)
		except Exception as e:
			image = None
			exceptions.append(e)
		try:
			redirects = wpg.getNumberOfRedirects(a_domain, False)
		except Exception as e:
			redirects = None
			exceptions.append(e)

		#next we grab all the whois content
		whois_server_found = False
		try:
			whois_parser = Whois_Parser()
			whois_server = whois_parser.server_info['.' + a_tld][0]
			whois_server_found = True
		except Exception as e:
			whois_server_found = False
			exceptions.append(e)
		try:
			if whois_server_found: 
				creation_date = whois_parser.getCreationDate(a_domain, whois_server)
			else:
				creation_date = None
		except Exception as e:
			creation_date = None
			exceptions.append(e)
		try:
			if whois_server_found: 
				privacy_prot = whois_parser.isWhoisPrivacyProtected(a_domain, whois_server)
			else:
				privacy_prot = None
		except Exception as e:
			privacy_prot = None
			exceptions.append(e)
		try:
			if whois_server_found: 
				is_parking = whois_parser.isParking(a_domain, whois_server)
			else:
				is_parking = None
		except Exception as e:
			is_parking = None
			exceptions.append(e)

		#next we grab Alexa info
		#try:
		#	is_top = self.alexa_reader.isDomainInAlexaTop(a_domain)
		#except Exception as e:
		#	is_top = None
		#	exceptions.append(e)

		with open(a_file, "a") as data_fp:
			#write out all of our data to the file
			data_fp.write("-Domain: {}\n".format(a_domain))
			data_fp.write("NumberOfCandidates: {}\n".format(len(domain_ctypos)))
			data_fp.write("Candidates: {}\n".format(str(domain_ctypos)))
			data_fp.write("Nilsimsa: {}\n".format(nilsimsa))
			data_fp.write("ImageHash: {}\n".format(image))
			data_fp.write("Redirects: {}\n".format(redirects))
			data_fp.write("CreationDate: {}\n".format(creation_date))
			data_fp.write("Privacy: {}\n".format(privacy_prot))
			data_fp.write("Parking: {}\n".format(is_parking))
			for exception in exceptions:
				data_fp.write("Exception: {}\n".format(exception))
			#data_fp.write("AlexaTop: {}\n".format(is_top))

	def _generate_typos(self, domain_name):
		"""
		Method returns a list of typos 'off by one'
		@param domain_name: The domain you wish to generate typos for.
		@return a list of generated typos
		"""
		#generate miss-spellings from 0-9 digits
		gtypos_from_digits = self._generate_one_char_off(domain_name, range(48, 58))
		#generate miss-spellings from a-z
		gtypos_from_lowercase = self._generate_one_char_off(domain_name, range(97, 123))
		#generate miss-spellings from A-Z
		#gtypos_from_uppercase = self._generate_one_char_off(domain_name, range(65, 91))
		#generate typos from special chars
		gtypos_from_specials = self._generate_one_char_off(domain_name, ascii_range=None, using_specials=True)
		#generate transpose errors
		gtypos_from_transpose = self._generate_transpose(domain_name)
		#generate addition typos from 0-9 digits
		gtypos_from_addition_digits = self._generate_addition_typos(domain_name, range(48, 58))
		#generate addition typos from a-z
		gtypos_from_addition_lower = self._generate_addition_typos(domain_name, range(97, 123))
		#generate addition typos from A-Z
		#gtypos_from_addition_upper = self._generate_addition_typos(domain_name, range(65, 91))
		#generate addition typos from special chars
		gtypos_from_addition_specials = self._generate_addition_typos(domain_name, ascii_range=None, using_specials=True)
		#generate subtraction typos from 0-9 digits
		gtypos_from_subtract = self._generate_subtract_typos(domain_name)
		
		all_gtypos = gtypos_from_digits + gtypos_from_lowercase + gtypos_from_specials \
										+ gtypos_from_transpose + gtypos_from_addition_digits + \
										gtypos_from_addition_lower + gtypos_from_addition_specials \
										+ gtypos_from_subtract
		return all_gtypos

	def _generate_typos_inhash(self, domain_name):
		"""
		Does the same work as _generate_typos but returns a hash map instead of a list
		"""
		all_typos_hash = {}
		#generate miss-spellings from 0-9 digits
		gtypos_from_digits = self._generate_one_char_off(domain_name, range(48, 58))
		for typo in gtypos_from_digits: all_typos_hash[typo] = 1
		#generate miss-spellings from a-z
		gtypos_from_lowercase = self._generate_one_char_off(domain_name, range(97, 123))
		for typo in gtypos_from_lowercase: all_typos_hash[typo] = 1
		#generate miss-spellings from A-Z
		#gtypos_from_uppercase = self._generate_one_char_off(domain_name, range(65, 91))
		#for typo in gtypos_from_uppercase: all_typos_hash[typo] = 1
		#generate typos from special chars
		gtypos_from_specials = self._generate_one_char_off(domain_name, ascii_range=None, using_specials=True)
		for typo in gtypos_from_specials: all_typos_hash[typo] = 1
		#generate transpose errors
		gtypos_from_transpose = self._generate_transpose(domain_name)
		for typo in gtypos_from_transpose: all_typos_hash[typo] = 1
		#generate addition typos from 0-9 digits
		gtypos_from_addition_digits = self._generate_addition_typos(domain_name, range(48, 58))
		for typo in gtypos_from_addition_digits: all_typos_hash[typo] = 1
		#generate addition typos from a-z
		gtypos_from_addition_lower = self._generate_addition_typos(domain_name, range(97, 123))
		for typo in gtypos_from_addition_lower: all_typos_hash[typo] = 1
		#generate addition typos from A-Z
		#gtypos_from_addition_upper = self._generate_addition_typos(domain_name, range(65, 91))
		#for typo in gtypos_from_addition_upper: all_typos_hash[typo] = 1
		#generate addition typos from special chars
		gtypos_from_addition_specials = self._generate_addition_typos(domain_name, ascii_range=None, using_specials=True)
		for typo in gtypos_from_addition_specials: all_typos_hash[typo] = 1
		#generate subtraction typos from 0-9 digits
		gtypos_from_subtract = self._generate_subtract_typos(domain_name)
		for typo in gtypos_from_subtract: all_typos_hash[typo] = 1

		return all_typos_hash

	def _generate_ctypos_for_domain(self, a_domain):
		"""
		Method to generate candidate typos for a particular domain
		"""
		gtypos = self._generate_typos(a_domain)
		local_ctypes = []
		for typo in gtypos:
			if typo in self.current_tld_domains and typo not in local_ctypes:
				local_ctypes.append(typo)
		return local_ctypes

	def _generate_ctypos(self):
		"""
		Method to generate candidate typos from a zone file
		"""
		for domain in self.current_tld_domains.keys():
			local_ctypes = self._generate_ctypos_for_domain(domain)
			self.ctypos += local_ctypes

	def _generate_one_char_off(self, domain_name, ascii_range=None, using_specials = False):
		"""
		Method that generates typos using substitution of domain name given a range of 
		ascii values to use as possible character typos.
		@param domain_name: domain you wish to generate one char off typos
		@param ascii_range: a python range correlating to the start ascci value and stop ascii value in table
		@param using_specials: if true, the list returned will be values generated using non-alphanumeric chars 
		for substitution.
		@return a list of one char off typos
		"""
		gtypos = []
		if using_specials:
			#generate typos using list of special characters
			domain_name_list = list(domain_name)
			for rep_i, char_val in enumerate(domain_name_list):
				for special_char in self.valid_replace_chars:
					domain_name_list[rep_i] = special_char
					if special_char != char_val:
						gtypos.append(''.join(domain_name_list))
				domain_name_list[rep_i] = char_val #reset domain to original name
				domain_name = ''.join(domain_name_list)
		else:
			domain_name_list = list(domain_name)
			for rep_i, char_val in enumerate(domain_name_list):
				for gchar_ascii in ascii_range:
					domain_name_list[rep_i] = chr(gchar_ascii)
					if chr(gchar_ascii) != char_val:
						gtypos.append(''.join(domain_name_list))
				domain_name_list[rep_i] = char_val #reset domain to original name
				domain_name = ''.join(domain_name_list)
		return gtypos

	def _generate_addition_typos(self, domain_name, ascii_range=None, using_specials=False):
		"""
		Method to generate typos via addition of one character
		@param domain_name: The domain name that you are generating typos for
		"""
		gtypos = []
		if using_specials:
			domain_name_list = list(domain_name)
			for rep_i in range(len(domain_name) + 1):
				for gchar_ascii in self.valid_replace_chars:
					domain_name_list.insert(rep_i, gchar_ascii)
					gtypos.append(''.join(domain_name_list))
					domain_name_list.pop(rep_i)
		else:
			domain_name_list = list(domain_name)
			for rep_i in range(len(domain_name) + 1):
				for gchar_ascii in ascii_range:
					domain_name_list.insert(rep_i, chr(gchar_ascii))
					gtypos.append(''.join(domain_name_list))
					domain_name_list.pop(rep_i)
		return gtypos

	def _generate_subtract_typos(self, domain_name):
		"""
		Method to generate typos via subtraction of one character
		@param domain_name: The domain name that you are generating typos for
		"""
		gtypos = []
		domain_name_list = list(domain_name)
		for i in range(len(domain_name_list)):
			x = domain_name_list.pop(i)
			gtypos.append(''.join(domain_name_list))
			domain_name_list.insert(i, x)
		return gtypos

	def _generate_transpose(self, domain_name):
		"""
		Method to generate typos of character off by one
		@param domain_name: The domain name you wish to generate transpose errors on.
		@return a list of generated typos
		"""
		gtypos = []
		domain_name_list = list(domain_name)
		for i in range(len(domain_name) - 1):
			temp = domain_name_list[i]
			domain_name_list[i] = domain_name_list[i + 1]
			domain_name_list[i + 1] = temp
			generated_domain = ''.join(domain_name_list)
			if generated_domain != domain_name:
				gtypos.append(generated_domain)
			domain_name_list = list(domain_name)
		return gtypos

def usage():
	usage = """
	USAGE:

	Arguments:
	1.) 'directory holding the file(s) you wish to parse'
	2.) -d 'flag indicating that you wish to download the zonefiles'
	"""
	return usage

def main(argv):
	"""
	Main method, taking in command line arguments if present.
	"""
	#no arguments were passed
	if len(argv) == 1:
		#use default paths
		tld_paths = "../data/zonefiles"
		downloadFiles=False
		clTldParser(tld_paths, downloadFiles).collect_all_data()
	elif len(argv) == 2 and argv[1] == "-d":
		#use default path only
		tld_paths = "../data/zonefiles"
		#download files has been requested
		downloadFiles=True
		clTldParser(tld_paths, downloadFiles).collect_all_data()
	elif len(argv) == 2 and os.path.isdir(argv[1]):
		#use the default path only
		tld_paths = argv[1]
		downloadFiles=False
		clTldParser(tld_paths, downloadFiles).collect_all_data()
	elif len(argv) == 3 and os.path.isdir(argv[1]) and argv[2] == "-d":
		#use both passed args
		tld_paths = argv[1]
		downloadFiles=True
		clTldParser(tld_paths, downloadFiles).collect_all_data()
	else:
		print(usage())

if __name__ == "__main__":
	try:
		main(sys.argv)
	except KeyboardInterrupt as e:
		print("\nProgram terminated by end user\n")


