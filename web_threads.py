"""
@author: engelsjj
@date: November 6, 2015
"""

from webpage_info import WebPageInfoGetter
from whois_registrant import Whois_Parser
import threading
from time import sleep
import sys
import os
import gzip

class WebThreads(object):
	"""
	this class goes after all the web page info using threads for performance
	"""
	def __init__(self):
		self.window_size = 15
		self.threads = []
		self.window = []
		self.exceptions = []
		self.resetWindow()
		self.aTLD = "com"
		self.whois = False
		self.web_content = False
		self.debug_info = 0

	def work(self, index, domain):
		"""
		each thread does the work here
		"""
		url = domain + '.' + self.aTLD
		exceptions = []

		if self.web_content:
			#target webcontent with this thread
			try:
				wpg = WebPageInfoGetter(url)
				wpg.id += str(index)
				wpg.setUpGetter(url)
			except Exception as e:
				exceptions.append(e)
			try:
				nilsimsa = wpg.getNilsimsaHash(url, False)
			except Exception as e:
				nilsimsa = None
				exceptions.append(e)
			try:
				image = wpg.getImageHash(url, False)
			except Exception as e:
				image = None
				exceptions.append(e)
			try:
				redirects = wpg.getNumberOfRedirects(url, False)
			except Exception as e:
				redirects = None
				exceptions.append(e)
			info = "-Domain: {}\nNilsimsa: {}\nImageHash: {}\nRedirects: {}\nExceptions: {}\n".format(url, nilsimsa, image, redirects, exceptions)
			self.window[index%self.window_size] = info
		else:
			#target only the whois content with this thread
			try:
				whois_parser = Whois_Parser()
				whois_server = whois_parser.server_info['.' + self.aTLD][0]
			except Exception as e:
				exceptions.append(e)
			try:
				creation_date = whois_parser.getCreationDate(url, whois_server)
			except Exception as e:
				creation_date = None
				exceptions.append(e)
			try:
				privacy_prot = whois_parser.isWhoisPrivacyProtected(url, whois_server)
			except Exception as e:
				privacy_prot = None
				exceptions.append(e)
			try:
				is_parking = whois_parser.isParking(url, whois_server)
			except Exception as e:
				is_parking = None
				exceptions.append(e)
			info = "-Domain: {}\nCreationDate: {}\nPrivacy: {}\nParking: {}\nExceptions: {}\n".format(url, creation_date, privacy_prot, is_parking, exceptions)
			self.window[index%self.window_size] = info


	def loadFile(self, aFile, aStart, aEnd):
		"""
		Method read in the gzip file and stores it into a list
		"""
		all_file_contents = {}
		retVal = []
		with gzip.open(aFile, "r") as fileh:
			for line in fileh:
				if self.isDomainLine(line):
					lineParts = line.split()
					domainName = lineParts[0]
					all_file_contents[domainName.lower()] = True

		line_number = 0
		for key in sorted(all_file_contents.keys()):
			if line_number < aStart:
				line_number += 1
				continue
			if line_number >= aEnd:
				line_number += 1
				continue
			retVal.append(key)
			line_number += 1
		#return list of all the domains from start index to end index but not including end index
		return retVal

	def isDomainLine(self, fileline):
		"""
		Helper to return if the line is a line with a domain name etc...
		"""
		lineParts = fileline.split()
		if len(lineParts) < 3:
			return False
		if lineParts[1].lower() == "ns":
			return True
		return False

	def resetWindow(self):
		self.window = []
		for i in range(self.window_size):
			self.window.append('')


	def main(self, args):
		if len(args) != 8:
			self.usage()
			sys.exit(-1)

		#parse out the args
		file_location = args[1]
		data_file_location = args[2]
		start_index = int(args[3])
		end_index = int(args[4])

		whois_or_web = args[5]
		if whois_or_web.lower() == "true":
			self.web_content = True
		else:
			self.whois = True
		self.aTLD = args[6]
		self.window_size = int(args[7])
		self.resetWindow()

		if not os.path.isfile(file_location) or not os.path.isdir(data_file_location):
			print("you must pass a valid source and destination file location")
			sys.exit(-2)

		domains = self.loadFile(file_location, start_index, end_index)
		print(len(domains))

		#set up the name of your output file
		filename = file_location.split("/")[-1]
		if whois_or_web.lower() == "true":
			name = "{}/web_{}_{}-{}.data".format(data_file_location, filename, start_index, end_index)
		else:
			name = "{}/whois_{}_{}-{}.data".format(data_file_location, filename, start_index, end_index)

		
		#run 40 threads in parallel
		for index in xrange(0,len(domains),self.window_size):
			self.debug_info = index
			threads = []
			for i in range(self.window_size):
				try:
					line = domains[index + i]
					t = threading.Thread(target=self.work, kwargs={"index" : (index + i), "domain" : line})
					t.start()
					threads.append(t)
				except Exception as e:
					print(e)
			# join all threads to make sure they all finish before moving on
			for thread in threads:
				thread.join()
			with open(name, "a") as fh:
				for text in self.window:
					fh.write(text)
			#reset the window
			self.resetWindow()

	def usage(self):
		error_msg = """
			You must pass 1.) A location file to read from
						  2.) A location file to write too.
						  3.) You must pass an index to begin at in the file
						  4.) You must pass an index to end at in the file
						  5.) You must pass in whether or not you want whois or web content. True means web, False means whois
						  6.) You must pass in a valid top level domain
						  7.) You must pass in a window size
			"""
		print(error_msg)
			
if __name__ == "__main__":
	wt = WebThreads()
	try:
		wt.main(sys.argv)
	except KeyboardInterrupt as e:
		print("\nProgram terminated by end user\n")	
		print("current index {}".format(wt.debug_info))


