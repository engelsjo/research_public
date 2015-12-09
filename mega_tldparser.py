"""
subclass of tldparser to handle collecting data from more 
popular top level domains that require larger amounts of memory
"""

from tldparser import clTldParser
from webpage_info import WebPageInfoGetter
from whois_registrant import Whois_Parser
from datetime import datetime
import gzip
import os
import sys

class clMegaTldParser(clTldParser):
	def __init__(self, candidateTypoFP="../data/comzonefile/splitfiles/", data_path=""):
		clTldParser.__init__(self, data_path, False)
		self.candidateTypoFP = candidateTypoFP
		self.candidatesCount = 0
		self.domainCount = 0
		self.startTime = datetime.now()

	def _loadCurrPrevAndNextFromFile(self, aFile):
		"""
		Helper method that loads in the current, previous and next files for a file passed
		into memory. Used for the big tld files... we want to put all domains of length n, n-1,
		and n+1 into a folder. Then each of these three files is loaded into memory so we can search
		for candidates
		@param aFile: the current file to navigate
		"""
		currMegaFile = previousMegaFile = nextMegaFile = {}
		#first some prelim error checks
		megaFiles = os.listdir(self.candidateTypoFP)
		if aFile not in megaFiles:
			raise Exception("File {} does not exist in directory {}".format(aFile, self.candidateTypoFP))
		currLen = int(aFile.split("_")[1][:-3])
		aFileBase = aFile.split("_")[0]
		aPrevStr = "{}_{}".format(aFileBase, str(currLen-1))
		aNextStr = "{}_{}".format(aFileBase, str(currLen+1))
		currMegaFile = self.loadFiles([aFile])
		if aPrevStr in megaFiles:
			previousMegaFile = self.loadFiles([aPrevStr])
		if aNextStr in megaFiles:
			nextMegaFile = self.loadFiles([aNextStr])
		return {
			"previous" : previousMegaFile,
			"current" : currMegaFile, 
			"next" : nextMegaFile
		}

	def navigateZoneFile(self, aGzipFile, aTLD="com"):
		"""
		Method to navigate all the domains -- and their candidates -- in a file
		"""
		dataFileName = aGzipFile.split('.')[0]
		#load the appropriate files into memory
		tld_files = self._loadCurrPrevAndNextFromFile(aGzipFile)
		for domain in tld_files["current"].keys():
			#STORE ALL INFORMATION FOR THE FILE
			#First, now that contents are in memory, go after the candidates
			candidates = []
			exceptions = []
			#generate typos for the domain in question
			gtypos = self._generate_typos_inhash(domain.lower())
			#iterate through gtypos looking if it exists in the files in memory. if so, we have a candidate
			for typo in gtypos:
				if self.isDomainCandidate(typo, tld_files["previous"], tld_files["current"], tld_files["next"]) and typo not in candidates:
					candidates.append(typo)
					
			url = domain + '.' + aTLD

			try:
				wpg = WebPageInfoGetter(url)
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

			#next we grab all the whois content
			try:
				whois_parser = Whois_Parser()
				whois_server = whois_parser.server_info['.' + aTLD][0]
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

			with open("/home/engelsjo/Documents/Research/tld_file_parser/data/{}_data/{}.data".format(aTLD, dataFileName), "a") as data_fp:
				#write out all of our data to the file
				data_fp.write("-Domain: {}\n".format(url))
				data_fp.write("NumberOfCandidates: {}\n".format(len(candidates)))
				data_fp.write("Candidates: {}\n".format(str(candidates)))
				data_fp.write("Nilsimsa: {}\n".format(nilsimsa))
				data_fp.write("ImageHash: {}\n".format(image))
				data_fp.write("Redirects: {}\n".format(redirects))
				data_fp.write("CreationDate: {}\n".format(creation_date))
				data_fp.write("Privacy: {}\n".format(privacy_prot))
				data_fp.write("Parking: {}\n".format(is_parking))
				for exception in exceptions:
					data_fp.write("Exception: {}\n".format(exception))	
		print("done with file")

	def isGtypoCandidate(self, gtypos, previousComFile, currentComFile, nextComFile):
		"""
		function that determines if any gtypo exists in the 3 files loaded into memory
		"""
		for typo in gtypos.keys():
			if self.isDomainCandidate(typo, previousComFile, currentComFile, nextComFile):
				return True
		return False

	def isDomainCandidate(self, aDomain, previousContents, currContents, nextContents):
		"""
		Does similar work to isDomainCandidate, only using a hash instead
		"""
		try:
			x = previousContents[aDomain]
		except KeyError as e:
			x = False
		try:
			y = currContents[aDomain]
		except KeyError as e:
			y = False
		try:
			z = nextContents[aDomain]
		except KeyError as e:
			z = False
		return (x or y or z)
		
	def loadFiles(self, filesList):
		retVal = {}
		for f in filesList:
			#debug tip
			#if len(f) == 1:
			#	print("Are you sure you passed filesList as a list parameter???")
			with gzip.open("{}/{}".format(self.candidateTypoFP, f), "r") as fileh:
				for line in fileh:
					if self.isDomainLine(line):
						lineParts = line.split()
						domainName = lineParts[0]
						retVal[domainName.lower()] = True
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

	def getNumberOfUniqueDomains(self, currentComFile):
		return len(currentComFile.keys())


def main(argv):
	"""
	Main driver method
	"""
	path_to_split_files = argv[1]
	tld = argv[2]

	megaFiles = os.listdir(path_to_split_files)
	megaFiles.sort(key=lambda s: int(s.split("_")[1][:-3]))

	for i, gzipped_file in enumerate(megaFiles):
		if i == 0 or i == len(megaFiles) - 1:
			#continue past the first and last file in the split files dir... this backfires on first and last dir
			# i will manually program around that later
			continue
		else:
			parser = clMegaTldParser(path_to_split_files)
			parser.navigateZoneFile(gzipped_file, tld)


if __name__ == "__main__":
	main(sys.argv)

		



