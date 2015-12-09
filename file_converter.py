"""
Python module to convert the formats of the different TLD files
"""
import os
import gzip
from random import randint

def convertCOMStuff():
	com_dirs_path = "/home/engelsjo/Documents/Research/tld_file_parser/data/comzonefile/splitfiles"
	com_folders = os.listdir(com_dirs_path)

	for folder in com_folders:
		com_folder_path = com_dirs_path + "/" + folder
		files_in_folder = os.listdir(com_folder_path)
		for com_file in files_in_folder:
			com_file_path = com_folder_path + "/" + com_file
			print("reading in {}".format(com_file_path))
			file_contents = {}
			#read in the old file
			with gzip.open(com_file_path, "r") as fh:
				for line in fh:
					line_parts = line.split()
					if len(line_parts) == 0:
						continue
					domain = line_parts[0].lower()
					file_contents[domain] = None
			#remove the old file
			os.system("rm -f {}".format(com_file_path))
			#write out the new file
			print("writing new file {}".format(com_file_path))
			with gzip.open(com_file_path, "w") as fh:
				for key in sorted(file_contents.keys()):
					fh.write(key.lower()+"\n")

def convertNewGTLDs():
	zone_dir_path = "/home/engelsjo/Documents/Research/tld_file_parser/data/zonefiles"
	zone_files = os.listdir(zone_dir_path)
	for zone_file in zone_files:
		if ".gz" not in zone_file:
			continue
		zone_file_path = zone_dir_path + '/' + zone_file
		print("reading in {}".format(zone_file_path))
		file_contents = {}
		tld = ''
		# read in the old file
		with gzip.open(zone_file_path, "r") as fh:
			for i, line in enumerate(fh): #loop through all lines in data file storing in memory
				line_parts = line.split()
				domain_name_from_line = line_parts[0]
				domain_name_from_line = domain_name_from_line[:-1] #get rid of trailing period
				if i == 0: #save off the actual tld
					tld = domain_name_from_line
				#remove the tld
				parts = domain_name_from_line.split('.')
				parts.pop()
				domain_name_from_line = ''
				for part in parts:
					domain_name_from_line += (part + '.')
				domain_name_from_line = domain_name_from_line[:-1]
				if domain_name_from_line not in file_contents and line_parts[3].lower() == 'ns' and domain_name_from_line != tld:
					file_contents[domain_name_from_line] = None
		#remove the old file
		os.system("rm -f {}".format(zone_file_path))
		#write out the new file from memory
		print("writing new file {}".format(zone_file_path))
		with gzip.open(zone_dir_path + '/' + tld + '.gz', "w") as fh:
			for key in sorted(file_contents.keys()):
				if key.strip() == "":
					continue
				fh.write(key.lower()+'\n')

def applyAlexaProbabilities():
	alexa_dir = "/home/engelsjo/Documents/Research/tld_file_parser/data/alexa_list"
	alexa_lines = []
	# read in the file contents.
	with open(alexa_dir + "/" + "top-1m.csv", "r") as fh:
		for line in fh:
			alexa_lines.append(line)
	# delete the old file
	os.system("rm -f {}/top-1m.csv".format(alexa_dir))
	# write out the new alexa file
	with open("{}/top-1m.csv".format(alexa_dir), "w") as fh:
		for line in alexa_lines:
			rand_nbr = randint(1,100)
			fh.write(line.strip().lower() + ",{}\n".format(str(rand_nbr)))

def convertNET():
	net_file_path = "/home/engelsjo/Documents/Research/tld_file_parser/data/otherzones/net.zone.gz"
	print("reading in {}".format(net_file_path))
	file_contents = {}
	tld = 'net'
	# read in the old file
	with gzip.open(net_file_path, "r") as fh:
		for i, line in enumerate(fh):
			line_parts = line.strip().split()
			if len(line_parts) < 2: continue
			if line_parts[1].lower() == "ns":
				file_contents[line_parts[0].lower()] = None
	# remove the old file
	os.system("rm -f {}".format(net_file_path))

	# write out the new file
	with gzip.open(net_file_path, "w") as fh:
		for key in sorted(file_contents.keys()):
			fh.write(key.lower()+'\n')


def convertBIZ():
	biz_file_path = "/home/engelsjo/Documents/Research/tld_file_parser/data/otherzones/biz.zone.gz"
	print("reading in {}".format(biz_file_path))
	file_contents = {}
	tld = ''
	# read in the old file
	with gzip.open(biz_file_path, "r") as fh:
		for i, line in enumerate(fh): #loop through all lines in data file storing in memory
			line_parts = line.split()
			domain_name_from_line = line_parts[0].strip()
			domain_name_from_line = domain_name_from_line[:-1] #get rid of trailing period
			if i == 0: #save off the actual tld
				tld = domain_name_from_line
			#remove the tld
			parts = domain_name_from_line.split('.')
			parts.pop()
			domain_name_from_line = ''
			for part in parts:
				domain_name_from_line += (part + '.')
			domain_name_from_line = domain_name_from_line[:-1]
			if domain_name_from_line not in file_contents and line_parts[3].lower() == 'ns' and domain_name_from_line != tld:
				file_contents[domain_name_from_line] = None
	#remove the old file
	os.system("rm -f {}".format(biz_file_path))
	#write out the new file from memory
	print("writing new file {}".format(biz_file_path))
	with gzip.open(biz_file_path, "w") as fh:
		for key in sorted(file_contents.keys()):
			fh.write(key.lower()+'\n')

def convertNAME():
	name_file = "/home/engelsjo/Documents/Research/tld_file_parser/data/otherzones/master.name.zone.gz"
	print("reading in {}".format(name_file))
	file_contents = {}
	tld = 'name'
	with gzip.open(name_file, "r") as fh:
		for i, line in enumerate(fh):
			line_parts = line.strip().split()
			if len(line_parts) < 4: continue
			if line_parts[3].lower() == "ns":
				domain_name_from_line = line_parts[0].lower()[:-1]
				# remove the tld
				parts = domain_name_from_line.split('.')
				parts.pop()
				domain_name_from_line = ''
				for part in parts:
					domain_name_from_line += (part + '.')
				domain_name_from_line = domain_name_from_line[:-1]
				# add to the hash table
				file_contents[domain_name_from_line] = None

	#remove the old file
	os.system("rm -f {}".format(name_file))

	print("writing out file {}".format(name_file))
	# write out the new file from memory
	with gzip.open(name_file, "w") as fh:
		for key in sorted(file_contents.keys()):
			if key.strip() == "" : continue
			fh.write(key.lower()+'\n')

def convertORG():
	org_file = "/home/engelsjo/Documents/Research/tld_file_parser/data/otherzones/org.zone.gz"
	print("reading in {}".format(org_file))
	file_contents = {}
	tld = "org"
	with gzip.open(org_file, "r") as fh:
		for i, line in enumerate(fh):
			line_parts = line.strip().split()
			if len(line_parts) < 2: continue
			if line_parts[1].lower() != "ns": continue
			domain_name_from_line = line_parts[0].lower()[:-1]
			#remove tld
			parts = domain_name_from_line.split('.')
			parts.pop()
			domain_name_from_line = ''
			for part in parts:
				domain_name_from_line += (part + '.')
			domain_name_from_line = domain_name_from_line[:-1]
			file_contents[domain_name_from_line] = None

	#remove the old file
	os.system("rm -f {}".format(org_file))
	print("writing out file {}".format(org_file))
	with gzip.open(org_file, "w") as fh:
		for key in sorted(file_contents.keys()):
			if key.strip() == "" : continue
			fh.write(key.lower()+'\n')

def convertMOBI():
	mobi_file = "/home/engelsjo/Documents/Research/tld_file_parser/data/otherzones/mobi.zone.gz"
	print("reading in {}".format(mobi_file))
	file_contents = {}
	tld = "mobi"
	with gzip.open(mobi_file, "r") as fh:
		for i, line in enumerate(fh):
			line_parts = line.lower().strip().split()
			if len(line_parts) < 2: continue
			if line_parts[1] != "ns": continue
			domain_name_from_line = line_parts[0][:-1]
			#remove tld
			parts = domain_name_from_line.split('.')
			parts.pop()
			domain_name_from_line = ''
			for part in parts:
				domain_name_from_line += (part + '.')
			domain_name_from_line = domain_name_from_line[:-1]
			file_contents[domain_name_from_line] = None

	#remove the old file
	os.system("rm -f {}".format(mobi_file))
	print("writing out file {}".format(mobi_file))
	with gzip.open(mobi_file, "w") as fh:
		for key in sorted(file_contents.keys()):
			if key.strip() == "" : continue
			fh.write(key.lower()+'\n')



if __name__ == "__main__":
	convertCOMStuff()
	convertNewGTLDs()
	applyAlexaProbabilities()
	convertMOBI()
	convertORG()
	convertNAME()
	convertNET()
	convertBIZ()






