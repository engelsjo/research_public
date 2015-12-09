"""
Parse the alexa list for all of the tld's involved in the top n
"""
import sys

tlds_hash = {}

tlds_we_have = []
tlds_we_have.append('net')
tlds_we_have.append('org')
tlds_we_have.append('biz')

def main(args):

	n = int(args[1])

	# first read in the alexa top n
	with open("/home/engelsjo/Documents/Research/tld_file_parser/data/alexa_list/top-1m.csv", "r") as fh:
		for line in fh:
			line_parts = line.split(',')
			try:
				line_number = int(line_parts[0].strip())
				domain = line_parts[1].strip()
				domain_tld = domain.split('.')[1]

				# dont add anything new to the list if we hit n
				if line_number == n:
					break;

				if domain_tld not in tlds_hash.keys():
					tlds_hash[domain_tld] = 1
				else:
					tlds_hash[domain_tld] += 1
			except Exception as e:
				print(str(e))

	number_of_tlds = len(tlds_hash.keys())
	print("number of tld's in top {} of alexa is {}".format(n, number_of_tlds))

	# read in all of our tlds from the whois server file
	with open("/home/engelsjo/Documents/Research/tld_file_parser/data/whois_servers.data", "r") as fh:
		for line in fh:
			try:
				if line[0] == '.':
					#we have a tld line
					line_parts = line.split(':')
					tld = line_parts[0][1:].strip()
					if tld not in tlds_we_have:
						tlds_we_have.append(tld)
			except Exception as e:
				print(str(e))

	
	print('\n********* TLD we have access for and are in alexa top n *********')
	for key, value in reversed(sorted(tlds_hash.items(), key=lambda x: x[1])):
		if key in tlds_we_have:
			print("Key: {} Value: {} Access: True".format(key, value))

	print('\n********* TLD we dont have access for and are in alexa top n *********')
	for key, value in reversed(sorted(tlds_hash.items(), key=lambda x: x[1])):
		if key not in tlds_we_have:
			print("Key: {} Value: {} Access: False".format(key, value))




if __name__ == "__main__":
	main(sys.argv)