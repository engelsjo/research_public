"""
Module to process the information that comes from loading a url
"""

import os
import subprocess32
subprocess = subprocess32
import sys
from PIL import Image
import imagehash
from nilsimsa import Nilsimsa

class WebPageInfoGetter(object):

	def __init__(self, url=None):
		self.url = url
		self.redirects = None
		self.image_hash = None
		self.nilsimsa_hash = None
		self.id = subprocess.check_output("hostname", shell=True).strip()

	def __str__(self):
		return "redirects: {} image_hash: {} nilsimsa_hash: {}".format(self.redirects, self.image_hash, self.nilsimsa_hash)

	def setUpGetter(self, url):
		"""
		NOTE: this method must be called for any of the methods below to work correctly
		"""
		self.redirects = -1
		try:
			info = subprocess.check_output("phantomjs load_url.js {} {}".format(url, self.id), shell=True, timeout=30)
			info = info.split("\n")
			for line in info:
				if 'Redirects: ' in line:
					self.redirects = int(line.split(":")[1].strip())
			if self.redirects == -1:
				raise Exception("Number of redirects was not returned for {}".format(url))
		except Exception as e:
			self.redirects = e.message

	def getNilsimsaHash(self, url, call_phantom=True):
		if call_phantom: self.setUpGetter(url)
		# if not output file exists, then the page failed to load
		if not os.path.isfile("{}-output.txt".format(self.id)):
			return -1
		#create and update our nilsimsa object with the source
		try:
			with open("{}-output.txt".format(self.id), "rb") as f:
				nilsimsaObj = Nilsimsa(f.read())
			#nilsimsaObj.from_file("output.txt")
			self.nilsimsa_hash = nilsimsaObj.hexdigest()
		except Exception as e:
			print(e)
		finally:
			# always remove the old file even if an exception is thrown
			os.remove('{}-output.txt'.format(self.id))
			#test = True
		return self.nilsimsa_hash

	def getImageHash(self, url, call_phantom=True):
		if call_phantom: self.setUpGetter(url)
		#get and return the image hash
		# if no image exists, then the page failed to load
		if not os.path.isfile("{}-screenie.jpeg".format(self.id)):
			return -1

		try:
			image_hash = imagehash.average_hash(Image.open('{}-screenie.jpeg'.format(self.id)))
			self.image_hash = image_hash 
		except Exception as e:
			print(e)
		finally:
			# always remove the old image even if an exception was thrown
			os.remove('{}-screenie.jpeg'.format(self.id))
			#test = True
		return self.image_hash

	def getNumberOfRedirects(self, url, call_phantom=True):
		if call_phantom: self.setUpGetter(url)
		return self.redirects


if __name__ == "__main__":
	wpg = WebPageInfoGetter()
	test_url = sys.argv[1]
	wpg.setUpGetter(test_url)
	print("Nilsimsa: {}".format(wpg.getNilsimsaHash(test_url, False)))
	print("ImageHash: {}".format(wpg.getImageHash(test_url, False)))
	print("Redirects: {}".format(wpg.getNumberOfRedirects(test_url, False)))
	# >> Nilsimsa: some_long_hex_string
	# >> ImageHash: some_long_hex_string
	# >> Redirects: some number of redirects
