from selenium import webdriver, selenium
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait # available since 2.4.0
from selenium.webdriver.support import expected_conditions as EC
from time import sleep
from PIL import Image
import imagehash
from nilsimsa import Nilsimsa

"""
Library of selenium functions
"""

class SeleniumHelpers:

	def __init__(self):
		self.aWaitTime = 10
		self.driver = webdriver.Firefox()

	def loadUrl(self, driver, url):
		'''
		@param driver: webdriver handle
		@param url: the url that you want to load
		'''
		driver.get(url)

	def findElementById(self, driver, aElement):
		"""
		@param driver: webdriver handle
		@param aElement: The element html id you want to find
		"""
		WebDriverWait(driver, self.aWaitTime).until(EC.presence_of_element_located((By.ID, aElement)))
		a_element = driver.find_element_by_id(aElement)
		return a_element

	def findElementsByTagName(self, driver, aTagType):
		"""
		@param driver: webdriver handle
		@param aTagType: the type of html tag you want to find.
		@return elementsList: a list of all the elements found with the specified tag
		"""
		WebDriverWait(driver, self.aWaitTime).until(EC.presence_of_element_located((By.TAG_NAME, aTagType)))
		elementsList = driver.find_elements_by_tag_name(aTagType)
		return elementsList

	def findElementsByTagAndClass(self, driver, aTagType, aClass):
		"""
		@param driver: webdriver handle
		@param aTagType: the type of html tag you want to find.
		@return elementsList: a list of all the elements found with the specified tag
		"""
		retVal = []
		initElements = findElementsByTagName(driver, aTagType)
		for ele in initElements:
			if ele.get_attribute("class") == aClass:
				retVal.append(aClass)
		return retVal

	def clickElement(self, driver, aElement, aBy):
		"""
		@param driver: webdriver handle
		@param aElement: the element class, name, tag, id etc you want to click
		@param aBy: the type of element you are clicking... eg by class, id or css
		"""
		if aBy == By.ID:
			findElementById(driver, aElement).click()

	def sendKeys(self, driver, aElement, aBy, aText):
		"""
		@param driver: webdriver handle
		@param aElement: the element class, name, tag, id etc you want to click
		@param aBy: the type of element you are clicking ... eg by class, id or css
		@param aText: a text to enter into the field
		"""
		if aBy == By.ID:
			findElementById(driver, aElement).send_keys(aText)

	def executeScript(self, driver, aScript):
		"""
		@param driver: webdriver handle
		@param aScript execute some javascript
		"""
		return driver.execute_script(aScript)

	def getImageHash(self, driver):
		"""
		returns an image hash of the url passed
		"""
		#take a screen shot of the browser
		driver.save_screenshot("screenie.png")
		#get and return the image hash
		image_hash = imagehash.average_hash(Image.open('screenie.png'))
		return image_hash

	def getTextualHash(self, driver):
		"""
		returns a textual hash of the url passed
		"""
		#get the html source
		html_source = driver.page_source
		#create and update our nilsimsa object with the source
		nilsimsaObj = Nilsimsa()
		nilsimsaObj.update(html_source)
		return nilsimsaObj.hexdigest()

	def cleanUp(self, driver):
		"""
		clean up the selenium drivers
		"""
		driver.quit()

if __name__ == "__main__":
	try:
		sh = SeleniumHelpers()
		sh.loadUrl(sh.driver, "http://backup.gratis")
		sh.driver.save_screenshot("screenie.png")
		sh.loadUrl(sh.driver, "http://signup.gratis")
		sh.driver.save_screenshot("screenie1.png")
		#print("Image Hash: {}".format(getImageHash(mainDriver)))
		#print("Nilsimsa Hash: {}".format(getTextualHash(mainDriver)))
	except Exception as e:
		print(e)
	finally:
		sh.driver.quit()



