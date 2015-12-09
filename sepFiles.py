"""
seperate the files in the zone file dir
"""
import os


def doWork(aZoneFileDir):
	zonefiles = sorted(os.listdir(aZoneFileDir))

	for i in range(25):
		newFolder = "{}/zonefiles_{}".format(aZoneFileDir, i)
		os.system("mkdir {}".format(newFolder))
		#25 computers
		if len(zonefiles) >= 21:
			#grab 21 files
			for j in range(21):
				fileToMove = zonefiles.pop(0)
				mvCmd = "mv {}/{} {}".format(aZoneFileDir, fileToMove, newFolder)
				os.system(mvCmd)
		else:
			for fileRemaining in zonefiles:
				mvCmd = "mv {}/{} {}".format(aZoneFileDir, fileRemaining, newFolder)
				os.system(mvCmd)


if __name__ == "__main__":
	doWork("/home/engelsjo/Documents/Research/data/zonefiles")


