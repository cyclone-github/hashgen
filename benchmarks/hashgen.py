import hashlib
import sys

# script by cyclone to generate md5 hashes
# requires python3
# tested with python v3.9.2
# version 2022-12-16.0900

for stdLine in sys.stdin:
	line = stdLine.rstrip()
	md5Hash = hashlib.md5(line.encode('UTF-8'))
	if len(md5Hash.hexdigest()) == 32:
		print(md5Hash.hexdigest())
	else:
		break
