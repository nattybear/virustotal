from urllib.request import Request, urlopen
from urllib.parse import urlencode
from json import loads

def report(apikey, resource):
	url = 'https://www.virustotal.com/vtapi/v2/file/report'
	params = {'apikey': apikey, 'resource': resource}
	data = urlencode(params).encode('ascii')
	req = Request(url, data=data)
	res = urlopen(req)
	code = res.getcode()

	if code != 200:
		print('Status code is not 200')
		exit()

	json = res.read().decode('utf-8')
	res.close()
	return loads(json)
