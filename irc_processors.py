
import json
import traceback
import datetime
import urlparse
import socket
from netaddr import IPNetwork, IPAddress

# TODO: find a nicer solution
SERVICES = {
	3306: 'MySQL',
	80: 'HTTP',
	21: 'FTP',
	445: 'SMB',
	22: 'SSH',
}

MSG_TEMPLATE = "\x03\x34<\x03%s\x03\x34>\x03 New attack from \x02%s, %s\x02 (%f,%f) to \x02%s, %s\x02 (%f,%f) %s"
class ezdict(object):
	def __init__(self, d):
		self.d = d
	def __getattr__(self, name):
		return self.d.get(name, None)

# time string
def timestr(dt):
	return dt.strftime("%Y-%m-%d %H:%M:%S")

# geoloc_none
def geoloc_none(t):
	if t == None: return {'latitude': None, 'longitude': None, 'city': None, 'country_name': None, 'country_code': None}
	if t['city'] != None: t['city'] = t['city'].decode('latin1')
	return t

def get_addr_family(addr):
		ainfo = socket.getaddrinfo(addr, 1, socket.AF_UNSPEC, socket.SOCK_STREAM)
		return ainfo[0][0]

def glastopf_event(identifier, payload, gi):
	try:
		dec = ezdict(json.loads(str(payload)))
		req = ezdict(dec.request)
		sip, sport = dec.source
		tstamp = datetime.datetime.strptime(dec.time, '%Y-%m-%d %H:%M:%S')
	except:
		print 'exception processing glastopf event', repr(payload)
		traceback.print_exc()
		return

	if dec.pattern == 'unknown': return None

	a_family = get_addr_family(sip)
	if a_family == socket.AF_INET:
		geoloc = geoloc_none( gi[a_family].record_by_addr(sip) )
	elif a_family == socket.AF_INET6:
		geoloc = geoloc_none( gi[a_family].record_by_addr_v6(sip) )
	return ("<%s> New attack from %s, %s (%f,%f)" % ('glastopf.events', geoloc['city'], geoloc['country_name'], geoloc['latitude'], geoloc['longitude']))
	#return {'type': 'glastopf.events', 'sensor': identifier, 'time': str(tstamp), 'latitude': geoloc['latitude'], 'longitude': geoloc['longitude'], 'source': sip, 'city': geoloc['city'], 'country': geoloc['country_name'], 'countrycode': geoloc['country_code']}

# TODO: Make optional!
def getSourceAddr(saddr, daddr):
	if IPAddress(saddr) in IPNetwork("192.168.0.0/16") or IPAddress(saddr) in IPNetwork("10.0.0.0/8"):
		return daddr;
	else:
		return saddr;

def dionaea_capture(identifier, payload, gi):
	try:
		dec = ezdict(json.loads(str(payload)))
		tstamp = datetime.datetime.now()
	except:
		print 'exception processing dionaea event'
		traceback.print_exc()
		return

	a_family = get_addr_family(dec.saddr)
	if a_family == socket.AF_INET:
		geoloc = geoloc_none( gi[a_family].record_by_addr(getSourceAddr(dec.saddr, dec.daddr)) )
		geoloc2 = geoloc_none( gi[a_family].record_by_addr(dec.daddr) )
	elif a_family == socket.AF_INET6:
		geoloc = geoloc_none( gi[a_family].record_by_addr_v6(dec.saddr) )
		geoloc2 = geoloc_none( gi[a_family].record_by_addr_v6(dec.daddr) )

	md5hash = ("\x03\x32[\x03\x315md5: %s\x03\x32]\x03" % dec.md5) if dec.md5 != 'null' else ""
	return (MSG_TEMPLATE % ('dionaea.capture', geoloc['city'], geoloc['country_name'], geoloc['latitude'], geoloc['longitude'], geoloc2['city'], geoloc2['country_name'], geoloc2['latitude'], geoloc2['longitude'], md5hash))
	#return {'type': 'dionaea.capture', 'sensor': identifier, 'time': timestr(tstamp), 'latitude': geoloc['latitude'], 'longitude': geoloc['longitude'], 'source': getSourceAddr(dec.saddr, dec.daddr), 'latitude2': geoloc2['latitude'], 'longitude2': geoloc2['longitude'], 'dest': dec.daddr, 'md5': dec.md5,
#'city': geoloc['city'], 'country': geoloc['country_name'], 'countrycode': geoloc['country_code'],
#'city2': geoloc2['city'], 'country2': geoloc2['country_name'], 'countrycode2': geoloc2['country_code']}

def dionaea_connections(identifier, payload, gi):
	try:
		dec = ezdict(json.loads(str(payload)))
		tstamp = datetime.datetime.now()
	except:
		print 'exception processing dionaea event'
		traceback.print_exc()
		return

	a_family = get_addr_family(dec.remote_host)
	if a_family == socket.AF_INET:
		geoloc = geoloc_none( gi[a_family].record_by_addr(getSourceAddr(dec.remote_host, dec.local_host)) )
		geoloc2 = geoloc_none( gi[a_family].record_by_addr(dec.local_host) )
	elif a_family == socket.AF_INET6:
		geoloc = geoloc_none( gi[a_family].record_by_addr_v6(dec.remote_host) )
		geoloc2 = geoloc_none( gi[a_family].record_by_addr_v6(dec.local_host) )
	if dec.local_port in SERVICES:
		service = "(%s)" % SERVICES[dec.local_port]
	else:
		service = "(Port: %d)" % dec.local_port
	return (MSG_TEMPLATE % ('dionaea.connections', geoloc['city'], geoloc['country_name'], geoloc['latitude'], geoloc['longitude'], geoloc2['city'], geoloc2['country_name'], geoloc2['latitude'], geoloc2['longitude'], service))
	#return {'type': 'dionaea.connections', 'sensor': identifier, 'time': timestr(tstamp), 'latitude': geoloc['latitude'], 'longitude': geoloc['longitude'], 'source': getSourceAddr(dec.remote_host, dec.local_host), 'latitude2': geoloc2['latitude'], 'longitude2': geoloc2['longitude'], 'dest': dec.local_host, 'md5': dec.md5,
#'city': geoloc['city'], 'country': geoloc['country_name'], 'countrycode': geoloc['country_code'],
#'city2': geoloc2['city'], 'country2': geoloc2['country_name'], 'countrycode2': geoloc2['country_code']}
def dionaea_dcerpcrequests(identifier, payload, gi):
	#print "dionaea_dcerpcrequests"
	#try:
	#	dec = ezdict(json.loads(str(payload)))
	#	tstamp = datetime.datetime.now()
	#except:
	#	print 'exception processing dionaea event'
	#	traceback.print_exc()
	#	return
	#print dec
	#return "dionaea_dcerpcrequests"
	return
def dionaea_shellcodeprofiles(identifier, payload, gi):
	#print "dionaea_shellcodeprofiles"
	#try:
	#	dec = ezdict(json.loads(str(payload)))
	#	tstamp = datetime.datetime.now()
	#except:
	#	print 'exception processing dionaea event'
	#	traceback.print_exc()
	#	return
	#print dec
	#return "dionaea_shellcodeprofiles"
	return

def mwbinary_dionaea_sensorunique(identifier, payload, gi):
	print "mwbinary_dionaea_sensorunique"
	#try:
	#	dec = ezdict(json.loads(str(payload)))
	#	tstamp = datetime.datetime.now()
	#except:
	#	print 'exception processing dionaea event'
	#	traceback.print_exc()
	#	return
	#print dec
	#return "mwbinary_dionaea_sensorunique"
	return