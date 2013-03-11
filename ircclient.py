
import sys
import datetime
import time
import logging
import hpfeeds
from irc_processors import *
import logging

import GeoIP
import irc.client
from threading import Thread

# hpfeed settings
# TODO: Maybe put settings in a separate file
HOST = 'localhost'
PORT = 10000
CHANNELS = [
	'dionaea.connections',
	'dionaea.capture',
	'glastopf.events',
	'dionaea.dcerpcrequests',
	'dionaea.shellcodeprofiles',
	'mwbinary.dionaea.sensorunique',
]
IDENT = '<yourident>'
SECRET = '<yourpassword>'

PROCESSORS = {
	'glastopf.events': [glastopf_event,],
	'dionaea.capture': [dionaea_capture,],
	'dionaea.connections': [dionaea_connections,],
	#'dionaea.dcerpcrequests': [dionaea_dcerpcrequests,],
	#'dionaea.shellcodeprofiles': [dionaea_shellcodeprofiles,],
	#'mwbinary.dionaea.sensorunique': [mwbinary_dionaea_sensorunique,],
}

# IRC settings
IRC_SERVER = 'irc.server.tld'
IRC_PORT = 6669
IRC_NICKNAME = 'Hpfeeds'
IRC_NICK_PASSWORD = 'test' # only works for nickserv authentication, disable with False
IRC_PASSWORD = None
IRC_USERNAME = None
IRC_SSL = True
IRC_CHANNEL = '#hpfeeds'

## Settings end ##
if IRC_SSL:
	import ssl
	import irc.connection
	import functools

logging.basicConfig()
logger = logging.getLogger("ircclient")
logger.setLevel(logging.DEBUG)

jobs = []
hpfeed = None
ircinstance = None

class HPFeed:
	def __init__(self):
		return

	def start(self):
		import socket
		self.hpc = None
		self.gi = {}
		self.gi[socket.AF_INET] = GeoIP.open("GeoLiteCity.dat",GeoIP.GEOIP_STANDARD)
		self.gi[socket.AF_INET6] = GeoIP.open("GeoLiteCityv6.dat",GeoIP.GEOIP_STANDARD)

		try:
			self.hpc = hpfeeds.new(HOST, PORT, IDENT, SECRET)
		except hpfeeds.FeedException, e:
			logger.error('[hpfeed] feed exception: %s'% e)

		logger.info('[hpfeed] connected to %s' % self.hpc.brokername)
		self.hpc.subscribe(CHANNELS)
		try:
			self.hpc.run(self.on_message, self.on_error)
		except hpfeeds.FeedException, e:
			logger.error('[hpfeed] feed exception: %s'% e)
		except (KeyboardInterrupt, SystemExit):
			sys.exit(0)
		except:
			import traceback
			traceback.print_exc()
		finally:
			self.hpc.close()

	def on_message(self, identifier, channel, payload):
		procs = PROCESSORS.get(channel, [])
		p = None
		for p in procs:
			try:
				m = p(identifier, payload, self.gi)
			except:
				print "[hpfeed] Invalid message %s" % payload
				return
			try: tmp = json.dumps(m)
			except: print 'DBG', m
			if m != None: sendToIrc(m)

		if not p:
			logger.warning('[hpfeed] not p?')
	def on_error(self, payload):
		global hpc
		logger.error('[hpfeed] errormessage from server: %s' % payload)
		hpc.stop()

class IRC_Client:
	def __init__(self):
		self.c = None
		self.client = None

	def connect_irc(self):
		logger.info("[IRC] Connecting to irc")
		self.client = irc.client.IRC()

		try:
			if IRC_SSL:
				wrapper = functools.partial(ssl.wrap_socket)
				self.c = self.client.server().connect(IRC_SERVER, IRC_PORT, IRC_NICKNAME, IRC_PASSWORD, IRC_USERNAME, None, connect_factory = irc.connection.Factory(wrapper=wrapper))
			else:
				self.c = self.client.server().connect(IRC_SERVER, IRC_PORT, IRC_NICKNAME, IRC_PASSWORD, IRC_USERNAME)
		except irc.client.ServerConnectionError:
			print(sys.exc_info()[1])
			raise SystemExit(1)
		logger.info("[IRC] connected to irc successfully")

		self.c.add_global_handler("disconnect", self.on_disconnect)
		self.c.add_global_handler("welcome", self.on_connect)
		try:
			self.client.process_forever()
		except (KeyboardInterrupt, SystemExit):
			sys.exit(0)

	def sendToIrc(self, msg, user=False):
		if not user:
			user = IRC_CHANNEL
		try:
			self.c.privmsg(user, msg)
		except:
			logger.info("[IRC] could not send to irc: ")
			traceback.print_exc()


	##### IRC EVENTS #####
	def on_connect(self, connection, event):
		if IRC_NICK_PASSWORD != 'False':
			self.sendToIrc("IDENTIFY %s" % IRC_NICK_PASSWORD, "NickServ")
		if irc.client.is_channel(IRC_CHANNEL):
			connection.join(IRC_CHANNEL)
			self.sendToIrc("Hello!")
			logger.info("[IRC] joined %s" % IRC_CHANNEL)
		else:
			logger.warning("[IRC] channelname invalid: %s" % IRC_CHANNEL)
			return

	def on_disconnect(self, connection, event):
		self.connect_irc()


def sendToIrc(msg):
	ircinstance.sendToIrc(msg)

def main():
	global ircinstance, hpfeed

	try:
		hpfeed = HPFeed()
		ircinstance = IRC_Client()
		jobs.append(Thread(target=hpfeed.start))
		jobs.append(Thread(target=ircinstance.connect_irc))
		for job in jobs: 
			job.daemon=True
			job.start()
		while True: time.sleep(100)
	except (KeyboardInterrupt, SystemExit):
		sys.exit(0)
	except:
		import traceback
		traceback.print_exc()
	return 0


if __name__ == '__main__':
	try: sys.exit(main())
	except KeyboardInterrupt:sys.exit(0)

