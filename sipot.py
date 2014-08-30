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

import os, sys, traceback, socket, multitask, random, logging, signal

try:
	sys.path.append(''.join([os.getcwd(), '/lib/39peers/std']))
	import rfc3550, rfc4566, rfc3489bis, kutil
	sys.path.append(''.join([os.getcwd(), '/lib/IPv6_fixes']))
	import rfc3261_IPv6, rfc2396_IPv6
	sys.path.append(''.join([os.getcwd(), '/lib/39peers/external']))
	import log
	
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
	usage += "\t *** Flood 500 Msg to 192.168.56.77 to IPv6 address: ***\r\n"
	usage += "\t python %prog --sipot-mode flooding --to sip:6000@[fd11:5001:ccc3:d9ab:0:0:0:3]:5060 --flood-number 500 \r\n"
	usage += "\t *** Flood 500 Msg from File to 192.168.56.77: ***\r\n"
	usage += "\t python %prog --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500 --flood-msg-file examples/example_sipot_flood.txt \r\n"
	usage += "\t *** Flood 500 Msg to 192.168.56.77 changing extentions with dictionary: ***\r\n"
	usage += "\t python %prog --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500 --ext-dictionary examples/example_sipot_ext_dict.txt \r\n"
	usage += "\r\n"
	
	usage += "Fuzzing mode:\r\n"
	usage += "\t *** Fuzzes the headers commonly found in a SIP INVITE request an IPv6 address: ***\r\n"
	usage += "\t python %prog --sipot-mode fuzzing --to sip:109@192.168.56.77:5060 \r\n"
	usage += "\t *** Fuzzes the headers commonly found in a SIP REGISTER request to 192.168.56.77: ***\r\n"
	usage += "\t python %prog --sipot-mode fuzzing --fuzz-fuzzer REGISTERFuzzer --to sip:109@192.168.56.77:5060 \r\n"
	usage += "\t *** Uses all available fuzzers to 192.168.56.77: ***\r\n"
	usage += "\t python %prog --sipot-mode fuzzing --fuzz-fuzzer --fuzz-max 10 All --to sip:109@192.168.56.77:5060 \r\n"
	usage += "\t *** Print results to a file: ***\r\n"
	usage += "\t python %prog --sipot-mode fuzzing --fuzz-crash --fuzz-to-file examples/example_fuzz_results.txt --to sip:109@192.168.56.77:5060 \r\n"
	usage += "\t *** Print results to a file: ***\r\n"
	usage += "\t python %prog --sipot-mode fuzzing --fuzz-crash --fuzz-to-file examples/example_fuzz_results.txt --fuzz-audit examples/example_fuzz_audit.txt --to sip:109@192.168.56.77:5060 \r\n"
	usage += "\r\n"
	
	usage += "Spoofing mode:\r\n"
	usage += "\t *** Spoofs Caller ID: ***\r\n"
	usage += "\t python %prog --sipot-mode spoofing --to sip:111@192.168.1.128:58386 --spoof-name Spoofed!\r\n"
	usage += "\t *** Spoofs Caller ID from message provided in file: ***\r\n"
	usage += "\t python %prog --sipot-mode spoofing --to sip:111@192.168.1.128:58386 --spoof-msg-file examples/example_sipot_spoof_this.txt \r\n"
	usage += "\t *** Spoofs BYE msg and spoof BYE from 200 OK: ***\r\n"
	usage += "\t python %prog --sipot-mode spoofing --spoof spfBYE --to sip:108@192.168.56.101:5060 --spoof-msg-file examples/example_sipot_spoof_bye.txt (Needs dialogID to be manually set)\r\n"
	usage += "\t python %prog --sipot-mode spoofing --spoof spfBYE --to sip:108@192.168.56.101:5060 --spoof-msg-file examples/example_sipot_spoof_bye_from_200.txt \r\n"
	usage += "\t *** Spoofs CANCEL msg and spoof CANCEL from 180 Ringing: ***\r\n"
	usage += "\t python %prog --sipot-mode spoofing --spoof spfCANCEL --to sip:108@192.168.1.77:5060 --spoof-msg-file examples/example_sipot_spoof_cancel.txt (Needs dialogID to be manually set)\r\n"
	usage += "\t python %prog --sipot-mode spoofing --spoof spfCANCEL --to sip:108@192.168.1.77:5060 --spoof-msg-file examples/example_sipot_spoof_cancel_from_180.txt \r\n"
	usage += "\t *** Automatic spoofing BYE/CANCEL when 200 OK/180 RINGING is detected: ***\r\n"
	usage += "\t python %prog --sipot-mode spoofing --spoof-auto --spoof spfBYE \r\n"
	usage += "\t python %prog --sipot-mode spoofing --spoof-auto --spoof spfCANCEL \r\n"
	usage += "\r\n"
	
	parser = OptionParser(usage,version="%prog v"+str(__version__)+__GPL__)
	
	parser.add_option('-v', '--verbose',   dest='verbose', default=False, action='store_true', help='enable verbose mode for this module')
	parser.add_option('-V', '--verbose-all',   dest='verbose_all', default=False, action='store_true', help='enable verbose mode for all modules')
    
	group1 = OptionGroup(parser, 'Network', 'Use these options for network configuration')
	group1.add_option('',   '--transport', dest='transport', default='udp', help='the transport type is one of "udp", "tcp" or "tls". Default is "udp"')
	group1.add_option('',   '--int-ip',  dest='int_ip',  default='0.0.0.0', help='listening IP address for SIP and RTP. Use this option only if you wish to select one out of multiple IP interfaces. Default "0.0.0.0"')
	group1.add_option('',   '--int-ipv6',  dest='int_ipv6',  default='::1', help='listening IPv6 address for SIP and RTP. Use this option only if you wish to select one out of multiple IP interfaces. Default "0.0.0.0"')
	group1.add_option('',   '--port',    dest='port',    default=5062, type="int", help='listening port number for SIP UDP/TCP. TLS is one more than this. Default is 5092')
	group1.add_option('',   '--fix-nat', dest='fix_nat', default=False, action='store_true', help='enable fixing NAT IP address in Contact')
	group1.add_option('',   '--max-size',dest='max_size', default=4096, type='int', help='size of received socket data. Default is 4096')
	group1.add_option('',   '--interval',dest='interval', default=180, type='int', help='The interval argument specifies how often should the sock be checked for close, default is 180 s')
	parser.add_option_group(group1)
    
	group2 = OptionGroup(parser, 'SIP', 'Use these options for SIP configuration')
	group2.add_option('','--username',dest='username',default=None,help='username to use in my SIP URI and contacts. Default is "%s"'%(default_login,))
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
	group4.add_option('', 	'--flood-file-noparse', default=False, action='store_true', dest='flood_noparse', help='Prevents the flooder to parse the message. By default try to parse.')
	parser.add_option_group(group4)
	
	group5 = OptionGroup(parser, 'Fuzzing Mode', 'use this options to set fuzzing parameters')
	group5.add_option('-l', '--fuzz-fuzzer-list', default=False, action='store_true', dest='list_fuzzers', help='Display a list of available fuzzers')
	group5.add_option('',   '--fuzz-fuzzer', dest='fuzzer', default='InviteCommonFuzzer', help='Set fuzzer. Default is InviteCommonFuzzer. Use -l to see a list of all available fuzzers')
	group5.add_option('',   '--fuzz-crash', default=False, action='store_true', dest='crash_detect', help='Enables crash detection')
	group5.add_option('',   '--fuzz-crash-method', dest='crash_method', default='OPTIONS', help='Set crash method. By default uses OPTIONS message and stores response.')
	group5.add_option('',   '--fuzz-crash-no-stop', default=False, action='store_true', dest='no_stop_at_crash', help='If selected prevents the app to be stoped when a crash is detected.')
	group5.add_option('',   '--fuzz-max', dest='fuzz_max_msgs', default=99999, type="int", help='Sets the maximum number of messages to be sent by fuzzing mode. Default is max available in fuzzer.')
	group5.add_option('',   '--fuzz-to-file', dest='file_name', default=None, help='Print the output to a file with the given name.')
	group5.add_option('',   '--fuzz-audit', dest='audit_file_name', default=None, help='Enables fuzzing audit. All messages sent (fuzzing) will be saved into the given file name.')
	parser.add_option_group(group5)
	
	group6 = OptionGroup(parser, 'Spoofing Mode', 'use this options to set spoof parameters')
	group6.add_option('',   '--spoof', dest='spoof_mode', default='spfINVITE', help='Set the method to spoof. Default is INVITE.')
	group6.add_option('', 	'--spoof-auto', default=False, action='store_true', dest='spoof_auto', help='Automatically spoofs messages when messages are sniffed.')
	group6.add_option('', 	'--spoof-auto-target', default='AB', dest='auto_spoof_target', help='Select wich target to spoof: AB: Both sides (default). A:Only side A. B: Only side B.')
	group6.add_option('-L', '--spoof-list', default=False, action='store_true', dest='list_spoof', help='Display a list of available spoof modes.')
	group6.add_option('',   '--spoof-name', dest='spoof_name', default=None, help='Set the name to spoof.')
	group6.add_option('',   '--spoof-contact', dest='spoof_contact', default=None, help='Set the contact header to spoof. ie. sip:666@192.168.1.129:5060.')
	group6.add_option('',   '--spoof-msg-file', dest='spoof_msg_file', default=None, help='Spoof message from file.')
	group6.add_option('',   '--spoof-lTag', dest='spoof_local_tag', default=None, help='Local tag to use in spoof message. ie: as5c9c6524')
	group6.add_option('',   '--spoof-rTag', dest='spoof_remote_tag', default=None, help='Remote tag to use in spoof message. ie: 1605a146-d627-e411-8066-0800273bf55a')
	group6.add_option('',   '--spoof-callID', dest='spoof_callID', default=None, help='Call-ID to use in spoof message. ie: 27679bab736046f14798e8b5593222f3@192.168.56.77:5060')
	parser.add_option_group(group6)
	
	group7 = OptionGroup(parser, 'Generate Extention', 'Extensions options for flooding. Changes the originator extention in each message.')
	group7.add_option('',   '--no-modify-ext',dest='modify_extentions', default=True, action='store_false', help='If not specified, extentions will be modified in each message flooded. To generate extentions options --ext-dictionary &--ext-range  will be used.')
	group7.add_option('',   "--ext-dictionary", dest="ExtDictionary", type="string",help="Specify a dictionary file with possible extension names")
	group7.add_option('',   "--ext-range", dest="ExtRange", default='100-999',metavar="RANGE",help="Specify an extension or extension range\r\nexample: -e 100-999,1000-1500,9999")
	group7.add_option('',   "--ext-range-zeropadding", dest="ExtZeropadding", type="int",help="""the number of zeros used to padd the username.the options "-e 1-9999 -z 4" would give 0001 0002 0003 ... 9999""")
	group7.add_option('',   '--ext-range-template',  dest="ExtTemplate",action="store",help="""A format string which allows us to specify a template for the extensions example svwar.py -e 1-999 --template="123%#04i999" would scan between 1230001999 to 1230999999" """)
	group7.add_option('',   '--ext-range-enabledefaults', dest="ExtDefaults", action="store_true", default=False, help="""Scan for default / typical extensions such as 1000,2000,3000 ... 1100, etc. This option is off by default. Use --enabledefaults to enable this functionality""")
	parser.add_option_group(group7)
	
	(options, args) = parser.parse_args()
    
	handler = log.ColorizingStreamHandler(stream=sys.stdout)
	handler.setLevel(logging.DEBUG)
	handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)d %(name)s %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
	logging.getLogger().addHandler(handler)
    
	#-------------------- General options---------------------------------
	logger.setLevel((options.verbose or options.verbose_all) and logging.DEBUG or logging.INFO)
	if options.verbose_all:
		if hasattr(rfc3261_IPv6, 'logger'): rfc3261_IPv6.logger.setLevel(logging.DEBUG)
		else: rfc3261_IPv6._debug = True
		
	if options.list_fuzzers:
		list_fuzzers = """
------------------------------------------------------------------------------------------------
	List of available FUZZERS (select vector to fuzz the message):
	> InviteCommonFuzzer[6775] (default): Fuzzes the headers commonly found and most likely to be processed in a SIP INVITE request

	> InviteStructureFuzzer[943]: Fuzzes the structure of a SIP request by repeating blocks, fuzzing delimiters and generally altering how a SIP request is structured.
	> InviteRequestLineFuzzer[1239]: Extensively tests the first line of an INVITE request by including all valid parts specified in SIP RFC 3375.
	> InviteOtherFuzzer[10497]: Tests all other headers specified as part of an INVITE besides those found in the InviteCommonFuzzer. Many of these are seemingly unparsed and ignored by a lot of devices.
	> CANCELFuzzer[3106]: A fuzzer for the CANCEL SIP verb.
	> REGISTERFuzzer[6283]: A fuzzer for the REGISTER SIP verb.
	> SUBSCRIBEFuzzer[4354]: A fuzzer for the SUBSCRIBE SIP verb.
	> NOTIFYFuzzer[5984]: A fuzzer for the NOTIFY SIP verb.
	> ACKFuzzer[3106]: A fuzzer for the ACK SIP verb that first attempts to manipulate the target device into a state where it would expect an ACK.
		
	> All[42287]: Uses all the fuzzers.
------------------------------------------------------------------------------------------------
		"""
		print list_fuzzers
		sys.exit(-1)
	if options.list_spoof:
		list_fuzzers = """
------------------------------------------------------------------------------------------------
	Available SPOOF MODES (select what to spoof):
	> spfINVITE (default): this mode spoofs INVITE messages. The destiny Caller ID will show the specified --spoof-name.
	> spfBYE: this mode spoofs BYE messages. It allows to finish established calls.
	> spfCANCEL: this mode spoofs CANCEL messages. It allows to finish not established calls (RINGING).
------------------------------------------------------------------------------------------------
		"""
		print list_fuzzers
		sys.exit(-1)
	# Verify if external file exists
	def FileCheck(fn):
		try:
			open(fn, "r")
			return True
		except IOError:
			print "Error: File does not appear to exist"
			return False
	# Align options: to, URI, domain, registrar_ip, username, host, port
	if options.spoof_auto and not(options.to and options.registrar_ip):
		options.to = 'sip:777@127.0.0.1:5060'
	if not options.to and not options.registrar_ip: 
		print 'must supply --to option with the target SIP address'
		sys.exit(-1)
	else:
		if not options.to:
			if not options.uri:
				options.registrar_ip = options.registrar_ip if options.registrar_ip else options.domain
				options.to = rfc2396_IPv6.Address(str('<sip:'+options.username+'@'+(options.registrar_ip if rfc2396_IPv6.isIPv4(options.registrar_ip) else ('['+options.registrar_ip+']'))+'>'))
				options.uri = options.to.uri.dup()
				options.to.uri.port = options.uri.port = options.port
			else:
				options.uri = rfc2396_IPv6.URI(options.uri) if options.uri else rfc2396_IPv6.URI(str('sip:'+options.username+'@'+(options.registrar_ip if rfc2396_IPv6.isIPv4(options.registrar_ip) else ('['+options.registrar_ip+']'))))
				options.to = rfc2396_IPv6.Address(str(options.uri))
				options.registrar_ip = options.registrar_ip if options.registrar_ip else options.to.uri.host
				options.to.uri.port = options.uri.port = options.port
		else:
			options.to = rfc2396_IPv6.Address(options.to)
			options.uri = rfc2396_IPv6.URI(options.uri) if options.uri else options.to.uri.dup()
			options.registrar_ip = options.registrar_ip if options.registrar_ip else options.to.uri.host
			options.port = options.to.uri.port if options.to.uri.port else options.port
			options.to.uri.port = options.uri.port = options.port
			
	if not options.fromAddr:
		options.username = options.username if options.username else (options.reg_username if options.reg_username else options.to.uri.user)
		options.reg_username = options.reg_username if options.reg_username else options.username
		options.fromAddr = rfc2396_IPv6.Address(str('<sip:'+options.username+'@'+(options.registrar_ip if rfc2396_IPv6.isIPv4(options.registrar_ip) else ('['+options.registrar_ip+']'))+'>'))
		options.fromAddr.uri.port = options.port
	else:
		options.fromAddr = rfc2396_IPv6.Address(options.fromAddr)
		options.username = options.username if options.username else options.fromAddr.displayable
		options.reg_username = options.reg_username if options.reg_username else options.fromAddr.displayable
		options.fromAddr.uri.port = options.port
	# Validate Flooding options
	if options.flood_msg_file and not FileCheck(options.flood_msg_file): sys.exit(-1)
	# Validate Fuzzing options
	if not options.crash_detect: options.audit_file_name = None
	# Validate Spoofing options
	if options.spoof_mode not in ['spfINVITE','spfBYE','spfCANCEL']:
		print "<"+options.spoof_mode+"> is not an available spoofing mode. Please check -L."
		sys.exit(-1)
	options.auto_spoof_target = options.auto_spoof_target.upper()
	if options.auto_spoof_target not in ['AB','A','B']:
		print "<"+options.auto_spoof_target+"> is not an available target: Options: AB/A/B."
		sys.exit(-1)

class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	
# Base User class
class User(object):
	'''The User object provides a layer between the application and the SIP stack.'''
	REGISTERED, UDP, TCP, TLS = 'Registered user','udp', 'tcp', 'tls' # transport values
	def __init__(self, app):
		self.app = app
		self.state = self.reg_state = None
		self.register = None
		self.reg_result = self.reg_reason = None
		# socket setup
		if rfc2396_IPv6.isIPv6(app.options.to.uri.host): # Unstable
			print "You are using IPv6 unstable feature."
			print "IPv6 data:"
			print "Bind to: "+str((app.options.int_ipv6, (app.options.port+1) if app.options.transport == self.TLS else app.options.port))
			sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind((app.options.int_ipv6, (app.options.port+1) if app.options.transport == self.TLS else app.options.port))
			self.sock, self.nat = sock, app.options.fix_nat
		else:
			sock = socket.socket(type=socket.SOCK_DGRAM if app.options.transport == self.UDP else socket.SOCK_STREAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind((app.options.int_ip, (app.options.port+1) if app.options.transport == self.TLS else app.options.port))
			self.sock, self.nat = sock, app.options.fix_nat
		# socket options
		self.max_size = app.options.max_size
		self.interval = app.options.interval
		# REGISTER options
		self.register_interval = app.options.register_interval
		self.reg_refresh = app.options.reg_refresh
		# SIP options
		self.username = app.options.username
		self.reg_username = app.options.reg_username
		self.password = app.options.password 
		self.registrarAddr = rfc2396_IPv6.Address(str('<sip:'+self.reg_username+'@'+(app.options.registrar_ip if rfc2396_IPv6.isIPv4(app.options.registrar_ip) else ('['+app.options.registrar_ip+']'))+'>'))
		# Generators
		self._listenerGen = self._registerGen = None
		# create a SIP stack instance
		self.transport = rfc3261_IPv6.TransportInfo(self.sock, secure=(app.options.transport == self.TLS))
		self._stack = rfc3261_IPv6.Stack(self, self.transport, fix_nat=app.options.fix_nat)
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
	
	def close(self):
		self.register_interval = 0
		multitask.add(self._register())
		if self._ua.gen: self._ua.gen.close(); self._ua.gen = None
	def stop(self):
		if self._listenerGen:
			self._listenerGen.close()
		if self._registerGen:
			self._registerGen.close()
		self._registerGen = None
		return self
	#-------------------- Internal ---------------------------------
	def _createRegister(self):
		'''Create a REGISTER Message and populate the Expires and Contact headers. It assumes
		that self.reg is valid.'''
		m = self._ua.createRegister(self._ua.localParty)
		m.Contact = rfc3261_IPv6.Header(str(self._stack.uri), 'Contact')
		m.Contact.value.uri.user = self.localParty.uri.user
		m.Expires = rfc3261_IPv6.Header(str(self.app.options.register_interval), 'Expires')
		return m
	#-------------------- Generators ---------------------------------
	def _listener(self):
		'''Listen for transport messages on the signaling socket. The default maximum 
		packet size to receive is 1500 bytes. The interval argument specifies how
		often should the sock be checked for close, default is 180 s.
		This is a generator function and should be invoked as multitask.add(u._listener()).'''
		self.app.status.append('Listener Generator Initiated')
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
		self._ua.localParty, self._ua.remoteParty, self._ua.remoteTarget = self.registrarAddr.dup(), self.registrarAddr.dup(), self.registrarAddr.dup()
		self.reg_result, self.reg_reason = yield self._registerUA()
		if self.reg_result=='success': 
			self._ua.localParty, self._ua.remoteParty, self._ua.remoteTarget = self.localParty.dup(), self.remoteParty.dup(), self.remoteTarget.dup()
			if self.reg_state == None:
				self.reg_state = self.REGISTERED
				self.app.status.append(bcolors.OKGREEN+"Register succesful!"+bcolors.ENDC +" (user: "+self.app.options.username+", password: "+self.app.options.password+")")
		else: self.app.status.append('Register result: '+self.reg_result+'. Reason: '+self.reg_reason)
	def _registerUA(self):
		if self.reg_state == None:
			self.app.status.append('Register Generator Initiated')
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
		ua = request.method in ['INVITE', 'BYE', 'ACK', 'SUBSCRIBE', 'MESSAGE', 'NOTIFY'] and rfc3261_IPv6.UserAgent(self.stack, request) or None
		if ua: ua.queue = ua.gen = None
		logger.debug('createServer', ua)
		return ua
	def createClient(self):
		'''Create a UAC and add additional attributes: queue and gen.'''
		self._ua = rfc3261_IPv6.UserAgent(self._stack)
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
				# TODO: non-dialog CANCEL comes here. need to fix rfc3261_IPv6 so that it goes to cancelled() callback.
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
	# rfc3261_IPv6.Transport related methods
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

# Base App class
class App(object):
	RUNNING = 'Runnning'
	def __init__(self, options):
		logger.info("ntsga: init app")
		self.options = options
		self.status = []
		self.user = None
		multitask.add(self.mainController())
		
	def start(self):
		self.createUser()
		self.user = self.user.add_listenerGen()
		if self.options.register: self.user.add_registerGen()
		# RUN MULTITASK: multitask.run()
		self.RUNNING
		TaskManager = multitask.get_default_task_manager()
		while self.RUNNING and (TaskManager.has_runnable() or TaskManager.has_io_waits() or TaskManager.has_timeouts()):
			TaskManager.run_next()
		return self

	def createUser(self):
		self.user = User(self).createClient()
		return self

	def exit_gracefully(self, signum, frame):
		import signal
		signal.signal(signal.SIGINT, return_original_sigint())
		try:
			if raw_input("\nReally quit? (y/n)> ").lower().startswith('y'):
				self.printResults()
				self.stop()
		except KeyboardInterrupt:
			print("Ok ok, quitting")
			sys.exit(1)
		signal.signal(signal.SIGINT, exit_gracefully)

	def mainController(self):
		logger.info("ntsga: start main default controller")
		while True:
			if self.status:
				print self.status.pop(0)
			if self.options.register and not self.user.reg_result==None:
				self.stop()
				raise StopIteration()
			yield

	def printResults(self):
		print "No results... =("
		return self
		
	def stop(self):
		self.RUNNING = False
		return self
		
	def close(self): 
		if self.user:
			self.user.stop()
# Signal exit
original_sigint = 0
def set_original_sigint(sigint):
    global original_sigint    # Needed to modify global copy of globvar
    original_sigint = sigint
def return_original_sigint():
    return original_sigint     # No need for global declaration to read value of globvar
#-------------------- START APPS---------------------------------
if __name__ == '__main__':
    try:
        print "------------------------------------------------------------------------------------------------------------"
        if options.sipot_mode == 'flooding':
			import module_flooder
			app = module_flooder.FloodingApp(options)
        if options.sipot_mode == 'fuzzing':
			import module_fuzzer
			app = module_fuzzer.FuzzingApp(options)
        if options.sipot_mode == 'spoofing':
			import module_spoofer
			app = module_spoofer.SpoofingApp(options)
        if not 'app' in globals(): app = App(options)
        set_original_sigint(signal.getsignal(signal.SIGINT))
        signal.signal(signal.SIGINT, app.exit_gracefully)
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
        
        
        
        


