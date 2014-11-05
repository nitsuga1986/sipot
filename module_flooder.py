# Flooding App
#===================================================================================================================
__GPL__ = """

   Sipot extension: flooder module

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
__version__ = 'alpha'
__prog__ = 'sipot: flooder module'
__desc__ = "SIP Open Tester"
#===================================================================================================================
#------------------------------IMPORT------------------------------
try:
	import sys, os, socket, multitask, random
	from sipot import App, User, logger
	# 39peers (IPv6 fixed)
	sys.path.append(''.join([os.getcwd(), '/lib/IPv6_fixes']))
	import rfc2396_IPv6, rfc3261_IPv6
	# Others: [multitask, helper_functions]
	sys.path.append(''.join([os.getcwd(), '/lib/']))
except ImportError: print 'We had a problem importing dependencies.'; traceback.print_exc(); sys.exit(1)
#===================================================================================================================
def module_Usage(usage):
	usage += "Flooding mode:\r\n"
	usage += "\t *** Flood 500 Msg to 192.168.56.77 to IPv6 address: ***\r\n"
	usage += "\t python %prog --sipot-mode flooding --to sip:6000@[fd11:5001:ccc3:d9ab:0:0:0:3]:5060 --flood-number 500 \r\n"
	usage += "\t *** Flood 500 Msg from File to 192.168.56.77: ***\r\n"
	usage += "\t python %prog --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500 --flood-msg-file examples/example_sipot_flood.txt \r\n"
	usage += "\t *** Flood 500 Msg to 192.168.56.77 changing extentions with dictionary: ***\r\n"
	usage += "\t python %prog --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500 --ext-dictionary examples/example_sipot_ext_dict.txt \r\n"
	usage += "\r\n"
	return usage
def module_Options(parser):
	from optparse import OptionGroup
	group_flooder = OptionGroup(parser, 'Flooding Mode', 'use this options to set flooding parameters')
	group_flooder.add_option('',   '--flood-number', dest='flood_num', default=600, type="int", help='Sets the number of messages to be sent by flooding mode. Default is 500.')
	group_flooder.add_option('',   '--flood-method', dest='flood_method', default='REGISTER', help='Set the method to flood. Default is REGISTER.')
	group_flooder.add_option('',   '--flood-msg-file', dest='flood_msg_file', default=None, help='Provide a message from file to flood.')
	group_flooder.add_option('', 	'--flood-file-noparse', default=False, action='store_true', dest='flood_noparse', help='Prevents the flooder to parse the message. By default try to parse.')
	parser.add_option_group(group_flooder)  
	return parser
#===================================================================================================================
class flooderUser(User):
	'''The User object provides a layer between the application and the SIP stack.'''
	FLOODING = 'User flooding'
	def __init__(self, app):
		User.__init__(self,app)
        #Flooder options
		self._floodGen = None
		self.flood_num = app.options.flood_num
		self.flood_method = app.options.flood_method
		self.flood_msg = 0
		self.start_flood_time = None
		self.flood_msg_file = app.options.flood_msg_file
		self.flood_noparse = app.options.flood_noparse
	
	def stop(self):
		if self._listenerGen:
			self._listenerGen.close()
		if self._registerGen:
			self._registerGen.close()
		if self._floodGen:
			self._floodGen.close()
		self._registerGen = None
		return self
		
	def add_floodGen(self):
		self.state = self.FLOODING
		if not self._floodGen:
			self._floodGen  = self._flood()
			multitask.add(self._floodGen)
		return self
	
	def _flood(self):
		from helper_functions import generateExtentions, loopExtentionsDictionary
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
				m = rfc3261_IPv6.Message()
				try:
					if self.flood_noparse:
						m = file_txt
					else:
						m = m._parse(file_txt.rstrip()+'\r\n\r\n\r\n')
				except ValueError, E: pass # TODO: send 400 response to non-ACK request
			else:
				m = self._ua.createRequest(self.flood_method)
				m.To = rfc3261_IPv6.Header(str(self.app.options.to.uri), 'To')
				m.Contact = rfc3261_IPv6.Header(str(self._stack.uri), 'Contact')
				m.Contact.value.uri.user = self.localParty.uri.user
				m.Expires = rfc3261_IPv6.Header(str(self.app.options.register_interval), 'Expires')
			return m
		def _createFloodMsgGen(message_generated):
			if self.app.options.modify_extentions and not self.flood_noparse:
				if self.app.options.ExtDictionary is not None:
					try:
						dictionary = open(self.app.options.ExtDictionary,'r')
					except IOError:
						logger.error( "Could not open %s" % self.app.options.ExtDictionary )
						exit(1)
					self.ExtensionsGenerator =  loopExtentionsDictionary(dictionary)
				else:
					self.ExtensionsGenerator = generateExtentions(*(self.app.options.ExtRange,self.app.options.ExtZeropadding,self.app.options.ExtTemplate,self.app.options.ExtDefaults))
				self.message_generated = message_generated
				while True:
					message_generated = self.message_generated
					# Modify message_generated: extension (To,From), tag, Call-ID
					extension = self.ExtensionsGenerator.next()
					if message_generated.method == "INVITE":
						if self.app.options.registrar_ip != self.app.options.to.uri.host:
							SourceFakeAddr = self.app.options.registrar_ip
						else:
							SourceFakeAddr = str(self.app.options.to.uri.host).split('.')
							SourceFakeAddr[3] = str(random.randint(0,254))
							SourceFakeAddr = ".".join(SourceFakeAddr)
						message_generated.From.value.uri.user = message_generated.From.value.displayName =  extension
						message_generated.From.value.uri.host = SourceFakeAddr
					else:
						message_generated.From.value.uri.user = message_generated.From.value.displayName =  message_generated.To.value.uri.user = message_generated.To.value.displayName = extension
					message_generated.From.tag=str(random.randint(0,2**31))
					message_generated['Call-ID'] = rfc3261_IPv6.Header(str(random.randint(0,2**31)) + '@' + (message_generated.From.value.uri.host or 'localhost'), 'Call-ID')
					yield (message_generated)
			else:
				while True:
					yield (message_generated)
		# Dest Address
		addr = self.remoteTarget.uri
		if addr and isinstance(addr, rfc2396_IPv6.URI):
			if not addr.host: raise ValueError, 'No host in destination uri'
			addr = (addr.host, addr.port or self.transport.type == 'tls' and self.transport.secure and 5061 or 5060)
		# Msg generator
		base_msg = _createBaseMessage()
		flood_msg = _createFloodMsgGen(base_msg)
		if self.flood_noparse:
			print "Flooding %s NOPARSED messages to %s" % (self.flood_num, addr)
		else:
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
#===================================================================================================================
class FloodingApp(App):
	def __init__(self, options):
		App.__init__(self,options)
		logger.info("ntsga: init flooding app")

	def start(self):
		self.createUser()
		# RUN MULTITASK: multitask.run()
		self.RUNNING
		TaskManager = multitask.get_default_task_manager()
		while self.RUNNING and (TaskManager.has_runnable() or TaskManager.has_io_waits() or TaskManager.has_timeouts()):
			TaskManager.run_next()
		return self
		
	def createUser(self):
		self.user = flooderUser(self).createClient()
		return self
		
	def mainController(self):
		logger.info("ntsga: start flooding controller")
		while True:
			self.user.add_floodGen()
			if not self.user.state == self.user.FLOODING:
				self.stop()
				raise StopIteration()
			yield
