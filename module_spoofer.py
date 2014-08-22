# Spoofing App

import sys, os, socket, multitask, random, ctypes
from sipot import App, User, logger, bcolors
# scapy
sys.path.append(''.join([os.getcwd(), '/lib/scapy']))
from scapy.all import *

# 39peers
sys.path.append(''.join([os.getcwd(), '/lib/39peers/std']))
import rfc3261, rfc2396
# Others: [multitask, helper_functions]
sys.path.append(''.join([os.getcwd(), '/lib/']))

class spooferUser(User):
	'''The User object provides a layer between the application and the SIP stack.'''
	SPOOFING = 'User Spoofing'
	def __init__(self, app):
		User.__init__(self,app)
        #Spoofer options
		self.spoof_mode = app.options.spoof_mode
		self.spoof_name = app.options.spoof_name
		self.spoof_msg_file = app.options.spoof_msg_file
		self.spoof_contact = app.options.spoof_contact
		self.spoof_local_tag = app.options.spoof_local_tag
		self.spoof_remote_tag = app.options.spoof_remote_tag
		self.spoof_callID = app.options.spoof_callID
		self.spoof_auto = app.options.spoof_auto
        #Spoofer sets
		self._spooferGen = None
        #Listener
		self.listenerOff = True if self.spoof_mode in ['spfINVITE','spfBYE','spfCANCEL'] else False
		self.spoof_method = {'spfINVITE':'INVITE','spfBYE':'BYE','spfCANCEL':'CANCEL'}[app.options.spoof_mode]
	
	def stop(self):
		if self._listenerGen:
			self._listenerGen.close()
		if self._registerGen:
			self._registerGen.close()
		if self._spooferGen:
			self._spooferGen.close()
		self._registerGen = None
		return self
		
	def add_spooferGen(self):
		self.state = self.SPOOFING
		if not self._spooferGen:
			if self.spoof_auto:
				self._spooferGen  = self._auto_spoofing()
				multitask.add(self._spooferGen)
			else:
				self._spooferGen  = self._spoofing()
				multitask.add(self._spooferGen)
		return self
	
	def _auto_spoofing(self):
		def autoBYE(message):
			pass
		def autoCANCEL(message):
			pass
		def SIPrecvd(pkt):
			try: 
				pkt = pkt[Raw].load
			except IndexError: pass
			#pkt = pkt.sprintf("{Raw:%Raw.load%\n}")
			m = rfc3261.Message()
			try:
				m = rfc3261.Message(str(pkt))
				#SIP message received -> AutoSpoof
				if self.spoof_mode == 'autoBYE':
					autoBYE(m)
				if self.spoof_mode == 'autoCANCEL':
					autoCANCEL(m)
			except ValueError, E: pass # TODO: send 400 response to non-ACK request
		try:
			is_admin = os.getuid() == 0
		except AttributeError:
			is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
		if is_admin:
			# Stop listener if not necessary in spoof mode
			if self.listenerOff: self._listenerGen.close()
			self.sock.close()
			sniff(prn=SIPrecvd, filter="ip and port 5060 ", store=0)
		else:
			print (bcolors.FAIL+"\n***** Admin rights needed to sniff the network *****\n"+bcolors.ENDC)
			self.app.stop()
			yield
			raise StopIteration()

	def _spoofing(self):
		# Msg to spoof generator ---------
		def _createSpoofMessage():
			if self.spoof_msg_file:
				with open (self.spoof_msg_file, "r") as file_txt:
					file_txt=file_txt.read()
				m = rfc3261.Message()
				try:
					m = m._parse(file_txt.rstrip()+'\r\n\r\n\r\n')
				except ValueError, E: pass # TODO: send 400 response to non-ACK request
			else:
				m = self._ua.createRequest(self.spoof_method)
				m.Contact = rfc3261.Header(str(self._stack.uri), 'Contact')
				m.Contact.value.uri.user = self.localParty.uri.user
				m.Expires = rfc3261.Header(str(self.app.options.register_interval), 'Expires')
			return m
		# Spoof msg content ---------
		def spoofMsg(message):
			def _createBYE(message):
				def BYEheaders(message):
					'''Read-only list of transaction Header objects (To, From, CSeq, Call-ID)'''
					return map(lambda x: message[x], ['To', 'From', 'Call-ID'])
				m = rfc3261.Message.createRequest('BYE', str(self.remoteParty), BYEheaders(message))
				m['CSeq'] = rfc3261.Header(str(message.CSeq.number+1) + ' BYE', 'CSeq')
				return m
			def _createCANCEL(message):
				def CANCELheaders(message):
					'''Read-only list of transaction Header objects (To, From, CSeq, Call-ID)'''
					return map(lambda x: message[x], ['To', 'From', 'CSeq', 'Call-ID'])
				m = rfc3261.Message.createRequest('CANCEL', str(self.remoteParty), CANCELheaders(message))
				if message and message.Route: m.Route = message.Route
				if message: m.Via = message.first('Via') # only top Via included
				return m
			# Spoofs ---------
			if self.spoof_mode == 'spfINVITE':
				self.spoof_name = 'SIPOT Caller ID'
			if self.spoof_mode == 'spfBYE' and message.method != 'BYE':
				message = _createBYE(message)
			if self.spoof_mode == 'spfCANCEL' and message.method != 'CANCEL':
				message = _createCANCEL(message)
			# caller ID
			if self.spoof_name:
				message.From.value.displayName = self.spoof_name
			if self.spoof_contact:
				message.Contact = rfc3261.Header(str(self.spoof_contact), 'Contact')
			# rTag, lTag, callID
			if self.spoof_local_tag:
				message.From.tag = self.spoof_local_tag
			if self.spoof_remote_tag:
				message.To.tag = self.spoof_local_tag
			if self.spoof_callID:
				message['Call-ID'] = rfc3261.Header(self.spoof_callID, 'Call-ID')
			return message
		# Stop listener if not necessary in spoof mode
		if self.listenerOff: self._listenerGen.close()
		try:
			spoof_message = spoofMsg(_createSpoofMessage())
			print spoof_message
			if not self.listenerOff:
				self._ua.sendRequest(spoof_message)
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
			else:
				self.send(str(spoof_message),self.remoteParty.uri.hostPort,None)				
			yield multitask.sleep(1)
			self.app.stop()
			yield
			raise StopIteration()
		except GeneratorExit:
			raise StopIteration(('failed', 'Generator closed'))
		self.app.stop()
		yield
		raise StopIteration()

class SpoofingApp(App):
	def __init__(self, options):
		App.__init__(self,options)
		logger.info("ntsga: init spoofing app")
		
		
		
		
		

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
		self.user = spooferUser(self).createClient()
		return self
		
	def mainController(self):
		logger.info("ntsga: start spoofing controller")
		while True:
			if self.status: # Print app status
				print self.status.pop(0)
			# If not register needed or already registered => fuzz
			if not self.options.register or (self.options.register and self.user.reg_state==self.user.REGISTERED):
				while True:
					self.user.add_spooferGen()
					if not self.user.state == self.user.SPOOFING:
						self.stop()
						raise StopIteration()
					yield
				yield
			# If register needed and could not register = > stop app
			elif not (self.user.reg_result=='success' or self.user.reg_result==None):
				print 'Could not register user.'
				self.stop()
				raise StopIteration()
			yield
