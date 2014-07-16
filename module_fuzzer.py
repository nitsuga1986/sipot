# Fuzzing App
import os, sys, traceback, socket, multitask
from sipot import App, User, logger
from std import rfc3261, rfc2396
# Sulley
sys.path.append(''.join([os.getcwd(), '/sulley']))
from sulley import *
sys.path.append(''.join([os.getcwd(), '/sulley/requests']))
import sip_block


class fuzzerUser(User):
	'''The User object provides a layer between the application and the SIP stack.'''
	FUZZING, FUZZING_COMPETED = 'User fuzzing', 'Fuzzing completed!'
	
	def __init__(self, app):
		User.__init__(self,app)
        #Fuzzer options
		self._fuzzerGen = None
		self.fuzz_method = app.options.fuzz_method
		self.fuzz_dialog = app.options.fuzz_dialog
		self.fuzz_msg_file = app.options.fuzz_msg_file
	
	def stop(self):
		if self._listenerGen:
			self._listenerGen.close()
		if self._registerGen:
			self._registerGen.close()
		if self._fuzzerGen:
			self._fuzzerGen.close()
		self._registerGen = None
		return self
		
	def add_fuzzerGen(self):
		self.state = self.FUZZING
		if not self._fuzzerGen:
			self._fuzzerGen  = self._fuzzing()
			multitask.add(self._fuzzerGen)
		return self
		
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
					if self.state != self.FUZZING and self.state != self.FUZZING_COMPETED:
						self._stack.received(data, remote)
					else:
						m = rfc3261.Message()
						try:
							m._parse(data)
							self.app.fuzzResponse[str(m.CSeq)] = str(m.response)+' '+str(m.responsetext)
						except ValueError, E: # TODO: send 400 response to non-ACK request
							if _debug: print 'Error in received message:', E
							if _debug: traceback.print_exc()
				except multitask.Timeout: pass
		except GeneratorExit: pass
		except: print 'User._listener exception', (sys and sys.exc_info() or None); traceback.print_exc(); raise
		logger.debug('terminating User._listener()')
		
	def _fuzzing(self):
		# Msg to Fumzz generator ---------
		def _createMutableMessage():
			# Msg to Fuzz generator ---------
			mutable_msg = s_get("INVITE_COMMON")
			print mutable_msg.num_mutations()
			return mutable_msg
			
		def _createFuzzerMsgGen(mutable_msg):
			def replaceDefaults(rendered_msg):
				from random import Random
				import string
				print "HERE"
				print self
				print self.localParty
				print self.localParty.uri.host
				# branch
				self.curr_invite_branch = ''.join(Random().sample(string.ascii_lowercase+string.digits, 32))
				rendered_msg = rendered_msg.replace('somebranchvalue', self.curr_invite_branch)
				rendered_msg = rendered_msg.replace('somefromtagvalue', self.curr_invite_branch)
				rendered_msg = rendered_msg.replace('somecallidvalue', self.curr_invite_branch)
				print rendered_msg
				# This stuff is new in this function and should be moved elsewhere
				# Works fine here for now though
				rendered_msg = rendered_msg.replace('TARGET_USER', self.remoteParty.uri.user)
				rendered_msg = rendered_msg.replace('USER', self.localParty.uri.user)
				rendered_msg = rendered_msg.replace('HOST', self.localParty.uri.host)
				rendered_msg = rendered_msg.replace('192.168.96.69', self.localParty.uri.host)
				rendered_msg = rendered_msg.replace('192.168.99.99', self.localParty.uri.host)        
				rendered_msg = rendered_msg.replace('PORT', str(self.localParty.uri.port))
				rendered_msg = rendered_msg.replace('LOCAL_IP', self.localParty.uri.host)
				return rendered_msg
				
			for i in range(1000):
				mutable_msg.mutate()
				m = replaceDefaults(mutable_msg.render())
				yield (m)
				
		# Dest Address
		addr = self.remoteTarget.uri
		if addr and isinstance(addr, rfc2396.URI):
			if not addr.host: raise ValueError, 'No host in destination uri'
			addr = (addr.host, addr.port or self.transport.type == 'tls' and self.transport.secure and 5061 or 5060)
		# Msg generator
		mutable_msg = _createMutableMessage()
		Fuzz_Generator = _createFuzzerMsgGen(mutable_msg)
		print "Fuzzing %s messages to %s" % (addr, addr) # TODO!!
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
						# Sender TCP
						pass
						# Sender TCP
						yield
						raise StopIteration()
					except socket.error:
						logger.debug('socket error in send')
				elif self.sock.type == socket.SOCK_DGRAM:
					while True:
						try:
							data = str(Fuzz_Generator.next())
							try:
								self.sock.sendto(data, addr)
							except socket.error:
								logger.debug('socket error in sendto' )
						except StopIteration:
							self.state = self.FUZZING_COMPETED
							raise StopIteration()
						yield
				else:
					logger.debug('invalid socket type', self.sock.type)
		except AttributeError: pass

class FuzzingApp(App):
	def __init__(self, options):
		App.__init__(self,options)
		logger.info("ntsga: init fuzzing app")
		self.fuzzResponse = dict()
		self.fuzzerNote = dict()

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
		self.user = fuzzerUser(self).createClient()
		return self
	
	def printFuzzResults(self):
		lenres = len(self.fuzzResponse)
		if lenres > 0:
			from pptable import indent,wrap_onspace
			width = 60
			labels = ('Cseq','Response','Fuzzing notes')
			rows = list()
			WaitingAnswer=False
			for Cseq in sorted(self.fuzzResponse.keys()):
				rows.append((Cseq,self.fuzzResponse[Cseq],self.fuzzerNote[Cseq]))
			print "\r\nFUZZING RESULTS:"
			print indent([labels]+rows,hasHeader=True,prefix='| ', postfix=' |',wrapfunc=lambda x: wrap_onspace(x,width))
	
	def mainController(self):
		logger.info("ntsga: start fuzzing controller")
		while True:
			if self.status: # Print app status
				print self.status.pop(0)
			# If not register needed or already registered => fuzz
			if not self.options.register or (self.options.register and self.user.reg_state==self.user.REGISTERED):
				self.user.add_fuzzerGen()
				while True:
					yield multitask.sleep(1)
					if not self.user.state == self.user.FUZZING:
						self.printFuzzResults()
						self.stop()
						raise StopIteration()
					yield
			# If register needed and could not register = > stop app
			elif not (self.user.reg_result=='success' or self.user.reg_result==None):
				print 'Could not register user.'
				self.stop()
				raise StopIteration()
			yield
