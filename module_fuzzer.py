# Fuzzing App
import os, sys, traceback, socket, multitask
from sipot import App, User, logger, bcolors
from std import rfc3261, rfc2396
# Sulley
sys.path.append(''.join([os.getcwd(), '/lib/sulley']))
from sulley import *
sys.path.append(''.join([os.getcwd(), '/lib/sulley/requests']))
import sip_block
sys.path.append(''.join([os.getcwd(), '/lib/']))


class fuzzerUser(User):
	'''The User object provides a layer between the application and the SIP stack.'''
	# self.state  				//  user state
	FUZZING, FUZZING_COMPETED,SETTING_CRASH_DETECT = 'User fuzzing', 'Fuzzing completed!', 'Setting crash detect'
	# self.crash_det_state  	//  communication between _setCrashDetect & mainController
	CRASH_SET, CRASH_ERROR = 'Crash detection working', 'Crash error'
	# self.crash_porbe  		//  crash internal self.crash_msg
	FUZZ_RECV, CRASH_PROBE_SENT, CRASH_PROBE_REC = 'Fuzz response received', 'Crash detection message sent', 'Response to crash probe received'
	# self.crash_fuzz  			//  Communication between self._fuzzing & self._setCrashDetect
	WAIT_FUZZ, WAIT_CRSH_CHK = 'Waiting Fuzz msg to be sent', 'Waiting crash to be checked'
	
	def __init__(self, app):
		User.__init__(self,app)
        #Fuzzer options
		self.fuzzer = app.options.fuzzer
		self.crash_detect = app.options.crash_detect
		self.crash_method  = app.options.crash_method
		self.fuzz_max_msgs  = app.options.fuzz_max_msgs
		#Fuzzer sets
		self._fuzzerGen = None
		self._setCrashGen = None
		self.fuzz_index = 0
		self.mutations = 0
		self.start_fuzz_time = None
		#Crash detection 
		self.crash_det_state = None
		self.crash_porbe = None
		self.crash_fuzz = None
		
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
		
	def add_setCrashDetectGen(self):
		self.app.status.append('Crash detection Initiated')
		self.state = self.SETTING_CRASH_DETECT
		if not self._setCrashGen:
			self._setCrashGen  = self._setCrashDetect()
			multitask.add(self._setCrashGen)
		return self
		
	def _fuzzing(self):
		# Msg to Fumzz generator ---------
		fuzzers = {'InviteCommonFuzzer': 'INVITE_COMMON', 'InviteStructureFuzzer': 'INVITE_STRUCTURE', 'InviteRequestLineFuzzer': 'INVITE_REQUEST_LINE','InviteOtherFuzzer': 'INVITE_OTHER', 'CANCELFuzzer': 'CANCEL', 'REGISTERFuzzer': 'REGISTER','SUBSCRIBEFuzzer': 'SUBSCRIBE', 'NOTIFYFuzzer': 'NOTIFY', 'ACKFuzzer': 'ACK'}

		def fuzzingCtrl(fuzz_index):
			if self.state == self.FUZZING:
				import datetime
				def log_perc_completed(i, partials, total=self.mutations):
					partials = map(int,(partials.split(',')))
					for partial in partials:
						if i == (partial*total/100):
							logger.info(str((datetime.datetime.now()-self.start_fuzz_time).total_seconds()*1000)+' msec'+':		'+str(int((total*partial/100)//1))+'/'+str(total)+' ('+str(int((partial)//1))+'%) messages sent')
				if not self.start_fuzz_time:
					self.start_fuzz_time = datetime.datetime.now()
				if self.crash_detect:
					log_perc_completed(fuzz_index,'1,2,4,8,10,20,30,40,50,60,70,80,90,100')
				else:
					log_perc_completed(fuzz_index,'25,50,75,100')
				
		def _createMutableMessage():
			# Msg to Fuzz generator ---------
			if not self.fuzzer == 'All':
				mutable_msg = s_get(fuzzers.get(self.fuzzer))
			else:
				mutable_msg = s_get(fuzzers.get('INVITE_COMMON'))
			return mutable_msg
			
		def _createFuzzerMsgGen(mutable_msg):
			def replaceDefaults(rendered_msg):
				from random import Random
				import string
				# branch
				self.curr_invite_branch = ''.join(Random().sample(string.ascii_lowercase+string.digits, 32))
				rendered_msg = rendered_msg.replace('somebranchvalue', self.curr_invite_branch)
				rendered_msg = rendered_msg.replace('somefromtagvalue', self.curr_invite_branch)
				rendered_msg = rendered_msg.replace('somecallidvalue', self.curr_invite_branch)
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
				
			if not self.fuzzer == 'All':
				for i in range(min(self.mutations, self.fuzz_max_msgs)):
					mutable_msg.mutate()
					m = replaceDefaults(mutable_msg.render())
					yield (m)
			else:
				msg_counter = 0
				for item in fuzzers:
					mutable_msg = s_get(fuzzers.get(item))
					for i in range(mutable_msg.num_mutations()):
						msg_counter += 1
						if msg_counter < min(self.mutations, self.fuzz_max_msgs):
							mutable_msg.mutate()
							m = replaceDefaults(mutable_msg.render())
							yield (m)
		
		if not self.crash_detect: self._listenerGen.close()
		# Dest Address
		addr = self.remoteTarget.uri
		if addr and isinstance(addr, rfc2396.URI):
			if not addr.host: raise ValueError, 'No host in destination uri'
			addr = (addr.host, addr.port or self.transport.type == 'tls' and self.transport.secure and 5061 or 5060)
		mutable_msg = _createMutableMessage()
		# Msg generator
		if not self.fuzzer == 'All':
			self.mutations = mutable_msg.num_mutations()
		else:
			self.mutations = 0
			for item in fuzzers:
				self.mutations += s_get(fuzzers.get(item)).num_mutations()
		Fuzz_Generator = _createFuzzerMsgGen(mutable_msg)
		print "Fuzzing %s messages to %s" % (self.mutations, addr) # TODO!!
		try:
			if self.sock:
				if self.sock.type == socket.SOCK_STREAM:
					pass
				elif self.sock.type == socket.SOCK_DGRAM:
					while True:
						try:
							data = str(Fuzz_Generator.next())
							if len(data) > 9216:
								data = data[:9216]
							try:
								self.sock.sendto(data, addr)
								self.fuzz_index += 1
								fuzzingCtrl(self.fuzz_index)
								self.crash_fuzz=self.WAIT_CRSH_CHK
								# if crash detect => wait until crash detection is completed
								# print '1. Fuzz sent'
								while (self.crash_detect and self.crash_fuzz!=self.WAIT_FUZZ):
									yield multitask.sleep(1)
							except socket.error:
								logger.debug('socket error in sendto' )
						except StopIteration:
							self.state = self.FUZZING_COMPETED
							raise StopIteration()
						yield
				else:
					logger.debug('invalid socket type', self.sock.type)
		except AttributeError: pass

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
							if self.crash_fuzz==self.WAIT_CRSH_CHK and self.crash_porbe==self.CRASH_PROBE_REC:
								# If response to fuzz is received
								# m._parse(data)
								self.app.fuzzResponse[str(self.fuzz_index)] = data.split('\n', 1)[0].replace('\r','')
								self.crash_porbe=self.FUZZ_RECV
							elif self.crash_fuzz==self.WAIT_CRSH_CHK and self.crash_porbe==self.CRASH_PROBE_SENT:
								# If response to probe received
								self._stack.received(data, remote)
								self.app.probeResponse[str(self.fuzz_index)] = data.split('\n', 1)[0].replace('\r','')
						except ValueError, E: # TODO: send 400 response to non-ACK request
							logger.debug('Error in received message:', E)
							logger.debug(traceback.print_exc())
				except multitask.Timeout: pass
		except GeneratorExit: pass
		except: print 'User._listener exception', (sys and sys.exc_info() or None); traceback.print_exc(); raise
		logger.debug('terminating User._listener()')

	def _setCrashDetect(self):
		try:
			request_porbe = self._ua.createRequest(self.crash_method)
			r = []
			for i in range(3): # 3 responses to get default response
				self._ua.sendRequest(request_porbe)
				self.crash_porbe = self.CRASH_PROBE_SENT
				WaitingResponse = True
				while WaitingResponse:
					response = (yield self._ua.queue.get())
					if response:
						self.crash_porbe = self.CRASH_PROBE_REC
						r.append(response)
						WaitingResponse = False
						if response.CSeq.method == self.crash_method:
							if str(response.response) == '408':
								print (bcolors.FAIL+"Request timeout!"+bcolors.ENDC +" Please verify if SIP destination is available.")
								self.crash_det_state = self.CRASH_ERROR
			if (str(r[0].Cseq) == str(r[1].Cseq) == str(r[2].Cseq))and(str(r[0].Via) == str(r[1].Via) == str(r[2].Via))and(str(r[0].From) == str(r[1].From) == str(r[2].From)):
				self.crash_response = response
				self.crash_det_state = self.CRASH_SET
				self.crash_fuzz=self.WAIT_FUZZ
				#####_self.CRASH_SET: Start crash detection_################################################
				while True:
					if self.crash_fuzz==self.WAIT_CRSH_CHK:
						WaitingResponse = True
						while WaitingResponse: 		# If fuzz sent => wait fuzz response.
							if self.crash_porbe==self.FUZZ_RECV:
								# print '2. Fuzz responded'
								WaitingResponse = False
							yield
						# Fuzz response received => send probe
						request_porbe.CSeq = rfc3261.Header(str(request_porbe.CSeq.number+1) + ' ' + request_porbe.CSeq.method, 'CSeq')
						self._ua.sendRequest(request_porbe)
						# print '3. Probe sent'
						self.crash_porbe = self.CRASH_PROBE_SENT
						WaitingResponse = True
						while WaitingResponse: 		# Probe sent => wait probe response.
							response = (yield self._ua.queue.get())
							if response:
								# print '4. Probe responded'
								WaitingResponse = False
								self.crash_porbe = self.CRASH_PROBE_REC
								self.crash_fuzz = self.WAIT_FUZZ
					yield
				#####################################################
				#####################################################
			else:
				print (bcolors.WARNING+"Verification fail!"+bcolors.ENDC +" It seems that we could not confirm a default response.")
				self.crash_det_state = self.CRASH_ERROR
		except GeneratorExit:
			raise StopIteration(('failed', 'Generator closed'))

class FuzzingApp(App):
	def __init__(self, options):
		App.__init__(self,options)
		logger.info("ntsga: init fuzzing app")
		self.fuzzResponse = dict()
		self.probeResponse = dict()

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
	
	def printResults(self):
		lenres = len(self.fuzzResponse)
		if lenres > 0:
			from pptable import indent,wrap_onspace
			width = 60
			labels = ('Index','Fuzz response','Probe response')
			rows = list()
			for index in sorted(self.fuzzResponse.keys()):
				rows.append((index,self.fuzzResponse[index],self.probeResponse[index]))
			if self.options.file_name:
				target = open (self.options.file_name, 'a')
				target.write(indent([labels]+rows,hasHeader=True, prefix='| ', postfix=' |',wrapfunc=lambda x: wrap_onspace(x,width)))
				target.close()
				print "Find results at file: <"+self.options.file_name+">"
			else:
				print indent([labels]+rows,hasHeader=True, prefix='| ', postfix=' |',wrapfunc=lambda x: wrap_onspace(x,width))
			

	def mainController(self):
		logger.info("ntsga: start fuzzing controller")
		while True:
			if self.status: # Print app status
				print self.status.pop(0)
			# If not register needed or already registered => fuzz
			if not self.options.register or (self.options.register and self.user.reg_state==self.user.REGISTERED):
				while True:
					# If not crash_detect => fuzz,  else => set setCrashDetect
					if not self.options.crash_detect or (self.options.crash_detect and self.user.crash_det_state==self.user.CRASH_SET):
						self.user.add_fuzzerGen()
						while True:
							yield multitask.sleep(1)
							if not self.user.state == self.user.FUZZING:
								self.printResults()
								self.stop()
								raise StopIteration()
							yield
					else:
						# crash detection active
						self.user.add_setCrashDetectGen()	
						if self.user.crash_det_state==self.user.CRASH_ERROR:
							self.printResults()
							self.stop()
							raise StopIteration()
					yield
			# If register needed and could not register = > stop app
			elif not (self.user.reg_result=='success' or self.user.reg_result==None):
				print 'Could not register user.'
				self.stop()
				raise StopIteration()
			yield
