# Fuzzing App
import multitask
from sipot import App, User, logger

class fuzzerUser(User):
	'''The User object provides a layer between the application and the SIP stack.'''
	FUZZING = 'Registered user'
	def __init__(self, app):
		User.__init__(self,app)
        #Fuzzer options
		self._fuzzerGen = None
	
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
	
	def _fuzzing(self):
		print 	"Running Fuzzing App"
		self.app.stop()
		yield
		raise StopIteration()

class FuzzingApp(App):
	def __init__(self, options):
		App.__init__(self,options)
		logger.info("ntsga: init fuzzing app")

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
		
	def mainController(self):
		logger.info("ntsga: start fuzzing controller")
		while True:
			self.user.add_fuzzerGen()
			if not self.user.state == self.user.FUZZING:
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
