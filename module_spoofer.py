# Spoofing App
import multitask
from sipot import App, User, logger

class spooferUser(User):
	'''The User object provides a layer between the application and the SIP stack.'''
	SPOOFING = 'User Spoofing'
	def __init__(self, app):
		User.__init__(self,app)
        #Spoofer options
		self._spooferGen = None
	
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
		print 	"Spoofing App not implemented yet =("
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
			self.user.add_spooferGen()
			if not self.user.state == self.user.SPOOFING:
				self.stop()
				raise StopIteration()
			yield
