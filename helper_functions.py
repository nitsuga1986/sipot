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
