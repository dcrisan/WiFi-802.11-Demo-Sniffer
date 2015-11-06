#
#  Copyright 2015 Diana A. Vasile
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

class Utils:
	def sanitizeMac(self, mac):
        	temp = mac.replace(":", "").replace("-", "").replace(".", "").upper()
        	return temp[:2] + ":" + ":".join([temp[i] + temp[i+1] for i in range(2,12,2)])	
	

	def dotreplace(self, matchobj):
       		if matchobj.group(0) == '.':
         	       return ''
         	elif  matchobj.group(0) == ':':
         	       return ''


	def pretty_print(self,vals):
	        for k in vals:
        	        print k
                	d[k] = set(d[k])
	                for x in d[k]:
        	                if x != '':
                	                print "\t" + x
	def trace(self,frame, event, arg):
    		print "%s, %s:%d" % (event, frame.f_code.co_filename, frame.f_lineno)
    		return trace
