#!/usr/bin/python3
# -*- coding: utf-8 -*

from cortexutils.analyzer import Analyzer
import os
import subprocess
import re
import paramiko


class SuricataRuleTest(Analyzer):
	def __init__(self):
		try:
			Analyzer.__init__(self)
			self.service = self.get_param('config.service', None, 'Running location is not defined')
			self.suricata_config = self.get_param('config.suricata_config', None, None)
			self.suricata_rule = self.get_param('config.suricata_rule', None, None)
			self.suricata_logfile = self.get_param('config.suricata_logfile', None ,None)
			self.reverse_taxonomy = self.get_param('config.reverse_taxonomy', None,None)
			if self.service == "remote":
				self.remote_host = self.get_param('config.remote_host', None, None)
				self.remote_user = self.get_param('config.remote_user', None, None)
				self.remote_port = self.get_param('config.remote_port', 22, None)
				self.remote_password = self.get_param('config.remote_password', None, None)
				self.remote_keyfile = self.get_param('config.remote_keyfile', None, None)
				self.allow_unknown_host = self.get_param('config.allow_unknown_host', None, None)
				
				if(self.remote_password == None and self.remote_keyfile == None):
					self.error("For remote connection at least one has to be configured: 1: ssh password 2: ssh keyfile")
				
			if (self.suricata_config == None and self.suricata_rule == None):
				self.error("At least one has to be configured: 1: Suricata config yaml file 2: Suricata rule file")
		except Exception as e:
			self.error("Init error: " +str(e))
			
	def run(self):
		try:   
			Analyzer.run(self)
			if self.data_type == 'file':
				filepath = self.get_param('file', None, None)
				if (filepath == None):
					self.error("No filepath has been provided.")
				
				#puttin together the suricata command
				#example: suricata -c /tmp/suricata.yaml -S /tmp/test.rule -r [pcap_name, not in the command]
				command = "suricata"
				if self.suricata_config != None and self.suricata_config != "":
					command = command + " -c " + self.suricata_config
				if self.suricata_rule != None and self.suricata_rule != "":
					command = command + " -S " + self.suricata_rule
				command = command + " -r "
				
				fast_log_entries = ""
				
				if(self.service == "local"):
					command = command + filepath
					fast_log_length = 0
					if(os.path.exists(self.suricata_logfile)):
						try:
							fast_log_length = sum(1 for line in open(self.suricata_logfile,'r'))
						except Exception as e:
							self.error("Suricata logfile couldn't be read: "+ self.suricata_logfile + " Error: "+ str(e))
			
					if subprocess.call(command, shell=True) ==1:
						self.error("Error during Suricata execution! "
						 "Executed command: " +str(command) +" "
						 "Check the suricata.log file for details.")
						 
					if(os.path.exists(self.suricata_logfile)):
						try:
							with open(self.suricata_logfile,'r') as logf:
								line_nr = 0
								for line in logf:
									line_nr +=1
									if (line_nr > fast_log_length):
										fast_log_entries = fast_log_entries + line
						except Exception as e:
							self.error("Suricata logfile couldn't be read: "+ self.suricata_logfile +" Error: "+ str(e))
				
				if(self.service == "remote"):
					command = command + "/tmp/"+filepath.split("/")[-1]
					ssh_client=paramiko.SSHClient()
					ssh_client.load_system_host_keys()
					if self.allow_unknown_host:
						ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

					if(self.remote_keyfile !=None):
						ssh_client.connect(hostname=self.remote_host,port=self.remote_port,
						username=self.remote_user,key_filename=self.remote_keyfile)	
					else:
						ssh_client.connect(hostname=self.remote_host,port=self.remote_port,
						username=self.remote_user,password=self.remote_password)	
						
					fast_log_length = 0 #entries in the fast.log file, we are using this number to find the new entries
					(stdin,stdout,stderr)=ssh_client.exec_command("wc -l "+self.suricata_logfile)
					if stdout.channel.recv_exit_status() == 1:
						if "Permission" in stderr.read().decode("utf-8"):
							self.error("No sufficient permission. Logfile: "+self.suricata_lofgile +" can't be read by this user.")
					else:
						fast_log_length = stdout.read().decode("utf-8").split(" ")[0]

					sftp = ssh_client.open_sftp()
					sftp.put(filepath,"/tmp/"+filepath.split("/")[-1])
					
					(stdin,stdout,stderr)=ssh_client.exec_command(command)	
					if stdout.channel.recv_exit_status() == 1:
						self.error("Error during Suricata execution! "
						 "Executed command: " +str(command) +" "
						 "Check the suricata.log file for details.")
					
					
					(stdin,stdout,stderr)=ssh_client.exec_command("wc -l "+self.suricata_logfile)
					if stdout.channel.recv_exit_status() == 1:
						self.error("Error in 'wc -l' execution")
					
					new_fast_log_length = stdout.read().decode("utf-8").split(" ")[0]
					if (new_fast_log_length  > fast_log_length):
						#this means new lines has been added
						(stdin,stdout,stderr)=ssh_client.exec_command("tail -n+"+str(int(fast_log_length)+1) +" "+self.suricata_logfile)	 
						if stdout.channel.recv_exit_status() == 1:
							if "Permission" in stderr.read().decode("utf-8"):
								self.error("No sufficient permission. Logfile: "+self.suricata_lofgile +" can't be read by this user.")	
							else:
								self.error("Error during logfile opening. Possibly the logfile location is not correct or suricata execution wasn't successful.")
						else:
							fast_log_entries= stdout.read().decode("utf-8")
						 
						 
						 
					if ssh_client is not None:
						#handling paramiko bug
						ssh_client.close()
						del ssh_client, stdin, stdout, stderr	
						
						
				
				rule_matches = {}
				test = []

				for line in fast_log_entries.split("\n"):
					try:
						match = re.search('\[\*\*\]\s+\[([0-9]+\:[0-9]+\:[0-9]+)\]\s+(.*)\s+\[\*\*\]',line)
						if match.group(1) in rule_matches.keys():
							rule_matches[match.group(1)]['counter'] +=1
						else:
							rule_matches[match.group(1)] =  {	'gid' : match.group(1).split(':')[0],
																'sid' : match.group(1).split(':')[1],
																'rev' : match.group(1).split(':')[2],
																'msg' : match.group(2),
																'counter': 1 }
					except:
						# if regex not working on a line, go to the next line
						# this happens when line is empty, or doesn't contain the pattern
						pass
					
					
				#successful execution
				self.report(rule_matches)
			else:
				self.error('Incorrect dataType. "file" expected')
		except Exception as e:
			self.error("Run error: " +str(e))
	 
	    
	def summary(self, raw):

		try:
            # default taxonomy
			taxonomies = []
			namespace = "SuricataRuleTest"
			predicate = "SignatureMatch"
			value = "NoMatch"
			level = "safe"
			
			
			if (len(raw) > 0):
                # the pcap triggered at least 1 rule
				value = len(raw)
				level = "malicious"
				match_cntr = 0
				
				for key in raw:
					match_cntr = match_cntr + raw[key]['counter']
	
				raw['details'] = "This pcap triggered " +str(len(raw)) +" different rule(s) " +str(match_cntr) +" times."
			else:
				raw['details'] = "None of the rules triggered on this packet."
				
			if self.reverse_taxonomy:
				level = "safe" if level == "malicious" else "malicious"
			
			taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
			return {"taxonomies": taxonomies}
		except Exception as e:
			self.error ("Summary error: "+str(e))	
			
			
if __name__ == '__main__':
	SuricataRuleTest().run()
