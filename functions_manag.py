import socket
import requests
import os
import threading
import nmap
import speedtest
import subprocess
from configparser import ConfigParser


global api_key_virustotal
global api_key_emailverification
global api_key_shodan
config = ConfigParser()
config.read('config.cfg', encoding='utf-8')

api_key_virustotal = config.get('api_keys', 'api_key_virustotal')
api_key_emailverification = config.get('api_keys', 'api_key_emailverification')
api_key_shodan = config.get('api_keys', 'api_key_shodan')




class Data_1:#Checks information on the remote computer
    def Network_info(self):  #
        self.cmd_command = 'ipconfig | findstr /i "IPv4 Address"'
        self.output = subprocess.check_output(self.cmd_command, shell=True, encoding='utf-8')#Checks the computer's internal IP address
        self.lines = self.output.split("\n")
        self.filter_8 = [line.split(":")[1].strip() for line in self.lines if line.strip().startswith("IPv4 Address")]#Filtering the output
        self.filter_9 = list(filter(None, self.filter_8))
        self.output = self.filter_9
        self.ip_private_1 = self.output[0]
        self.ip_private_2 = ("private ip address:{0}".format(self.ip_private_1))
        self.cmd_command = 'ipconfig | findstr /i "gateway"'   #Checks the router address of the remote computer's network
        self.output = subprocess.check_output(self.cmd_command, shell=True, encoding='utf-8')
        self.lines = self.output.split("\n")
        self.filter_6 = [line.split(":")[1].strip() for line in self.lines if line.strip().startswith("Default Gateway")]
        self.filter_7 = list(filter(None, self.filter_6))
        self.output = self.filter_7
        self.ip_gateway_1 = self.output[0]
        self.ip_gateway_2 = ("Default Gateway:{0}".format(self.ip_gateway_1))
        self.output = subprocess.check_output(['curl', '-s', 'ifcfg.me']) #Checks the external IP address to which the remote computer is connected
        self.ip_1 = self.output.decode('utf-8').strip().split('\n')[-1]
        self.ip_pbulk = ("Public Ip Address:{0}".format(self.ip_1))
        self.response = requests.get('http://ip-api.com/json')  # Checks the name of the external provider to which the remote computer is connected
        self.data = self.response.json()
        self.isp = ("isp:{0}".format(self.data['isp']))
        self.network_info_1=("Network information:""\n",self.ip_private_2,"\n",self.ip_gateway_2,"\n",self.isp,"\n",self.ip_pbulk,"\n")#Network data summary
        self.cmd_command = 'systeminfo | find /i "Original Install Date"'
        self.output = subprocess.check_output(self.cmd_command, shell=True, encoding='utf-8')
        self.upda_1 = self.output[self.output.find(":") + 6: self.output.rfind(":") + 2]
        self.upda_2=("Last Updated In:{0}".format(self.upda_1))#Checking the latest version update performed on the pharmacist's computer
        self.cmd_command = 'systeminfo | findstr /C:"OS Name'
        self.output = subprocess.check_output(self.cmd_command, shell=True, encoding='utf-8')
        self.type_1 = self.output[self.output.find(":") + 19:]
        self.type_2=("Operating System:{0}".format(self.type_1))#Checking the type of operating system for the remote computer
        self.ver = (os.popen("ver").read())
        self.version_1 = self.ver[self.ver.rfind("[") + 9:self.ver.find("]") - 1]
        self.version_2=("Version:{0}".format(self.version_1))#Checking version for the remote computer
        self.hostname_1 = (os.popen("hostname").read())
        self.hostname_2=("Name Connected Computer:{0}".format(self.hostname_1))#Checking the remote computer name
        self.username_1 = (os.popen("echo %username%").read())
        self.username_2 =("Logged In Username:{0}".format(self.username_1))#Checking the username on the remote computer
        self.all_inf=("System Information:""\n\n",self.hostname_2,self.username_2,self.type_2,self.version_2,"\n",self.upda_2, \
        "\n\n""Network Information:""\n\n",self.ip_private_2,"\n",self.ip_gateway_2,"\n",self.isp,"\n",self.ip_pbulk,"\n")
        return self.all_inf  #Entering all the information in a variable


class Options:
    def __init__(self):
        pass

    def scanner_ports(self, ip_address,start_port, end_port): #Scans ports to an internal address
        self.scanner = nmap.PortScanner()
        self.scanner.scan(ip_address, f"{start_port}-{end_port}")
        self.results = []
        for host in self.scanner.all_hosts():
            self.results.append(f"סריקת פורטים עבור כתובת IP: {host}")
            for protocol in self.scanner[host].all_protocols():
                self.ports = self.scanner[host][protocol].keys()
                self.sorted_ports = sorted(self.ports)
                for port in self.sorted_ports:
                    self.port_state = self.scanner[host][protocol][port]['state']
                    self.results.append(f"פורט {port}/{protocol}  {self.port_state}")
        self.results_1 = '\n'.join(self.results)
        return self.results_1


    def run_speed(self):  #Network speed test with directory  speedtest
        self.speed = speedtest.Speedtest(secure=2)
        #self.speed.get_best_server()
        self.down_speed = self.speed.download()
        self.uploa_speed = self.speed.upload()
        #self.ping_result = self.speed.results.ping
        self.u = self.down_speed, self.uploa_speed
        self.do = (f"מהירות הורדה: {self.down_speed / 1024 / 1024:.2f}Mbps")
        self.up = (f"מהירות העלאה: {self.uploa_speed / 1024 / 1024:.2f}Mbps")
        #self.ping_data=(f"Ping: {self.ping_result}ms")
        self.ll = [self.do, "\n", self.up]#, "\n",self.ping_data]
        return (self.ll)

    def my_ip1(self):  #Internal IP address check for network scanning
        self.ip_list = []
        self.ip = os.popen("wmic NICCONFIG WHERE IPEnabled=true GET IPAddress")
        for line in self.ip.readlines():
            if "{" in line:
                self.start = line.find('"') + 1
                self.end = line[self.start:].find('"') + self.start
                self.ip_list.append(line[self.start:self.end])
                self.ip1 = self.ip_list[0]
        return self.ip1

    def scanner_1(self, ip_address, clients, lock, Working):  #Sending a ping to any ip address
        result = os.popen("ping {0} -n 1".format(ip_address)).read()
        if "TTL" in result:
            with lock:
                clients.append(ip_address)

    def scanner_2(self):  # Manage sending the ping simultaneously to all addresses
        self.my_ip = self.my_ip1()
        self.network = self.my_ip[:self.my_ip.rfind(".") + 1]
        self.clients = []
        self.threads = []
        self.lock = threading.Lock()
        for item in range(1, 255):
            self.test = self.network + str(item)
            self.t = threading.Thread(target=self.scanner_1, args=(self.test, self.clients, self.lock, None))
            self.t.start()
            self.threads.append(self.t)
        for thread in self.threads:
            thread.join()
        # Creating a list of IP addresses as a string
        ip_addresses = '\n'.join(self.clients)
        return ip_addresses  # Returning the string with the IP addresses

    def check_ip(self,ip_address):#Non-malicious public ip address check
        self.url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        self.api_key_virustotal = list(api_key_virustotal)
        headers = {
            "accept": "application/json",
            "x-apikey": api_key_virustotal
        }
        self.response = requests.get(self.url, headers=headers)
        self.data_1 = self.response.json()  #Receiving the values and inserting them into the variables
        # data = f"last_analysis_date: {data_1['data']['attributes']['last_analysis_date']}\n"
        #data = f"as_owner: {self.data_1['data']['attributes']['as_owner']}\n"
        #data = f"last_analysis_stats: {self.data_1['data']['attributes']['last_analysis_stats']}\n"
        data = f"harmless: {self.data_1['data']['attributes']['last_analysis_stats']['harmless']}\n"
        data += f"malicious: {self.data_1['data']['attributes']['last_analysis_stats']['malicious']}\n"
        data += f"suspicious: {self.data_1['data']['attributes']['last_analysis_stats']['suspicious']}\n"
        data += f"undetected: {self.data_1['data']['attributes']['last_analysis_stats']['undetected']}\n"
        data += f"timeout: {self.data_1['data']['attributes']['last_analysis_stats']['timeout']}"
        return data

    def check_url(self, url):#Non-malicious url  check
        self.url = f"https://www.virustotal.com/api/v3/domains/{url}"
        self.api_key_virustotal=list(api_key_virustotal)
        headers = {
            "accept": "application/json",
            "x-apikey": api_key_virustotal
        }
        self.response = requests.get(self.url, headers=headers)
        self.data_1 = self.response.json()  #Receiving the values and inserting them into the variables
        #data = f"last_analysis_date: {self.data_1['data']['attributes']['last_analysis_date']}\n"
        #data = f"last_analysis_stats: {self.data_1['data']['attributes']['last_analysis_stats']}\n"
        data = f"harmless: {self.data_1['data']['attributes']['last_analysis_stats']['harmless']}\n"
        data += f"malicious: {self.data_1['data']['attributes']['last_analysis_stats']['malicious']}\n"
        data += f"suspicious: {self.data_1['data']['attributes']['last_analysis_stats']['suspicious']}\n"
        data += f"undetected: {self.data_1['data']['attributes']['last_analysis_stats']['undetected']}\n"
        data += f"timeout: {self.data_1['data']['attributes']['last_analysis_stats']['timeout']}"
        return data


    def check_email(self,email):#Non-malicious email  check
        self.api_key_emailverification=list(api_key_emailverification)
        self.url = f'https://emailverification.whoisxmlapi.com/api/v2?apiKey={api_key_emailverification}&emailAddress={email}&_hardRefresh=1'
        r = requests.get(self.url)
        self.data = r.json()  ##Receiving the values and inserting them into the variables
        result = f"Username: {self.data['username']}\n"
        result += f"Domain: {self.data['domain']}\n"
        result += f"Email Address: {self.data['emailAddress']}\n"
        result += f"Format Check: {self.data['formatCheck']}\n"
        result += f"SMTP Check: {self.data['smtpCheck']}\n"
        result += f"DNS Check: {self.data['dnsCheck']}\n"
        result += f"Free Check: {self.data['freeCheck']}\n"
        result += f"Disposable Check: {self.data['disposableCheck']}\n"
        result += f"Catch-All Check: {self.data['catchAllCheck']}\n"
        result += "MX Records:\n"
        for mx_record in self.data['mxRecords']:
            result += f"- {mx_record}\n"
        result += f"Audit Created Date: {self.data['audit']['auditCreatedDate']}\n"
        result += f"Audit Updated Date: {self.data['audit']['auditUpdatedDate']}\n"
        return result


class scanner_ports_public:#Port scanning for a public ip address
    def __init__(self):
        self.data = ""
    def scan(self, target_ip):
        url = f"https://api.shodan.io/shodan/host/{target_ip}?key={api_key_shodan}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            return None
    def data_get(self, result):
        if result:
            self.data = f"מידע מ-Shodan API:\n"
            self.data += f"last_update: {result.get('last_update', 'N/A')}\n"
            self.data += f"isp: {result.get('isp', 'N/A')}\n"
            self.data += f"country_name: {result.get('country_name', 'N/A')}\n"
            self.data += f"org: {result.get('org', 'N/A')}\n"
           # self.data += f"ports: {result.get('ports', 'N/A')}\n"
            self.data += f"os: {result.get('os', 'N/A')}\n"
            self.data += f"vulns: {result.get('vulns', 'N/A')}\n"
            ports = result.get('ports', [])
            if ports:
                self.data += "ports:\n"
                for port in ports:
                    self.data += f"  * {port}\n"
        else:
            self.data = "אירעה שגיאה בבקשה ל-Shodan API"
    def run_scan_and_print(self, target_ip):
        result = self.scan(target_ip)
        self.data_get(result)


class Portsanner_1:#Port scanning for a private ip address
    def __init__(self, target_ip: object, start_port: object, end_port: object) -> object:
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.open_ports = []
        self.data = ""
        self.lock = threading.Lock()
    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((self.target_ip, port))
        sock.close()
        if result == 0:
            with self.lock:
                self.open_ports.append(port)
                self.check_service(port)
    def check_service(self, port):
           try:
               service = socket.getservbyport(port)
               self.data+= f"פורט {port} פתוח ומשתמש בשירות: {service}\n"
           except:
               self.data += f"פורט {port}פתוח אך לא ניתן לזהות את השירות\n"
               return self.data
    def start_scan(self):
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()














