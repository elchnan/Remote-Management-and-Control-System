import os
import subprocess
import tkinter
import tkinter as tk
from socket import *
import threading
from tkinter import END, Button, ttk, messagebox
from datetime import datetime
from functions_manag import Options, scanner_ports_public, Portsanner_1

class ServerApp:
    def __init__(self, *args):
        self.host = None
        self.scan = None
        self.p = None
        self.client = None
        self.entry30_value = None
        self.entry20_value = None
        self.entry10_value = None
        self.options = None
        self.entry10 = None
        self.window = tk.Tk()
        self.server = socket(AF_INET, SOCK_STREAM)
        self.server.bind(("",1235))
        self.server.listen(50)
        self.ss_1 = tk.IntVar(value=0)
        self.window.title("Management")
        self.window.geometry('800x650')
        self.txt = tk.Text(self.window, width=41)
        self.txt.place(x=445, y=70)
        self.txt_1 = tk.Text(self.window, width=41)
        self.txt_1.place(x=445, y=350)
        self.bl1 = tk.Label(self.window, text="CMD")
        self.bl1.place(x=445, y=48)
        self.btn1 = tk.Button(self.window, text="  Enter ",command= self.cmd_get)
        self.btn1.place(x=726, y=46)
        self.ent1 = tk.Entry(self.window, width=40)
        self.ent1.place(x=480, y=50)
        self.ent7 = tk.Entry(self.window, width=17)
        self.ent7.place(x=20, y=40)
        self.btn8 = tk.Button(self.window, text="נתק חיבור מרחוק ", command=self.close)
        self.btn8.place(x=20, y=70)
        self.is_remote = tk.BooleanVar()
        self.is_remote.trace("w", self.host)
        self.checkbutton = tk.Checkbutton(self.window, text="מחשב  שלי ", variable=self.is_remote)
        self.checkbutton.place(x=200, y=60)
        self.host = 0
        self.btn2 = tk.Button(self.window, text="          סרוק רשת                ", command=self.scanner_update_text)
        self.btn2.place(x=200, y=90)
        self.btn3 = tk.Button(self.window, text="          סרוק פורטים            ", command=self. ports_type)
        self.btn3.place(x=200, y=115)
        self.btn4 = tk.Button(self.window, text="       בדיקת מהירות            ", command=self.speed_update_text)
        self.btn4.place(x=200, y=140)
        self.btn5 = tk.Button(self.window, text="             IP סרוק כתובת     ", command=self.type_ports_2)
        self.btn5.place(x=199, y=192)
        self.btn6 = tk.Button(self.window, text="            URL בדוק כתובת   ", command=self.scon_url)
        self.btn6.place(x=199, y=218)
        self.btn7 = tk.Button(self.window, text="                IP בדוק כתובת   ", command=self.type_ip)
        self.btn7.place(x=199, y=244)
        self.btn8 = tk.Button(self.window, text="        EMAIL בדוק כתובת   ", command=self.type_email)
        self.btn8.place(x=199, y=270)
        server_thread = threading.Thread(target=self.start_server)
        server_thread.start()
        self.up_time()
        self.window.mainloop()

    def start_server(self):#  Runs a function to get information about the clicet
        while True:
            if not self.client:
               self.client, addr = self.server.accept()
               while True:
                   data = "Information"
                   self.client.sendall(data.encode())
                   data = self.client.recv(2048).decode()
                   self.txt_1.delete('1.0', END)
                   self.txt_1.insert(END, data)
                   break


    def up_time(self):#Activating and printing the time
         now = datetime.now()
         self.ent7.delete('0', END)
         self.ent7.insert(END, now.strftime("%Y-%m-%d %H:%M:%S"))
         self.window.after(1000, self.up_time)


    def close(self):#close the  socket
        self.client.close()
        self.txt.delete('1.0', END)
        self.txt.insert(END, "החיבור נותק")

    def type_host(self, *args):#
        if self.is_remote.get():
            self.host = 1
        else:
            self.host = 0

    def cmd_get(self):#sends a command to an operating system (cmd)
         data = (self.ent1.get())
         if self.host == 0:
             self.client.sendall(data.encode())
             data = self.client.recv(2048).decode()
         else:
             try:
                 result = subprocess.run(data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
                 error_message = f"Command failed with code {result.returncode}\n{result.stderr}"
                 if result.returncode != 0:
                     data = error_message
                 else:
                     data = result.stdout
             except Exception as e:
                 data = f"General error: {e}"
         self.txt.delete('1.0', END)
         self.txt.insert(END, data)

    def speed_update_text(self):#A function that activates a function to test the network speed
        def update_text(data): #A function that receives the data from the test and updates
            self.txt.delete('1.0', END)
            self.txt.insert(END, data)
        def ran_speed():# This function performs a separate process in the background
            global ee
            messagebox.showwarning("שימו לב", " speedtest-cli  שים לב!  בפונקציה זאת יש להתקין ספרית")
            self.txt.delete('1.0', END)
            self.txt.insert(END, "הבדיקה מתבצעת אנא המתן...")
            if self .host ==0:
                self.data = "speed"
                self.client.sendall(self.data.encode())
                data = self.client.recv(2048).decode()
                self.window.after(0, update_text, data)
            else:
                data_1 = Options()
                data = data_1.run_speed()
                ee = ''.join(data)
            self.window.after(0, update_text,ee)
        scanner_thread = threading.Thread(target=ran_speed)
        scanner_thread.start()

    def scanner_update_text(self):#A function that activates a function to scan the network
        def update_text(data): #A function that receives the data from the test and updates
            self.txt.delete('1.0', END)
            self.txt.insert(END, data)
        def ran_scanner():# A function that executes a separate process in the background
            self.txt.delete('1.0', END)
            self.txt.insert(END, "הסריקה מתבצעת אנא המתן...")
            if self .host ==0:
                self.data = "scanner"
                self.client.sendall(self.data.encode())
                data = self.client.recv(2048).decode()
            else:
                data_1 = Options()
                data = data_1.scanner_2()
            self.window.after(0, update_text, data)
        scanner_thread = threading.Thread(target=ran_scanner)
        scanner_thread.start()


    def port_update_text(self,get_ip, who_port, to_port):#A function that activates a function to scan the network

        def update_text(data): #A function that receives the data from the test and updates
            self.txt.delete('1.0', END)
            self.txt.insert(END, data)
        def ran_scanner():# A function that executes a separate process in the background
            self.target_ip = self.get_ip.get()
            self.start_port = self.who_port.get()
            self.end_port = self.to_port.get()
            self.frame.destroy()
            self.txt.delete('1.0', END)
            self.txt.insert(END, "הסריקה מתבצעת אנא המתן...")
            if self .host ==0:
                self.data = f"ports|{self.target_ip}|{self.start_port}|{self.end_port}"
                self.client.sendall(self.data.encode())
                data = self.client.recv(2048).decode()
                self.window.after(0, update_text, data)
            else:
                self.end_port = int(self.end_port)
                self.start_port = int(self.start_port)
                scanner = Portsanner_1(self.target_ip,self.start_port,self.end_port)
                scanner.start_scan()
            self.window.after(0, update_text, scanner.data)
        scanner_thread = threading.Thread(target=ran_scanner)
        scanner_thread.start()




    def scon_url(self):#Receiving an url address to check that it is not malicious
        messagebox.showwarning("None", " API KEY  שים לב!  בפונקציה זאת יש להכניס")
        self.frame = tk.Toplevel(self.window)
        #self.frame.geometry("300x200+100+100")
        self.my_url = tk.Label(self.frame, text="URL כתובת")#Obtaining an url for scanning
        self.my_url.grid(row=0, column=0)
        self.url = tk.Entry(self.frame)
        self.url.grid(row=0, column=1)
        self.submit_button = Button(self.frame, text="סרוק", command = self.urls_1)#Sending to a function that will activate the scanning function
        self.submit_button.grid(row=3, columnspan=2)

    def urls_1(self):#Activation of url scanning function
        url = self.url.get()
        uu = Options()
        pp = uu.check_url(url)
        self.frame.destroy()
        self.txt.delete('1.0', END)
        self.txt.insert(END, pp)

    def type_ip(self):#Receiving an ip address to check that it is not malicious
        messagebox.showwarning("שימו לב", " API KEY  שים לב!  בפונקציה זאת יש להכניס")
        self.frame = tk.Toplevel(self.window)
        #self.frame.geometry("300x200+100+100")
        self.my_ip = tk.Label(self.frame, text="IP כתובת")#Obtaining an ip address for scanning
        self.my_ip.grid(row=0, column=0)
        self.get_ip_scon = tk.Entry(self.frame)
        self.get_ip_scon.grid(row=0, column=1)
        self.submit_button = Button(self.frame, text="סרוק", command = self.scan_ip)#Sending to a function that will activate the scanning function
        self.submit_button.grid(row=3, columnspan=2)

    def scan_ip(self):#Activation of Ip address scanning function
        ip = self.get_ip_scon.get()
        uu = Options()
        pp = uu.check_ip(ip)
        self.frame.destroy()
        self.txt.delete('1.0', END)
        self.txt.insert(END, pp)

    def type_email(self):#Receiving an email address to check that it is not malicious
        messagebox.showwarning("שימו לב", " API KEY  שים לב!  בפונקציה זאת יש להכניס")
        self.frame = tk.Toplevel(self.window)
        # self.frame.geometry("300x200+100+100")
        self.my_email = tk.Label(self.frame, text="EMAIL כתובת")#Receive an email address to scan
        self.my_email.grid(row=0, column=0)
        self.email = tk.Entry(self.frame)
        self.email.grid(row=0, column=1)
        self.submit_button = Button(self.frame, text="סרוק", command = self.scan_email)#Sending the email address and activating a function
        self.submit_button.grid(row=3, columnspan=2)

    def scan_email(self):#Activating the function to scan the email
        email = self.email.get()
        uu = Options()
        pp = uu.check_email(email)
        self.frame.destroy()
        self.txt.delete('1.0', END)
        self.txt.insert(END, pp)


    def ports_type(self):#A function that receives the input IP address from the output specification and runs the scan function
        self.frame = tk.Toplevel(self.window)
        #self.frame.geometry("50*60")
        self.my_ip = tk.Label(self.frame, text="IP כתובת")
        self.my_ip.grid(row=0, column=0)
        self.get_ip = tk.Entry(self.frame)
        self.get_ip.grid(row=0, column=1)
        self.which_port = tk.Label(self.frame, text=" מפורט")# Gets the beginning of a range of ports
        self.which_port.grid(row=1, column=0)
        self.who_port = tk.Entry(self.frame)
        self.who_port.grid(row=1, column=1)
        self.to_which_port = tk.Label(self.frame, text=" עד פורט")#Gets the end of the range of ports
        self.to_which_port.grid(row=2, column=0)
        self.to_port = tk.Entry(self.frame)
        self.to_port.grid(row=2, column=1)
        self.submit_button =Button(self.frame, text="  סרוק  ",command=lambda: self.port_update_text(self.get_ip, self.who_port,self.to_port))
        self.submit_button.grid(row=3, columnspan=6)

    def speed(self):
        messagebox.showwarning("שימו לב", " speedtest-cli  שים לב!  בפונקציה זאת יש להתקין ספריית")
        if self.host ==0:
           self.data = "speed"
           self.client.sendall(self.data.encode())
           data = self.client.recv(2048).decode()
        else:
            data_1 = Options()
            data = data_1.run_speed()
        self.txt.delete('1.0', END)
        self.txt.insert(END, data)


    def type_ports_2(self):#a function that receives an ip address and runs a function that scans the ip address
        messagebox.showwarning("שימו לב", " API KEY  שים לב!  בפונקציה זאת יש להכניס")
        self.frame = tk.Toplevel(self.window)
        # self.frame.geometry("300x200+100+100")
        self.what_ip = tk.Label(self.frame, text="IP כתובת")#gets an ip address
        self.what_ip.grid(row=0, column=0)
        self.ip_scan = tk.Entry(self.frame)
        self.ip_scan.grid(row=0, column=1)
        self.submit_button = Button(self.frame, text="סרוק", command=self.ports_2)#activates the scan function
        self.submit_button.grid(row=3, columnspan=2)



    def ports_2(self):#A function that sends the data to a function that scans the IP
        ip = self.ip_scan.get()
        data = scanner_ports_public()
        data.run_scan_and_print(ip)
        self.frame.destroy()
        self.txt.delete('1.0', END)
        self.txt.insert(END, data.data)

    def pack(self):
        pass


if __name__ == "__main__":
    app = ServerApp()

