import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import sys
import os
import socket
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from network.server import start_server
from network.client import start_client
from encryption import encrypt_rsa, decrypt_rsa, generate_aes_key, encrypt_aes, decrypt_aes
from cryptography.hazmat.primitives import serialization
from network.utils import send_msg, recv_msg

class chat_app:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Chat")
        self.root.geometry("1460x750")

        #colors
        self.bg = "#0a0a0a"
        self.green = "#00ff00"
        self.gray = "#888888"
        self.white = "#ffffff"
        self.black = "#1a1a1a"

        self.chat_disabled_shown = False
        self.conn = None
        self.private_key = None
        self.peer_public_key = None
        self.aes_key = None
        self.mode = None
        self.connection = False
        self.server_socket = None

        #title
        title_container = tk.Frame(root, bg=self.black)
        title_container.place(relx=0.0, rely=0.0, relwidth=1.0, relheight=0.1)

        tk.Label(title_container, text="End-To-End Encrypted Chat", font=("Helvetica", 42, "bold"),
                 fg=self.green, bg=self.black).pack()
        
        #body
        body_container = tk.Frame(root, bg=self.bg)
        body_container.place(relx=0.0,rely=0.1, relwidth=1.0, relheight=0.9)

        #connection control section
        body_p1 = tk.Frame(body_container, bg=self.black)
        body_p1.place(relx=0.0, rely=0.0, relwidth=0.3, relheight=1.0)

        cc1 = tk.Frame(body_p1, bg=self.bg, highlightbackground=self.green, highlightthickness=1,
                       highlightcolor=self.green)
        cc1.place(relx=0.15, rely=0.1, relwidth=0.7, relheight=0.7)

        self.host_box = tk.Text(cc1, wrap="word", bg=self.bg, fg=self.green, state="disabled",
                                font=("Consolas", 11))
        self.host_box.pack(fill=tk.BOTH, expand=True)

        self.host_btn = tk.Button(body_p1, text="Host", bg=self.black, fg=self.green, command=self.host_mode,
                             font=("consolas", 16), cursor="hand2")

        self.peer_ip = tk.Entry(body_p1, font=("consolas", 16),
                                bg=self.bg, fg=self.green, insertbackground=self.green)
        
        self.peer_port = tk.Entry(body_p1, font=("consolas", 16),
                                bg=self.bg, fg=self.green, insertbackground=self.green)

        self.connect_btn = tk.Button(body_p1, text="Connect", bg=self.black, fg=self.green,
                                command=self.connect_mode, font=("consolas", 16), cursor="hand2")

        self.stop_btn = tk.Button(body_p1, text="Terminate Connection", bg=self.black, fg=self.green,
                                command=self.terminate, font=("consolas", 16), cursor="hand2")

        #message section
        body_p2 = tk.Frame(body_container, bg=self.bg)
        body_p2.place(relx=0.3, rely=0.0, relwidth=0.7, relheight=1.0)

        ms1 = tk.Frame(body_p2, bg=self.bg, highlightbackground=self.green, highlightthickness=2)
        ms1.place(relx=0.0, rely=0.0, relwidth=1.0, relheight=0.9)

        self.chat_box = scrolledtext.ScrolledText(ms1, wrap=tk.WORD, state="disabled",
                                                  bg=self.bg, fg=self.green, font=("Consolas", 25))
        self.chat_box.pack(fill=tk.BOTH ,expand=True)

        ms2 = tk.Frame(body_p2,bg=self.black)
        ms2.place(relx=0.0, rely=0.9, relwidth=1.0, relheight=0.1)

        self.message_entry = tk.Entry(ms2, border=3, borderwidth=1, width=40, font=("Consolas", 11),
                                      bg=self.bg, fg=self.green, insertbackground=self.green)
        self.message_entry.place(relx=0.08, rely=0.25, relwidth=0.7, relheight=0.5)

        send_btn = tk.Button(ms2, text="Send", bg=self.black, fg=self.green,
                             font=("Helvetica", 16, "bold"), command=self.send_message, cursor="hand2")
        send_btn.place(relx=0.8, rely=0.25, relwidth=0.15, relheight=0.5)

        #binding
        for widget in (self.host_box, self.chat_box):
            for event in ("<Button-1>", "<Double-1>", "<Triple-1>", "<B1-Motion>"):
                widget.bind(event, self.prevent_selection)

        #initializing buttons
        self.update_buttons()

    #utility
    def prevent_selection(self, event):
        return "break"
    
    def update_buttons(self):
        self.host_btn.place_forget()
        self.peer_ip.place_forget()
        self.peer_port.place_forget()
        self.connect_btn.place_forget()
        self.stop_btn.place_forget()

        if self.mode is None:
            self.host_btn.place(relx=0.7, rely=0.04, relwidth=0.15, relheight=0.05)
            self.peer_ip.place(relx=0.15, rely=0.81, relwidth=0.48, relheight=0.05)
            self.peer_port.place(relx=0.65, rely=0.81, relwidth=0.2, relheight=0.05)
            self.connect_btn.place(relx=0.15, rely=0.87, relwidth=0.7, relheight=0.05)
        else:
            self.stop_btn.place(relx=0.15, rely=0.81, relwidth=0.7, relheight=0.05)
    
    def append_message(self, message:str, target):
        target.config(state="normal")
        target.insert(tk.END, message + "\n")
        target.config(state="disabled")
        target.see(tk.END)

    #Networking
    def host_mode(self):
        self.chat_disabled_shown = False
        self.mode = "host"
        server_thread = threading.Thread(target=self.run_server, daemon=True)
        server_thread.start()
        self.update_buttons()

    def connect_mode(self):
        self.chat_disabled_shown = False
        ip = self.peer_ip.get().strip()
        port = int(self.peer_port.get().strip())
        if not ip and not port:
            messagebox.showwarning("No IP and Port", "Please enter the IP address and Port.")
            return
        elif not ip:
            messagebox.showwarning("No IP", "Please enter IP address")
            return
        elif not port:
            messagebox.showwarning("No Port", "Please enter Port number")
            return
        self.append_message(f'>Attepting to connect with :{ip}', self.host_box)
        self.mode = "client"
        client_thread = threading.Thread(target=self.run_client, args=(ip,port, ), daemon=True)
        client_thread.start()
        self.update_buttons()

    def run_server(self):
        gen = None
        try:
            self.append_message('[INFO] Initializing Server...', self.host_box)
            gen = start_server()
            host_ip, host_port = next(gen)
            self.append_message(f'[INFO] Server Established...', self.host_box)
            self.append_message(f'[INFO] IP : {host_ip}', self.host_box)
            self.append_message(f'[INFO] PORT : {host_port}', self.host_box)
            self.append_message('>Waiting for connection...', self.host_box)
            conn, priv, peer_pub, addr, server_socket = next(gen)
            self.conn = conn
            self.server_socket = server_socket
            self.private_key = priv
            self.peer_public_key = serialization.load_pem_public_key(peer_pub)
            self.append_message(f'[SECURE] Connection Established with: {addr}', self.host_box)
            self.connection = True

            #receive aes key
            rev_aes = recv_msg(self.conn)
            if not rev_aes:
                raise ConnectionError("Failed to receive AES key")
            self.aes_key = decrypt_rsa(self.private_key, rev_aes)
            threading.Thread(target=self.receive_message, daemon=True).start()
            self.append_message("[SYSTEM] Chat Enabled", self.chat_box)
        except Exception as e:
            self.append_message(f'[ERROR]: {e}', self.host_box)
            self.terminate()
        except StopIteration:
            self.append_message('[ERROR] Server generator ended unexpectedly', self.host_box)
            self.terminate()

    def run_client(self, hostip, port):
        self.append_message('>Making a Secure Channel...', self.host_box)
        try:
            conn, priv, server_pub = start_client(hostip, port)
            self.conn = conn
            self.private_key = priv
            self.peer_public_key = serialization.load_pem_public_key(server_pub)
            self.append_message(f'[SECURE] Connection Established with: {hostip}', self.host_box)
            self.connection = True

            #generate and send aes
            self.aes_key = generate_aes_key()
            send_aes = encrypt_rsa(self.peer_public_key, self.aes_key)
            send_msg(self.conn, send_aes)
            threading.Thread(target=self.receive_message, daemon=True).start()
            self.append_message("[SYSTEM] Chat Enabled", self.chat_box)
        except Exception as e:
            self.append_message(f'[ERROR]: {e}', self.host_box)
            self.terminate()

    def send_message(self):
        msg = self.message_entry.get().strip()
        if not msg:
            return     
        if not self.connection:
            messagebox.showerror("Error","Connection is not established")
            return  
        try:
            enc = encrypt_aes(self.aes_key, msg)
            send_msg(self.conn, enc)
            self.append_message(f'You: {msg}', self.chat_box)
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            self.append_message(f'[ERROR]: {e}', self.host_box)
            self.terminate()

    def receive_message(self):
        while self.connection:
            try:
                data = recv_msg(self.conn)
                if not data:
                    break
                msg = decrypt_aes(self.aes_key, data)
                self.append_message(f'Peer: {msg}', self.chat_box)
            except Exception as e:
                self.append_message(f'[ERROR]: {e}', self.host_box)
                break
        if self.connection:
            self.append_message('[INFO] Peer disconnected', self.host_box)
        self.terminate()

    def terminate(self):
        line = ">----------------------------------------"
        was_connected = self.connection
        self.connection = False
        self.mode = None
        if self.conn:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
            except:
                pass
            self.conn = None
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        self.aes_key = None
        self.private_key = None
        self.peer_public_key = None
        self.append_message('[INFO] Connection Terminated', self.host_box)
        self.append_message(line, self.host_box)
        if was_connected and not self.chat_disabled_shown:
            self.append_message('[SYSTEM] Chat Disabled', self.chat_box)
            self.chat_disabled_shown = True
        self.update_buttons()

    def on_close(self):
        self.terminate()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = chat_app(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()