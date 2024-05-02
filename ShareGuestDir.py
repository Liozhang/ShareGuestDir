# python 3.9
import os
import re
import subprocess
import ctypes
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
from tkinter.simpledialog import askstring


class ShareUtils:
    def __init__(self):
        self.guest_account = "Guest" if not os.environ.get('GUEST_ACCOUNT') else os.environ.get('GUEST_ACCOUNT')
        self.guest_password = os.environ.get('GUEST_PASSWORD')
        pass
    
    def get_ip_address(self):
        '''Get the IPv4 address of the local machine'''
        try:
            ipconfig = subprocess.Popen(['ipconfig'], stdout=subprocess.PIPE)
            result = subprocess.check_output(('findstr', '/i', 'IPv4'), stdin=ipconfig.stdout, text=True)
            ipconfig.wait()
            # Use regular expression to extract IPv4 addresses starting with 192
            ipv4_address = re.findall(r'192\.\d{1,3}\.\d{1,3}\.\d{1,3}', result)
            ipv4_address = ipv4_address[0] if ipv4_address and isinstance(ipv4_address, list) else ipv4_address
            if not ipv4_address:
                return False, "未获取到IP地址\n"
            return True, ipv4_address
        except subprocess.CalledProcessError:
            return False, "获取IP地址失败\n"
    
    
    def get_mac_address(self, ip_address):
        '''Get the MAC address of the specified IP address'''
        try:
            result = subprocess.run(['arp', '-a', ip_address], capture_output=True, text=True)
            mac_address = re.findall(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', result.stdout)
            if not mac_address:
                return False, "Failed to get MAC address\n"
            return True, mac_address
        except subprocess.CalledProcessError:
            return False, "Failed to get MAC address\n"
    
    
    def if_is_admin(self):
        '''Check if the program is running with administrator privileges'''
        try:
            return os.getuid() == 0
        except AttributeError:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        
     
    def get_admin(self):
        '''Get administrator privileges'''
        if not self.if_is_admin():
            return False, "Please run the program as an administrator!\n"
        return True, "Administrator privileges obtained\n"
    
    
    def enable_guest_account(self):
        '''Enable the guest account'''
        try:
            # Check if guest password is set, if not create a input window
            if not self.guest_password:
                self.guest_password = askstring("Guest Password", "Please enter the guest password:")
                if not self.guest_password:
                    return False, "No guest password entered\n"
            # Enable the guest account
            subprocess.run(["net", "user", self.guest_account, "/active:yes"], check=True)
            # Set the guest account password
            subprocess.run(["net", "user", self.guest_account, "/passwordreq:yes", "/passwordchg:yes", self.guest_password], check=True)
            return True, "Guest account enabled\n"
        except subprocess.CalledProcessError:
            return False, "Failed to enable guest account\n"
        
    
    def disable_guest_account(self):
        '''Disable the guest account'''
        try:
            subprocess.run(["net", "user", self.guest_account, "/active:no"], check=True)
            return True, "Guest account disabled\n"
        except subprocess.CalledProcessError:
            return False, "Failed to disable guest account\n"
        
    
    def check_guest_account(self):
        '''Check if the Guest account is enabled'''
        try:
            result = subprocess.run(["net", "user", self.guest_account], capture_output=True, text=True)
            if self.guest_account in result.stdout:
                return True, "Guest account is enabled\n"
            else:
                return False, "Guest account is not enabled\n"
        except subprocess.CalledProcessError:
            return False, "Failed to get Guest account status\n"
        
    
    def enable_network_discovery(self):
        '''Enable network discovery'''
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "set", "rule", "group=\"Network Discovery\"", "new", "enable=yes"], check=True)
            return True, "Network discovery enabled\n"
        except subprocess.CalledProcessError:
            # raise
            return False, "Failed to enable network discovery\n"
        
    
    def disable_network_discovery(self):
        '''Disable network discovery'''
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "set", "rule", "group=\"Network Discovery\"", "new", "enable=no"], check=True)
            return True, "Network discovery disabled\n"
        except subprocess.CalledProcessError:
            # raise
            return False, "Failed to disable network discovery\n"
        
    
    def check_network_discovery(self):
        '''Check if network discovery is enabled'''
        try:
            result = subprocess.run(["sc", 'query', 'fdrespub'], capture_output=True, text=True)
            if 'RUNNING' in result.stdout:
                return True, "Network discovery is enabled\n"
            else:
                return False, "Network discovery is disabled\n"
        except subprocess.CalledProcessError:
            return False, "Failed to get network discovery status\n"
        
    
    def share_folder(self, folder_path, share_name):
        '''Share a folder'''
        try:
            subprocess.run(["icacls", folder_path, "/grant", f"{self.guest_account}:(R)", "/T"], check=True)
            subprocess.run(["icacls", folder_path, "/grant", "Everyone:(OI)(CI)(RX)", "/T"], check=True)  # Set permissions for Everyone group
            subprocess.run(["icacls", folder_path, "/inheritance:e", "/T"], check=True)  # Inherit permissions from parent folder
            subprocess.run(["net", "share", share_name+"="+folder_path, "/GRANT:Everyone,READ"], check=True)
            return True, f"Folder {folder_path} successfully shared as {share_name}"
        except subprocess.CalledProcessError:
            return False, f"Failed to share folder {folder_path}"
        
    
    def unshare_folder(self, share_name):
        '''Unshare a folder'''
        try:
            subprocess.run(["net", "share", share_name, "/DELETE"], check=True)
            return True, f"Folder {share_name} has been unshared\n"
        except subprocess.CalledProcessError:
            return False, f"Failed to unshare folder {share_name}\n"
        
    
    def check_folder_shared(self, share_name):
        '''Check if a folder is shared'''
        try:
            result = subprocess.run(["net", "share", share_name], capture_output=True, text=True)
            if "does not exist" in result.stdout:
                return False, f"Folder {share_name} is not shared\n"
            else:
                return True, f"Folder {share_name} is shared\n"
        except subprocess.CalledProcessError:
            return False, f"Failed to check the sharing status of folder {share_name}\n"
        
    
    def enable_smb_protocol(self):
        '''Enable WIN10 SMB v2/v3 protocol'''
        try:
            subprocess.run(["powershell", "-Command", "Set-SmbServerConfiguration -EnableSMB2Protocol $true -Confirm:$false"], check=True)
            # Check if it is enabled
            result = subprocess.run(["powershell", "-Command", "Get-SmbServerConfiguration | Select EnableSMB2Protocol"], capture_output=True, text=True)
            if "True" in result.stdout:
                return True, "SMB v2/v3 protocol enabled\n"
            else:
                return False, "Failed to enable SMB v2/v3 protocol\n"
        except subprocess.CalledProcessError:
            return False, "Failed to enable SMB v2/v3 protocol\n"
        
    
    def close_smb_protocol(self):
        '''Disable SMB v2/v3 protocol'''
        try:
            subprocess.run(["powershell", "-Command", "Set-SmbServerConfiguration -EnableSMB2Protocol $false"], check=True)
            # Check if it is disabled
            result = subprocess.run(["powershell", "-Command", "Get-SmbServerConfiguration | Select EnableSMB2Protocol"], capture_output=True, text=True)
            if "False" in result.stdout:
                return True, "SMB v2/v3 protocol has been disabled\n"
            else:
                return False, "Failed to disable SMB v2/v3 protocol\n"
        except subprocess.CalledProcessError:
            return False, "Failed to disable SMB v2/v3 protocol\n"
        
    
    def check_smb_protocol(self):
        '''Check if SMB v2/v3 protocol is enabled'''
        try:
            result = subprocess.run(["powershell", "-Command", "Get-SmbServerConfiguration | Select EnableSMB2Protocol"], capture_output=True, text=True)
            if "True" in result.stdout:
                return True, "SMB v2/v3 protocol is enabled\n"
            else:
                return False, "SMB v2/v3 protocol is not enabled\n"
        except subprocess.CalledProcessError:
            return False, "Failed to get SMB v2/v3 protocol status\n"
        
    
    def check_share_folder_accessible(self, share_folder):
        '''Check if the shared folder is accessible'''
        try:
            command = [
                "net", "use", f"\\\\{self.ip_address}\\{share_folder}", f'/user:{self.guest_account}', self.guest_password
            ]
            print(command)
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0 and "成功" in result.stdout:
                return True, "The shared folder is accessible\n"
            else:
                return False, "The shared folder is not accessible\n"
        except subprocess.CalledProcessError as e:
            return False, f"The shared folder is not accessible:\n{e}\n"
        
    
    def view_shared_folders(self):
        '''View currently shared folders'''
        try:
            result = subprocess.run(["powershell", "-Command", "Get-SmbShare | ConvertTo-Csv -NoTypeInformation -Delimiter `t"], capture_output=True, text=True)
            output = []
            for line in result.stdout.split("\n"):
                if not '$' in line and not 'Print' in line and ':' in line:
                    line = line.split('\t')[16:18]
                    line = f"> Share Name: {line[0]}\n> Local Path: {line[1]}"
                    output.append(line)
            output = "\n".join(output) + "\n"
            return True, output
        except subprocess.CalledProcessError:
            return False, "Failed to view shared folders\n"
        
        
    def get_folder_name(self, folder_path):
        '''Get the shared name of a folder'''
        try:
            result = subprocess.run(["powershell", "-Command", "Get-SmbShare | ConvertTo-Csv -NoTypeInformation -Delimiter `t"], capture_output=True, text=True)
            lines = result.stdout.splitlines()
            shares = []
            for line in lines:
                if not folder_path in line:
                    continue
                share_name = line.split('\t')[16]
                shares.append(share_name)
            if not shares:
                return False, "Shared folder not found\n"
            else:
                return True, shares
        except subprocess.CalledProcessError:
            return False, "Failed to get shared folder name\n"
            

class ShareAppUI(ShareUtils):
    def __init__(self, root):
        super().__init__()
        self.root = root
        self.title = 'Folder Sharing Settings'
        self.folder_path = ''
        self.folder_name = ''
        self.ip_address = '192.168.x.x'
        self.admin_status = False
        self.smb_status = False
        self.network_discovery_status = False
        self.guest_account_status = False
        self.shared_folders_status = False

        # Set button styles
        self.main_labelframe_style = "dark"
        self.sub_labelframe_style = "default"
        self.sub_labelframe_on = "success"
        self.sub_labelframe_off = "danger"
        self.open_button_style = "primary-link"
        self.close_button_style = "danger-link"
        
        
    def create_gui(self):
        '''Create the GUI interface'''
        self.root.title(self.title)
        
        # Create a Frame that will contain all the components
        self.frame = tk.Frame(self.root)
        self.frame.pack(expand=True, fill='both')
        # Place the Frame in the center of the window
        self.frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Create some styles
        success_style = ttk.Style()
        success_style.configure('success.TLabel', foreground='green')
        danger_style = ttk.Style()
        danger_style.configure('danger.TLabel', foreground='red')
        warning_style = ttk.Style()
        warning_style.configure('warning.TLabel', foreground='orange')
        open_button_style = ttk.Style()
        open_button_style.configure('primary-link.TButton', foreground='dodgerblue', borderwidth=0)
        close_button_style = ttk.Style()
        close_button_style.configure('danger-link.TButton', foreground='red')
        folder_button_style = ttk.Style()
        folder_button_style.configure('folder.TButton', foreground='black')

        
        # Set Guest Password
        self.password_frame = ttk.LabelFrame(self.frame, text="Guest Password")
        self.password_frame.grid(row=0, column=0, columnspan=3, padx=5, pady=5)
        
        self.password_input = ttk.Entry(self.password_frame, show="*", width=11)
        self.password_input.grid(row=0, column=0)
        
        self.password_button = ttk.Button(self.password_frame, text="Set Password", style="folder.TButton", command=self.set_guest_password)
        self.password_button.grid(row=0, column=1)
        
        # View Shared Folders
        self.view_frame = ttk.LabelFrame(self.frame, text="View Shared Folders")
        self.view_frame.grid(row=1, column=0, columnspan=3)

        self.view_button = ttk.Button(self.view_frame, text="View", style="folder.TButton", command=self.view_shared)
        self.view_button.grid(row=0, column=0)

        self.check_status_button = ttk.Button(self.view_frame, text="Check Status", style="folder.TButton", command=self.check_all_status)
        self.check_status_button.grid(row=0, column=1)
        
        
        # Set the layout to a 5-row, 4-column grid layout
        self.setting_frame = ttk.LabelFrame(self.frame, text=self.ip_address)
        self.setting_frame.grid(row=2, column=0, columnspan=3, rowspan=3, padx=5, pady=5)
        
        # SMB Protocol Status
        self.smb_frame = ttk.LabelFrame(self.setting_frame, text="SMB Protocol Status")
        self.smb_frame.grid(row=0, column=0, columnspan=3, padx=5, pady=5)

        self.smb_status_label = ttk.Label(self.smb_frame, text="ON" if self.smb_status else "OFF", style="danger.TLabel" if not self.smb_status else "success.TLabel")
        self.smb_status_label.grid(row=0, column=0, padx=5)

        self.smb_open = ttk.Button(self.smb_frame, text="Enable", style="primary-link.TButton", command=self.enable_smb)
        self.smb_open.grid(row=0, column=1)

        self.smb_close = ttk.Button(self.smb_frame, text="Disable", style="danger-link.TButton", command=self.disable_smb)
        self.smb_close.grid(row=0, column=2)
        
        # Network Discovery Status
        self.network_frame = ttk.LabelFrame(self.setting_frame, text="Network Discovery Status")
        self.network_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        
        self.network_status_label = ttk.Label(self.network_frame, text="ON" if self.network_discovery_status else "OFF", style="danger.TLabel" if not self.network_discovery_status else "success.TLabel")
        self.network_status_label.grid(row=0, column=0, padx=5)

        self.network_open = ttk.Button(self.network_frame, text="Enable", style="primary-link.TButton", command=self.enable_network)
        self.network_open.grid(row=0, column=1)

        self.network_close = ttk.Button(self.network_frame, text="Disable", style="danger-link.TButton", command=self.disable_network)
        self.network_close.grid(row=0, column=2)
        
        # Guest Account Status
        self.guest_frame = ttk.LabelFrame(self.setting_frame, text="Guest Account Status")
        self.guest_frame.grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        
        self.guest_status_label = ttk.Label(self.guest_frame, text="ON" if self.guest_account_status else "OFF", style="danger.TLabel" if not self.guest_account_status else "success.TLabel")
        self.guest_status_label.grid(row=0, column=0, padx=5)

        self.guest_open = ttk.Button(self.guest_frame, text="Enable", style="primary-link.TButton", command=self.enable_guest)
        self.guest_open.grid(row=0, column=1)

        self.guest_close = ttk.Button(self.guest_frame, text="Disable", style="danger-link.TButton", command=self.disable_guest)
        self.guest_close.grid(row=0, column=2)
        
        
        # Shared Folders
        self.share_frame = ttk.LabelFrame(self.frame, text="Shared Folders")
        self.share_frame.grid(row=5, column=0, columnspan=4, padx=5, pady=5)

        self.share_folder_label = ttk.Label(self.share_frame, text="No folder selected" if not self.folder_path else self.folder_path, style="warning.TLabel")
        self.share_folder_label.grid(row=0, column=0, columnspan=4)
        self.share_folder_label.update()
     
        self.select_button = ttk.Button(self.share_frame, text="Select Folder", style="folder.TButton", command=self.select_folder)
        self.select_button.grid(row=1, column=0)

        self.share_button = ttk.Button(self.share_frame, text="Share", style="folder.TButton", command=self.share)
        self.share_button.grid(row=1, column=1)

        self.unshare_button = ttk.Button(self.share_frame, text="Unshare", style="folder.TButton", command=self.unshare)
        self.unshare_button.grid(row=1, column=2)

        self.check_folder = ttk.Button(self.share_frame, text="Check Access", style="folder.TButton", command=self.check_accessible)
        self.check_folder.grid(row=1, column=3)
        
        
        # A Text component to display messages
        self.info_text = tk.Text(self.frame, height=15, width=50)
        self.info_text.grid(row=6, column=0, columnspan=3)
        
        # Add a scrollbar to the right of the message component
        self.scroll = tk.Scrollbar(self.frame, command=self.info_text.yview)
        self.scroll.grid(row=6, column=3, sticky='ns')
        self.info_text.config(yscrollcommand=self.scroll.set)
        self.info_text.insert(tk.END, "Program running...\nPlease start with a status check.\n")
        
        
    # Bind event to the button
    def select_folder(self):
        self.folder_path = filedialog.askdirectory()
        if self.folder_path:
            message = f"Selected folder: {self.folder_path}\n"
            self.share_folder_label.config(text=self.folder_path)
        else:
            message = "No folder selected\n"
            self.share_folder_label.config(text="No folder selected")
        self.show_mesg(message)
        
        
    def enable_smb(self):
        self.info_text.insert(tk.END, "Trying to enable SMB protocol\n")
        success, message = self.enable_smb_protocol()
        success, message = self.check_smb_protocol()
        if success:
            self.smb_status_label.config(text="ON", style="success.TLabel")
        else:
            self.smb_status_label.config(text="OFF", style="danger.TLabel")
        self.show_mesg(message)
        
    
    def disable_smb(self):
        self.info_text.insert(tk.END, "Trying to disable SMB protocol\n")
        success, message = self.close_smb_protocol()
        success, message = self.check_smb_protocol()
        if success:
            self.smb_status_label.config(text="ON", style="success.TLabel")
        else:
            self.smb_status_label.config(text="OFF", style="danger.TLabel")
        self.show_mesg(message)
        
        
    def set_guest_password(self):
        self.guest_password = self.password_input.get()
        if not self.guest_password:
            self.show_mesg("No password entered\n")
            return
        self.show_mesg("Guest password set\n")
        

    def enable_guest(self):
        self.info_text.insert(tk.END, "Trying to enable guest account\n")
        success, message = self.enable_guest_account()
        success, message = self.check_guest_account()
        if success:
            self.guest_status_label.config(text="ON", style="success.TLabel")
        else:
            self.guest_status_label.config(text="OFF", style="danger.TLabel")
        self.show_mesg(message)


    def disable_guest(self):
        self.info_text.insert(tk.END, "Trying to disable guest account\n")
        success, message = self.disable_guest_account()
        success, message = self.check_guest_account()
        if success:
            self.guest_status_label.config(text="ON", style="success.TLabel")
        else:
            self.guest_status_label.config(text="OFF", style="danger.TLabel")
        self.show_mesg(message)


    def enable_network(self):
        self.info_text.insert(tk.END, "Trying to enable network discovery\n")
        success, message = self.enable_network_discovery()
        success, message = self.check_network_discovery()
        if success:
            self.network_status_label.config(text="ON", style="success.TLabel")
        else:
            self.network_status_label.config(text="OFF", style="danger.TLabel")
        self.show_mesg(message)
        

    def disable_network(self):
        self.info_text.insert(tk.END, "Trying to disable network discovery\n")
        success, message = self.disable_network_discovery()
        success, message = self.check_network_discovery()
        if success:
            self.network_status_label.config(text="ON", style="success.TLabel")
        else:
            self.network_status_label.config(text="OFF", style="danger.TLabel")
        self.show_mesg(message)


    def share(self):
        if not self.folder_path:
            message = "Please select a folder first\n"
            self.show_mesg(message)
            return
        self.info_text.insert(tk.END, "Trying to share the folder\n")
        share_name = self.get_share_name()  # Get the share_name from the user

        success, message = self.share_folder(self.folder_path, share_name)
        success, message = self.check_folder_shared(share_name)
        if success:
            self.share_folder_label.config(text=f"{self.folder_path} [{self.folder_name}]", style="success.TLabel")
        else:
            self.share_folder_label.config(text=f"{self.folder_path} [{self.folder_name}]", style="danger.TLabel")
        self.show_mesg(message)


    def unshare(self):
        if not self.folder_path:
            message = "Please select a folder first\n"
            self.show_mesg(message)
            return
        self.info_text.insert(tk.END, "Trying to unshare the folder\n")
        share_name = self.get_share_name()
        self.folder_name = share_name
        success, message = self.unshare_folder(share_name)
        success, message = self.check_folder_shared(share_name)
        if success:
            self.share_folder_label.config(text=f"{self.folder_path} [{self.folder_name}]", style="warning.TLabel")
        else:
            self.share_folder_label.config(text=f"{self.folder_path} [{self.folder_name}]", style="danger.TLabel")
        self.show_mesg(message)


    def view_shared(self):
        self.info_text.insert(tk.END, "Trying to view shared folders\n")
        success, message = self.view_shared_folders()
        self.show_mesg(message)

    def get_share_name(self):
        share_name = askstring("Share Name", "Please enter the share name:")
        if not share_name:
            self.show_mesg("No share name entered\n")
            raise ValueError("No share name entered")
        self.folder_name = share_name
        return share_name
    
    
    def check_accessible(self):
        if not self.folder_path:
            message = "Please select a folder first\n"
            self.show_mesg(message)
            return
        self.info_text.insert(tk.END, "Trying to check if the folder is accessible\n")
        if not self.ip_address or 'x' in self.ip_address:
            self.show_mesg("Please perform a status check first\n")
            raise ValueError("Failed to obtain IP address")
        share_name = self.get_share_name()
        success, message = self.check_share_folder_accessible(share_name)
        if success:
            self.share_folder_label.config(text=f"{self.folder_path} [{self.folder_name}]\nAccessible", style="success.TLabel")
        else:
            self.share_folder_label.config(text=f"{self.folder_path} [{self.folder_name}]\nInaccessible", style="danger.TLabel")
        self.show_mesg(message)
    
    
    def check_all_status(self):
        '''Check all settings and trigger UI updates'''
        self.show_mesg("Checking all settings\n")
        
        self.show_mesg("  > Getting IP address\n")
        self.ip_status, self.ip_address = self.get_ip_address()
        self.setting_frame.config(text=self.ip_address)
        
        self.show_mesg("  > Checking permission status (admin or not)\n")
        self.admin_status, self.admin_info = self.get_admin()
        self.show_mesg(self.admin_info)
        
        self.show_mesg("  > Checking network discovery status\n")
        self.network_discovery_status, self.network_discovery_info = self.check_network_discovery()
        self.network_status_label.config(text="ON" if self.network_discovery_status else "OFF", style="success.TLabel" if self.network_discovery_status else "danger.TLabel")
        
        self.show_mesg("  > Checking SMB protocol status\n")
        self.smb_status, self.smb_info = self.check_smb_protocol()
        self.smb_status_label.config(text="ON" if self.smb_status else "OFF", style="success.TLabel" if self.smb_status else "danger.TLabel")
        
        self.show_mesg("  > Checking guest account status\n")
        self.guest_account_status, self.guest_account_info = self.check_guest_account()
        self.guest_status_label.config(text="ON" if self.guest_account_status else "OFF", style="success.TLabel" if self.guest_account_status else "danger.TLabel")
        
        self.show_mesg("  > Viewing all shared folders\n")
        self.shared_folders_status, self.shared_folders_info = self.view_shared_folders()
        self.show_mesg(self.shared_folders_info)
        
        self.show_mesg("Check completed\n")
        
        
    def show_mesg(self, message):
        '''Display message in the Text component'''
        self.info_text.insert(tk.END, message)
        self.info_text.see(tk.END)
        self.info_text.update()
    
    
# The Main Function
def main():
    root = tk.Tk()
    
    # Set the theme
    style = ttk.Style()
    style.theme_use()
    
    # Create the application
    app = ShareAppUI(root)
    
    # Check if running as administrator
    success, message = app.get_admin()
    if success:
        app.create_gui()
        app.root.geometry("400x600")  # Set initial window size
        app.root.mainloop()
    else:
        messagebox.showerror("Error", message)
        
    # BUILD A EXE in Windows 10 CMD with pyinstaller and same python version and same packages
    # pyinstaller --onefile ShareGuestDir.py -n ShareGuestDir2
    

if __name__ == '__main__':
    main()