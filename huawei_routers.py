import paramiko
import time
# Router connection details
ROUTER_IP = '192.168.1.254'
USERNAME = 'admin'
PASSWORD = 'password'
PORT = 22

def check_console_security():
    # Create SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connect to the router
        ssh_client.connect(ROUTER_IP, port=PORT, username=USERNAME, password=PASSWORD)
        
        # Open a shell session
        ssh_shell = ssh_client.invoke_shell()
        
        # Send commands to enter system view and check console settings
        ssh_shell.send('system-view\n')
        ssh_shell.send('display current-configuration | include console\n')
        
        # Allow some time for the command to execute
        time.sleep(2)
        
        # Receive the output
        output = ssh_shell.recv(65535).decode()
        
        # Check if AAA authentication is enabled for console
        if 'authentication-mode aaa' in output:
            print("Console port is configured with AAA authentication.")
        else:
            print("Console port is not configured with AAA authentication.")
        
        # Close SSH connection
        ssh_client.close()
        
    except paramiko.AuthenticationException:
        print("Authentication failed, please check your credentials.")
    except paramiko.SSHException as e:
        print(f"Failed to connect to the router: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    check_console_security()
