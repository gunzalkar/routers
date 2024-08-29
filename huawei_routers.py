import paramiko
import time

# Router connection details
ROUTER_IP = '192.168.1.254'
USERNAME = 'admin'
PASSWORD = 'password'
PORT = 22

def check_console_security(ssh_shell):
    # Send commands to enter system view and check console settings
    ssh_shell.send('system-view\n')
    time.sleep(1)
    ssh_shell.send('display current-configuration | include console\n')
    time.sleep(2)
    
    # Receive the output
    output = ssh_shell.recv(65535).decode()
    
    # Check if AAA authentication is enabled for console
    if 'authentication-mode aaa' in output:
        print("Console port is configured with AAA authentication.")
    else:
        print("Console port is not configured with AAA authentication.")

def check_certificate_management(ssh_shell):
    # Send commands to enter system view and check certificate settings
    ssh_shell.send('system-view\n')
    time.sleep(1)
    ssh_shell.send('display pki certificate all\n')
    time.sleep(2)
    
    # Receive the output
    output = ssh_shell.recv(65535).decode()
    
    # Check if certificates are present and valid
    if 'Certificate ID' in output:
        print("Digital certificates are present on the device.")
        # You can add more specific checks here based on your needs
        print(output)
    else:
        print("No digital certificates found on the device.")

def check_certificate_details(ssh_shell):
    # Send command to display certificate details
    ssh_shell.send('display pki certificate detail\n')
    time.sleep(2)
    
    # Receive the output
    output = ssh_shell.recv(65535).decode()
    
    # Check for expiry and issuer
    if 'Not After' in output and 'Issuer' in output:
        print("Certificate details found:")
        print(output)
    else:
        print("Failed to retrieve certificate details.")

def main():
    # Create SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connect to the router
        ssh_client.connect(ROUTER_IP, port=PORT, username=USERNAME, password=PASSWORD)
        
        # Open a shell session
        ssh_shell = ssh_client.invoke_shell()
        
        # Check console security
        check_console_security(ssh_shell)
        
        # Check certificate management
        check_certificate_management(ssh_shell)
        
        # Check certificate details
        check_certificate_details(ssh_shell)
        
        # Close SSH connection
        ssh_client.close()
        
    except paramiko.AuthenticationException:
        print("Authentication failed, please check your credentials.")
    except paramiko.SSHException as e:
        print(f"Failed to connect to the router: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()
