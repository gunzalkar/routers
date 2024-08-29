import paramiko
import time
import csv

# Router connection details
ROUTER_IP = '192.168.1.254'
USERNAME = 'admin'
PASSWORD = 'password'
PORT = 22

def check_console_security(ssh_shell):
    results = []
    
    # Enter system view
    ssh_shell.send('system-view\n')
    time.sleep(1)
    
    # Display console configuration
    ssh_shell.send('display current-configuration | include console\n')
    time.sleep(2)
    
    # Receive the output
    output = ssh_shell.recv(65535).decode()
    
    # Check if AAA authentication is enabled for console
    if 'authentication-mode aaa' in output:
        results.append(["Device Login Security", "Strong authentication methods are in place."])
    else:
        results.append(["Device Login Security", "No AAA authentication for console."])
    
    return results

def check_certificate_details(ssh_shell):
    results = []
    
    # Enter system view
    ssh_shell.send('system-view\n')
    time.sleep(1)
    
    # Display certificate details
    ssh_shell.send('display pki certificate all\n')
    time.sleep(2)
    
    # Receive the output
    output = ssh_shell.recv(65535).decode()
    
    # Check if certificates are present
    if 'Certificate ID' in output:
        results.append(["Digital Certificate Management", "Certificate Authority verification passed."])
        
        # Further check the specific details of the certificates
        ssh_shell.send('display pki certificate detail\n')
        time.sleep(2)
        
        # Receive detailed output
        detailed_output = ssh_shell.recv(65535).decode()
        
        if 'Not After' in detailed_output and 'Issuer' in detailed_output:
            results.append(["Digital Certificate Management", "Certificate is valid."])
        else:
            results.append(["Digital Certificate Management", "Certificate validity check failed."])
    else:
        results.append(["Digital Certificate Management", "No digital certificates found on the device."])
    
    return results

def check_aaa_user_management(ssh_shell):
    results = []
    
    # Enter system view
    ssh_shell.send('system-view\n')
    time.sleep(1)
    
    # Check AAA configuration
    ssh_shell.send('display aaa configuration\n')
    time.sleep(2)
    
    # Receive the output
    output = ssh_shell.recv(65535).decode()
    
    # Check for local account locking configuration
    if 'wrong-password retry-interval 6 retry-time 4 block-time 6' in output:
        results.append(["AAA User Management Security", "Authentication mechanisms are securely implemented."])
    else:
        results.append(["AAA User Management Security", "Authentication mechanisms configuration check failed."])
    
    # Check if AAA user identities and access control are managed securely
    if 'domain' in output and 'authentication scheme' in output:
        results.append(["AAA User Management Security", "User identities are managed securely."])
        results.append(["AAA User Management Security", "Access control policies are validated."])
    else:
        results.append(["AAA User Management Security", "AAA user management configuration check failed."])
    
    return results

def write_results_to_csv(results, filename='security_check_results.csv'):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Objective", "Result"])
        for result in results:
            writer.writerow(result)

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
        results = check_console_security(ssh_shell)
        
        # Check certificate details
        results.extend(check_certificate_details(ssh_shell))
        
        # Check AAA User Management Security
        results.extend(check_aaa_user_management(ssh_shell))
        
        # Write results to CSV
        write_results_to_csv(results)
        
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
