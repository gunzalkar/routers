import paramiko
import csv

# Configuration
ROUTER_IP = '192.168.1.1'  # Replace with your router's IP address
USERNAME = 'your_ssh_username'  # Replace with your SSH username
PASSWORD = 'your_ssh_password'  # Replace with your SSH password
LOCAL_USERNAME = 'local_user'  # Replace with the local username you want to check

def check_privilege_level(client, local_username):
    stdin, stdout, stderr = client.exec_command('show run | incl privilege')
    output = stdout.read().decode()
    # Check if the local user has privilege level 1
    if f'username {local_username} privilege 1' in output:
        return 'Pass'
    else:
        return 'Fail'

def main():
    # SSH Client setup
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(ROUTER_IP, username=USERNAME, password=PASSWORD)

        result = check_privilege_level(client, LOCAL_USERNAME)
        
        # Write results to CSV
        with open('cisco_router_compliance_check.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Sr. no.', 'Category', 'Control Objective', 'Description', 'Remediation', 'Verification'])
            writer.writerow([
                '1',
                'Access Rules',
                'Set \'privilege 1\' for local users',
                'Default device configuration does not require strong user authentication potentially enabling unfettered access to an attacker that is able to reach the device. Creating a local account with privilege level 1 permissions only allows the local user to access the device with EXEC-level permissions and will be unable to modify the device without using the enable password. In addition, require the use of an encrypted password as well',
                'Set the local user to privilege level 1.\nhostname(config)#username <LOCAL_USERNAME> privilege 1',
                result
            ])
        print("Compliance check completed. Results written to 'cisco_router_compliance_check.csv'.")
        
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client.close()

if __name__ == '__main__':
    main()
