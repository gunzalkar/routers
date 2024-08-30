import paramiko
import logging
import csv

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Configuration
router_ip = '192.168.1.1'
username = 'admin'
password = 'password'
ssh_port = 22

# SSH Client Setup
def ssh_connect(ip, user, pwd, port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=user, password=pwd)
    except Exception as e:
        print(f"Error connecting to {ip}: {e}")
        raise
    return client

def execute_command(client, command):
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode('utf-8')
        if stderr:
            error = stderr.read().decode('utf-8')
            if error:
                print(f"Error executing command '{command}': {error}")
        return output
    except Exception as e:
        print(f"Error executing command '{command}': {e}")
        raise

def check_privilege_levels(client):
    command = "show run | incl privilege"
    output = execute_command(client, command)
    return 'Compliant' if 'privilege 1' in output else 'Non-Compliant'

def check_vty_transport(client):
    command = "show run | sec vty"
    output = execute_command(client, command)
    return 'Compliant' if 'transport input ssh' in output else 'Non-Compliant'

def check_no_exec_aux(client):
    command = "show run | sec aux"
    output = execute_command(client, command)
    return 'Compliant' if 'no exec' in output else 'Non-Compliant'

# Main function
def main():
    client = ssh_connect(router_ip, username, password, ssh_port)
    
    # Policies
    policies = [
        {
            'Policy': 'Set privilege 1 for local users',
            'Description': 'All local users have privilege level 1 or more',
            'Command': 'show run | incl privilege',
            'Check': check_privilege_levels(client)
        },
        {
            'Policy': 'Set transport input ssh for line vty connections',
            'Description': 'SSH should be the only transport method for incoming VTY logins',
            'Command': 'show run | sec vty',
            'Check': check_vty_transport(client)
        },
        {
            'Policy': 'Set no exec for line aux 0',
            'Description': 'The EXEC process on the auxiliary port should be disabled',
            'Command': 'show run | sec aux',
            'Check': check_no_exec_aux(client)
        }
    ]

    # Output to CSV and Terminal
    with open('policy_compliance_report.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Policy', 'Description', 'Command', 'Check'])
        for policy in policies:
            writer.writerow([policy['Policy'], policy['Description'], policy['Command'], policy['Check']])
            print(f"Policy: {policy['Policy']}")
            print(f"Description: {policy['Description']}")
            print(f"Command: {policy['Command']}")
            print(f"Check: {policy['Check']}")
            print('-' * 80)

    client.close()

if __name__ == "__main__":
    main()
