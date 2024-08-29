import paramiko
import csv
import time

# Router credentials and SSH setup
ROUTER_IP = '192.168.1.254'
USERNAME = 'admin'
PASSWORD = 'password'
PORT = 22

# Validation checks
CHECKS = [
    {
        'objective': 'Digital Certificate Management',
        'command': 'display pki certificates',
        'expected_output': ['Certificate Authority', 'Revocation Status', 'Expiry Date']
    },
    {
        'objective': 'Device Login Security',
        'command': 'display aaa user',
        'expected_output': ['Authentication Methods', 'Password Policies', 'MFA']
    },
    {
        'objective': 'AAA User Management Security',
        'command': 'display aaa configuration',
        'expected_output': ['Account Locking', 'Authentication Retry Interval']
    },
    {
        'objective': 'SNMP Device Management Security',
        'command': 'display snmp-agent',
        'expected_output': ['ACL Configuration', 'SNMPv3 Settings']
    },
    {
        'objective': 'Service Plane Access Prohibition of Insecure Management Protocols',
        'command': 'display cpu-defend policy 1',
        'expected_output': ['Telnet', 'SSH', 'HTTP', 'SNMP', 'FTP', 'ICMP']
    }
]

def ssh_connect(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=PORT, username=username, password=password)
    return client

def run_command(shell, command):
    shell.send(command + '\n')
    time.sleep(2)  # Wait for the command to execute
    output = shell.recv(65535).decode('utf-8')
    return output

def validate_output(output, expected):
    for keyword in expected:
        if keyword not in output:
            return 'Fail'
    return 'Pass'

def execute_check(shell, check):
    # Enter system-view mode
    run_command(shell, 'system-view')
    # Run the validation command
    output = run_command(shell, check['command'])
    return validate_output(output, check['expected_output'])

def main():
    client = ssh_connect(ROUTER_IP, USERNAME, PASSWORD)
    shell = client.invoke_shell()
    
    # Optional: send a dummy command to ensure the shell is ready
    shell.send('\n')
    time.sleep(2)
    
    results = []
    for check in CHECKS:
        result = execute_check(shell, check)
        results.append({
            'Objective': check['objective'],
            'Result': result
        })
    
    client.close()

    # Write results to CSV
    with open('validation_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['Objective', 'Result']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)

if __name__ == '__main__':
    main()
