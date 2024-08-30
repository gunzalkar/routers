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
        'objective': 'Device Login Security: Strong Authentication Methods',
        'commands': [
            'system-view',
            'aaa',
            'user-password complexity-check',
            'quit',
            'display current-configuration | include irreversible-cipher'
            'quit'
        ],
        'expected_output': ['super password irreversible-cipher']
    },

    {
        'objective': 'Device Login Security:Password Policies',
        'commands': [
            'system-view',
            'display current-configuration | include wrong-password'
            'quit'
        ],
        'expected_output': ['wrong-password retry-interval 6 retry-time 4 block-time 6']
    },

    {
    'objective': 'Device Login Security:Multi-factor Authentication (MFA)',
    'commands': [
        'system-view',
        'display current-configuration | include wrong-password',
        'quit'

    ],
    'expected_output': ['wrong-password retry-interval 6 retry-time 4 block-time 6']
    },

    {
    'objective': 'AAA User Management Security:Authentication Mechanisms',
    'commands': [
        'system-view',
        'display current-configuration | include encryption',
        'display local-user'

    ],
    'expected_output': ['encryption-algorithm aes-256', ' super                          A      TM        15']
    },
    {
    'objective': 'SNMP Device Management Security',
    'commands': [
        'system-view',
        'display acl 2001',
        'quit'

    ],
    'expected_output': ['rule 10 deny source 10.183.20.123 0', 'rule 15 permit source 10.139.90.111 0' ]
    }

]

def ssh_connect(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=PORT, username=username, password=password)
    return client

def run_command(shell, command):
    shell.send(command + '\n')
    time.sleep(1)  # Wait for the command to execute
    output = shell.recv(65535).decode('utf-8')
    return output

def validate_output(output, expected):
    for keyword in expected:
        if keyword not in output:
            return 'Fail'
    return 'Pass'

def execute_check(shell, check):
    if 'commands' in check:
        # Execute each command in the list
        output = ''
        for command in check['commands']:
            output += run_command(shell, command)
    else:
        # Single command case
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
