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
    },
    {
        'objective': 'Management Pane MPAC Configuration',
        'commands': [
            'system-view',
            'service-security policy ipv4 test',
            'rule 10 deny protocol ip source-ip 10.10.1.1 0',
            'quit',
            'service-security global-binding ipv4 test'
        ],
        'expected_output': ['service-security policy', 'deny protocol ip', 'global-binding ipv4 test']
    },
    {
        'objective': 'Local Attack Defense',
        'commands': [
            'system-view',
            'cpu-defend',
            'attack-source-tracing',
            'port-attack-defend'
        ],
        'expected_output': ['CPU attack defense', 'Attack source tracing', 'Port attack defense']
    },
    {
        'objective': 'Attack Defense Through Service and Management Isolation',
        'commands': [
            'system-view',
            'management-port isolate enable',
            'management-plane isolate enable'
        ],
        'expected_output': ['management-port isolate enable', 'management-plane isolate enable']
    },
    {
        'objective': 'Attack Defense',
        'commands': [
            'system-view',
            'attack-defense'
        ],
        'expected_output': ['attack defense', 'malformed packet', 'flood attack', 'IGMP null packet attack']
    },
    {
        'objective': 'Wireless User Access Security',
        'commands': [
            'system-view',
            'wlan',
            'security-profile name p1',
            'security wpa-wpa2 psk pass-phrase YsHsjx_202206 aes-tkip',
            'security wpa-wpa2 dot1x aes-tkip'
        ],
        'expected_output': ['WPA-WPA2-PSK', 'WPA-WPA2-802.1X', 'TKIP-AES']
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
    if isinstance(check['commands'], list):
        # Execute each command in the list
        for command in check['commands']:
            output = run_command(shell, command)
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
