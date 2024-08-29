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
        'objective': 'Management Plane MPAC Configuration',
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
    },
    {
        'objective': 'Forwarding Plane ACL',
        'commands': [
            'system-view',
            'acl 2001',
            'rule permit source 192.168.32.1 0'
        ],
        'expected_output': ['ACL 2001', 'rule permit source 192.168.32.1 0']
    },
    {
        'objective': 'Forwarding Plane Traffic Suppression and Storm Control',
        'commands': [
            'system-view',
            'interface gigabitethernet 1/0/1',
            'broadcast-suppression 30',
            'multicast-suppression 30',
            'unicast-suppression 30',
            'quit'
        ],
        'expected_output': ['broadcast-suppression 30', 'multicast-suppression 30', 'unicast-suppression 30']
    },
    {
        'objective': 'Forwarding Plane Trusted Path-based Forwarding',
        'commands': [
            'system-view',
            'urpf strict'
        ],
        'expected_output': ['URPF strict mode']
    },
    {
        'objective': 'Management Plane Information Center Security',
        'commands': [
            'system-view',
            'ssl policy Example@123',
            'info-center loghost 192.168.2.2 transport tcp ssl-policy Example@123'
        ],
        'expected_output': ['info-center loghost 192.168.2.2', 'transport tcp ssl-policy Example@123']
    },
    {
        'objective': 'Management Plane HWTACACS User Management Security',
        'commands': [
            'system-view',
            'hwtacacs-server template test1',
            'hwtacacs-server shared-key cipher YsHsjx_202206'
        ],
        'expected_output': ['hwtacacs-server shared-key cipher YsHsjx_202206']
    },
    {
        'objective': 'ARP Security',
        'commands': [
            'system-view',
            'arp anti-attack entry-check fixed-mac enable',
            'interface gigabitethernet 1/0/1',
            'arp anti-attack check user-bind enable',
            'arp anti-attack gateway-collision enable'
        ],
        'expected_output': ['arp anti-attack entry-check fixed-mac enable', 'arp anti-attack check user-bind enable', 'arp anti-attack gateway-collision enable']
    },
    {
        'objective': 'DHCP Security',
        'commands': [
            'system-view',
            'acl name dhcp-valid',
            'rule permit udp source-port eq bootps',
            'quit',
            'acl name dhcp-invalid',
            'rule deny udp source-port eq bootps',
            'quit'
        ],
        'expected_output': ['acl name dhcp-valid', 'rule permit udp source-port eq bootps', 'acl name dhcp-invalid', 'rule deny udp source-port eq bootps']
    },
    {
        'objective': 'Routing Protocol Security',
        'commands': [
            'system-view',
            'cpu-defend policy 1',
            'car packet-type bgp cir 64',
            'cpu-defend-policy 1 global',
            'cpu-defend-policy 1',
            'bgp max-as-path 200'
        ],
        'expected_output': ['cpu-defend policy 1', 'car packet-type bgp cir 64', 'bgp max-as-path 200']
    },
    {
        'objective': 'MPLS Security',
        'commands': [
            'system-view',
            'keychain kc1 mode absolute',
            'key-id 1',
            'algorithm sha-256',
            'key-string YsHsjx_202206',
            'quit',
            'mpls lsr-id 2.2.2.2',
            'mpls ldp',
            'authentication key-chain kc1'
        ],
        'expected_output': ['keychain kc1 mode absolute', 'algorithm sha-256', 'mpls lsr-id 2.2.2.2', 'authentication key-chain kc1']
    },
    {
        'objective': 'Multicast Security',
        'commands': [
            'system-view',
            'acl number 2000',
            'rule permit source 225.0.0.0 0.0.0.255',
            'quit',
            'igmp-snooping enable',
            'vlan 2',
            'igmp-snooping enable',
            'igmp-snooping group-policy 2000'
        ],
        'expected_output': ['acl number 2000', 'rule permit source 225.0.0.0 0.0.0.255', 'igmp-snooping group-policy 2000']
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
