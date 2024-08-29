import paramiko
import csv
import time

# Configuration
ROUTER_IP = '192.168.1.254'
USERNAME = 'admin'
PASSWORD = 'password'
COMPLIANCE_REPORT = 'compliance_report.csv'

# Compliance objectives and their corresponding commands
OBJECTIVES = {
    'Digital Certificate Management': [
        ('Certificate Authority verification passed.', 'display pki certificate'),
        ('OCSP check failed.', 'display pki ocsp'),
        ('Certificate is valid.', 'display pki certificate')
    ],
    'Device Login Security': [
        ('Strong authentication methods are in place.', 'display aaa local-user'),
        ('Password policies are enforced.', 'display aaa local-user'),
        ('Multi-factor authentication is enabled.', 'display aaa local-user')
    ],
    'AAA User Management Security': [
        ('Authentication mechanisms are securely implemented.', 'display aaa'),
        ('User identities are managed securely.', 'display aaa local-user'),
        ('Access control policies are validated.', 'display aaa')
    ],
    'SNMP Device Management Security': [
        ('ACL 2001 is correctly configured.', 'display acl 2001'),
        ('SNMP ACL is configured correctly.', 'display snmp-agent acl'),
        ('MIB view iso-view is configured.', 'display snmp-agent mib-view iso-view'),
        ('SNMPv3 group v3group is configured correctly.', 'display snmp-agent v3group v3group'),
        ('SNMPv3 user v3user is configured correctly.', 'display snmp-agent v3user v3user')
    ],
    'Service Plane Access Prohibition of Insecure Management Protocols': [
        ('Service plane access prohibition is correctly configured.', 'display cpu-defend policy 1')
    ]
}

def connect_to_router():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ROUTER_IP, username=USERNAME, password=PASSWORD)
    return client

def execute_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode()

def enter_system_view(client):
    # Send the command to enter system view
    execute_command(client, 'system-view')
    # Ensure the command is executed
    time.sleep(1)

def generate_report():
    with open(COMPLIANCE_REPORT, 'w', newline='') as csvfile:
        fieldnames = ['Objective', 'Result']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        client = connect_to_router()
        
        enter_system_view(client)

        for objective, commands in OBJECTIVES.items():
            for expected_result, command in commands:
                # Execute command in system-view context
                output = execute_command(client, command)
                if expected_result in output:
                    result = f'{expected_result}'
                else:
                    result = 'Failed'
                writer.writerow({'Objective': objective, 'Result': result})
        
        client.close()

if __name__ == '__main__':
    generate_report()
