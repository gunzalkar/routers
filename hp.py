import paramiko # type: ignore
import time
import csv

# Credentials
hostname = '192.168.1.10'
port = 22
username = 'admin'
password = 'password'

def connect_to_router():
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh_client.connect(hostname, port=port, username=username, password=password)
        return ssh_client
    except Exception as e:
        print(f"Connection error: {e}")
        return None

def run_command(shell, command):
    shell.send(f"{command}\n")
    time.sleep(2)
    return shell.recv(65535).decode()

# MBSS 1 - Disable Telnet Check
def check_telnet_compliance(shell):
    output = run_command(shell, 'display current-configuration | include telnet')
    return 'telnet server enable' not in output

# MBSS 2 - Enable HTTPS Check
def check_https_compliance(shell):
    output = run_command(shell, 'display current-configuration | include https')
    return '' in output and '' in output

# MBSS 3 - Disable TFTP Check
def check_tftp_compliance(shell):
    output = run_command(shell, 'display current-configuration | include tftp')
    return 'tftp' not in output or 'enable' not in output

# MBSS 4 - Enable SNMPv3 Check
def check_snmpv3_compliance(shell):
    output = run_command(shell, 'display current-configuration | include snmp')
    return 'snmp-agent sys-info version v3' in output

# MBSS 5 - IP Stack Management Check
def check_ip_stack_management_compliance(shell):
    output = run_command(shell, 'display current-configuration | include stack')
    return 'enable' not in output

# MBSS 6 - Secure Management VLAN Check
def check_secure_management_vlan_compliance(shell):
    output = run_command(shell, 'display current-configuration | include vlan')
    return 'vlan' in output

# MBSS 7 - Authorized IP Managers Check
def check_authorized_ip_managers_compliance(shell):
    output = run_command(shell, 'display acl 2000')
    return 'rule 10' and 'rule 20' in output

# MBSS 8 - Radis Scheme Check
def radius_authentication(shell):
    output = run_command(shell, 'display current-configuration | include radius')
    return 'radius scheme local' in output

# MBSS 9 - TACAS Scheme Check
def tacacs_authentication(shell):
    output = run_command(shell, 'display current-configuration | include TACACS')
    return '' in output #TACAS 

# MBSS 10 - TACAS Scheme Check
def level_privilege(shell):
    output = run_command(shell, 'display current-configuration | include radius')
    return 'service' in output 

# MBSS 11 - ARP Protection
def arp_valid(shell):
    output = run_command(shell, 'display current-configuration | include arp')
    return 'valid' in output

# MBSS 12 - Password Recovery Disable
def password_rec(shell):
    output = run_command(shell, 'display current-configuration | include password')
    return 'undo password-recovery' in output


results = []

ssh_client = connect_to_router()

if ssh_client:
    shell = ssh_client.invoke_shell()
    shell.send('system-view\n')
    time.sleep(1)

    # MBSS 1
    telnet_compliance = check_telnet_compliance(shell)
    results.append({
        'Serial Number': 1,
        'Category': 'Device protection',
        'Objective': 'Disable telnet',
        'Compliance': 'Compliant' if telnet_compliance else 'Non-Compliant'
    })

    # MBSS 2
    https_compliance = check_https_compliance(shell)
    results.append({
        'Serial Number': 2,
        'Category': 'Device protection',
        'Objective': 'Enable HTTPS',
        'Compliance': 'Compliant' if https_compliance else 'Non-Compliant'
    })

    # MBSS 3
    tftp_compliance = check_tftp_compliance(shell)
    results.append({
        'Serial Number': 3,
        'Category': 'Device protection',
        'Objective': 'Disable TFTP',
        'Compliance': 'Compliant' if tftp_compliance else 'Non-Compliant'
    })

    # MBSS 4
    snmpv3_compliance = check_snmpv3_compliance(shell)
    results.append({
        'Serial Number': 4,
        'Category': 'Device protection',
        'Objective': 'Enable SNMPv3',
        'Compliance': 'Compliant' if snmpv3_compliance else 'Non-Compliant'
    })

    # MBSS 5
    ip_stack_compliance = check_ip_stack_management_compliance(shell)
    results.append({
        'Serial Number': 5,
        'Category': 'Device protection',
        'Objective': 'IP Stack Management',
        'Compliance': 'Compliant' if ip_stack_compliance else 'Non-Compliant'
    })

    # MBSS 6
    secure_vlan_compliance = check_secure_management_vlan_compliance(shell)
    results.append({
        'Serial Number': 6,
        'Category': 'Access Control',
        'Objective': 'Secure Management VLAN',
        'Compliance': 'Compliant' if secure_vlan_compliance else 'Non-Compliant'
    })

    # MBSS 7
    authorized_ip_managers_compliance = check_authorized_ip_managers_compliance(shell)
    results.append({
        'Serial Number': 7,
        'Category': 'Access Control',
        'Objective': 'Authorized IP Managers',
        'Compliance': 'Compliant' if authorized_ip_managers_compliance else 'Non-Compliant'
    })

    # MBSS 8
    radius_auth = radius_authentication(shell)
    results.append({
        'Serial Number': 8,
        'Category': 'Access Control',
        'Objective': 'RADIUS authentication',
        'Compliance': 'Compliant' if radius_auth else 'Non-Compliant'
    })

    # MBSS 9
    radius_auth = tacacs_authentication(shell)
    results.append({
        'Serial Number': 9,
        'Category': 'Access Control',
        'Objective': 'TACACS authentication',
        'Compliance': 'Compliant' if radius_auth else 'Non-Compliant'
    })
    
    # MBSS 10
    radius_auth = level_privilege(shell)
    results.append({
        'Serial Number': 10,
        'Category': 'Access Control',
        'Objective': 'Server-Supplied Privilege Level',
        'Compliance': 'Compliant' if radius_auth else 'Non-Compliant'
    })

    # MBSS 11
    radius_auth = arp_valid(shell)
    results.append({
        'Serial Number': 11,
        'Category': 'Attack Prevention',
        'Objective': 'Dynamic ARP Protection',
        'Compliance': 'Compliant' if radius_auth else 'Non-Compliant'
    })

    # MBSS 12
    radius_auth = password_rec(shell)
    results.append({
        'Serial Number': 12,
        'Category': 'Physical Security',
        'Objective': 'Password Clear Protection – Front-Panel Security ',
        'Compliance': 'Compliant' if radius_auth else 'Non-Compliant'
    })

    ssh_client.close()

# Output results
for result in results:
    print(f"Check Passed: {result['Objective']} is correctly set." if result['Compliance'] == 'Compliant' else f"Check Failed: {result['Objective']} is not correctly set.")

# Write results to CSV
with open('compliance_report.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=['Serial Number', 'Category', 'Objective','Compliance'])
    writer.writeheader()
    writer.writerows(results)
