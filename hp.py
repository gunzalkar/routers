import paramiko
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
    return 'https' in output and 'enabled' in output

# MBSS 3 - Disable TFTP Check
def check_tftp_compliance(shell):
    output = run_command(shell, 'display current-configuration | include tftp')
    return 'tftp' not in output or 'enable' not in output

# MBSS 4 - Enable SNMPv3 Check
def check_snmp_compliance(shell):
    output = run_command(shell, 'display current-configuration | include snmp')
    return 'snmp-agent sys-info version v3' in output

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
        'Comments': 'Compliant' if telnet_compliance else 'Non-Compliant',
        'Compliance': 'Compliant' if telnet_compliance else 'Non-Compliant'
    })

    # MBSS 2
    https_compliance = check_https_compliance(shell)
    results.append({
        'Serial Number': 2,
        'Category': 'Device protection',
        'Objective': 'Enable HTTPS',
        'Comments': 'Compliant' if https_compliance else 'Non-Compliant',
        'Compliance': 'Compliant' if https_compliance else 'Non-Compliant'
    })

    # MBSS 3
    tftp_compliance = check_tftp_compliance(shell)
    results.append({
        'Serial Number': 3,
        'Category': 'Device protection',
        'Objective': 'Disable TFTP',
        'Comments': 'Compliant' if tftp_compliance else 'Non-Compliant',
        'Compliance': 'Compliant' if tftp_compliance else 'Non-Compliant'
    })

    # MBSS 4
    snmp_compliance = check_snmp_compliance(shell)
    results.append({
        'Serial Number': 4,
        'Category': 'Device protection',
        'Objective': 'Enable SNMPv3',
        'Comments': 'Compliant' if snmp_compliance else 'Non-Compliant',
        'Compliance': 'Compliant' if snmp_compliance else 'Non-Compliant'
    })

    ssh_client.close()

# Output results
for result in results:
    print(f"Check Passed: {result['Objective']} is correctly set." if result['Compliance'] == 'Compliant' else f"Check Failed: {result['Objective']} is not correctly set.")

# Write results to CSV
with open('compliance_report.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=['Serial Number', 'Category', 'Objective', 'Comments', 'Compliance'])
    writer.writeheader()
    writer.writerows(results)
