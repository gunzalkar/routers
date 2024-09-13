import paramiko
import time
import csv

hostname = '192.168.1.1'
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

    ssh_client.close()

# Output results
for result in results:
    print(f"Check Passed: {result['Objective']} is correctly set." if result['Compliance'] == 'Compliant' else f"Check Failed: {result['Objective']} is not correctly set.")

# Write results to CSV
with open('compliance_report.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=['Serial Number', 'Category', 'Objective', 'Comments', 'Compliance'])
    writer.writeheader()
    writer.writerows(results)
