import paramiko
import pandas as pd
import time

# Define SSH connection parameters
HOST = '192.168.1.254'
PORT = 22
USERNAME = 'admin'
PASSWORD = 'password'

# Define control checks
checks = [
    {
        'sl_no': 1,
        'category': 'Management Pane',
        'control_objective': 'Digital Certificate Management',
        'description': 'Digital certificates are used to secure communication...',
        'remediation': 'Upload the obtained certificates and private key file...',
        'validation': 'Certificate Authority (CA) Verification, Certificate Revocation Status, Certificate Expiry'
    },
    {
        'sl_no': 2,
        'category': 'Management Pane',
        'control_objective': 'Device Login Security',
        'description': 'Console ports are physical interfaces...',
        'remediation': 'Connect the DB9 female connector of the console cable...',
        'validation': 'Strong Authentication Methods, Password Policies, Multi-factor Authentication (MFA)'
    },
    {
        'sl_no': 3,
        'category': 'Management Pane',
        'control_objective': 'AAA User Management Security',
        'description': 'An attacker attempts to obtain system administrators\' login access rights...',
        'remediation': 'Enable local account locking...',
        'validation': 'Authentication Mechanisms, User Identity Management, Access Control Policies'
    }
]

def check_control(ssh_client, control):
    start_time = time.time()
    compliance_status = 'Non-Compliant'
    try:
        print(f"Checking control {control['sl_no']}...")
        # Choose command based on control
        if control['sl_no'] == 1:
            command = 'display pki certificate ocsp'  # Adjusted command for PKI OCSP certificates
        elif control['sl_no'] == 2:
            command = 'display console'
        elif control['sl_no'] == 3:
            command = 'display aaa'
        
        print(f"Executing command: {command}")
        # Execute command and capture output
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        error_output = stderr.read().decode()

        if error_output:
            print(f"Error output: {error_output}")

        print(f"Command output: {output[:500]}...")  # Print the first 500 characters for brevity

        # Example validation logic
        if 'Certificate' in output or 'AAA' in output:
            compliance_status = 'Compliant'
        
    except Exception as e:
        print(f"Error checking control {control['sl_no']}: {e}")
    end_time = time.time()
    print(f"Control {control['sl_no']} check time: {end_time - start_time:.2f} seconds")
    return compliance_status

def generate_report():
    start_time = time.time()
    report = []

    # SSH Connection
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Connecting to {HOST}...")
        ssh_client.connect(HOST, PORT, USERNAME, PASSWORD)
        print("Connection established.")
    except Exception as e:
        print(f"Failed to connect to {HOST}: {e}")
        return

    # Check each control
    for control in checks:
        status = check_control(ssh_client, control)
        report.append({
            'Sl no.': control['sl_no'],
            'Category': control['category'],
            'Control Objective': control['control_objective'],
            'Description': control['description'],
            'Remediation': control['remediation'],
            'Validation': control['validation'],
            'Compliance Status': status
        })

    ssh_client.close()
    print("SSH connection closed.")

    # Save to CSV
    if report:
        df = pd.DataFrame(report)
        df.to_csv('compliance_report.csv', index=False)
        print("Compliance report generated.")
    else:
        print("No data to report.")
    
    end_time = time.time()
    print(f"Total script execution time: {end_time - start_time:.2f} seconds")

if __name__ == '__main__':
    generate_report()
