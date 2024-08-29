import paramiko
import csv
import time

# SSH details
hostname = '192.168.1.254'
username = 'admin'
password = 'password'
port = 22

# Commands to be executed in system-view
commands = {
    "Certificate Authority verification passed.": "display certificate authority",
    "OCSP check failed.": "display certificate ocsp-status",
    "Certificate is valid.": "display certificate status",
    "Strong authentication methods are in place.": "display aaa configuration",
    "Password policies are enforced.": "display aaa password-policy",
    "Multi-factor authentication is enabled.": "display aaa mfa-configuration",
    "Authentication mechanisms are securely implemented.": "display aaa authentication-scheme",
    "User identities are managed securely.": "display aaa user-identity-management",
    "Access control policies are validated.": "display access-control policies",
    "ACL 2001 is correctly configured.": "display acl 2001",
    "SNMP ACL is configured correctly.": "display snmp acl",
    "MIB view iso-view is configured.": "display snmp mib-view iso-view",
    "SNMPv3 group v3group is configured correctly.": "display snmp v3group",
    "SNMPv3 user v3user is configured correctly.": "display snmp v3user",
    "Service plane access prohibition is correctly configured.": "display service-plane access"
}

# Output CSV file
output_file = 'compliance_report.csv'

def execute_command(ssh_client, command):
    stdin, stdout, stderr = ssh_client.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()
    return output, error

def main():
    # Connect to the router
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname, port, username, password)

    # Enter system-view mode
    channel = ssh_client.invoke_shell()
    channel.send('system-view\n')
    time.sleep(2)  # Wait for the command to be processed

    results = []

    for objective, command in commands.items():
        # Send command
        channel.send(f'{command}\n')
        time.sleep(2)  # Wait for command output

        # Read command output
        output = channel.recv(4096).decode()
        result = "Check Failed"

        # Basic validation based on command output
        if "passed" in output.lower() or "valid" in output.lower() or "correctly configured" in output.lower():
            result = "Passed"
        elif "error" in output.lower():
            result = "Failed"

        results.append({"Objective": objective, "Result": result})

    # Close SSH connection
    channel.send('quit\n')
    time.sleep(2)
    ssh_client.close()

    # Write results to CSV
    with open(output_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["Objective", "Result"])
        writer.writeheader()
        for result in results:
            writer.writerow(result)

    print(f"Compliance report saved to {output_file}")

if __name__ == "__main__":
    main()
