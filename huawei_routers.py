import paramiko
import csv
import time

# SSH connection details
host = '192.168.1.254'
username = 'admin'
password = 'password'
port = 22

# Command definitions
commands = {
    "Authentication Mechanisms": [
        "system-view",
        "display aaa configuration",  # General AAA configuration command
        "display current-configuration | include password",  # Verify cryptographic algorithms for password
        "quit"
    ],
    "User Identity Management": [
        "system-view",
        "display local-user",  # Updated command to list local users
        "display current-configuration | include local-user",  # Review user access privileges
        "quit"
    ],
    "Access Control Policies": [
        "system-view",
        "display acl",  # Check ACL policies
        "display current-configuration | include rbac",  # Check for RBAC implementation
        "quit"
    ]
}

def execute_command(client, command):
    stdin, stdout, stderr = client.exec_command(command, timeout=60)
    time.sleep(1)  # Short delay to ensure command starts executing

    output = ""
    while not stdout.channel.exit_status_ready():
        if stdout.channel.recv_ready():
            output += stdout.read(1024).decode('utf-8')
        time.sleep(1)  # Wait for more output if available

    output += stdout.read().decode('utf-8')
    output += stderr.read().decode('utf-8')
    return output

def main():
    # Establish SSH connection
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password, port=port)

    # Run commands and collect output
    results = []
    for objective, cmds in commands.items():
        output = ""
        for cmd in cmds:
            print(f"Executing: {cmd}")
            output += execute_command(client, cmd)
        results.append({"Objective": objective, "Result": output})

    # Close SSH connection
    client.close()

    # Write results to CSV
    with open('router_compliance_report.csv', 'w', newline='') as csvfile:
        fieldnames = ['Objective', 'Result']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)

if __name__ == "__main__":
    main()
