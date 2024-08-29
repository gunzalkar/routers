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
        "display aaa configuration",  # Check for AAA and authentication mechanisms
        "display current-configuration | include password",  # Verify cryptographic algorithms for password
        "quit"
    ],
    "User Identity Management": [
        "system-view",
        "display aaa local-user",  # List local users to verify lifecycle management
        "display current-configuration | include local-user",  # Review user access privileges
        "quit"
    ],
    "Access Control Policies": [
        "system-view",
        "display current-configuration | include acl",  # Validate ACL policies
        "display current-configuration | include rbac",  # Check for RBAC implementation
        "quit"
    ]
}

def execute_commands(client, commands):
    ssh = client.invoke_shell()
    output = ""

    for command in commands:
        print(f"Executing: {command}")  # Debugging line to see the command being executed
        ssh.send(command + '\n')
        time.sleep(2)  # Adjust delay if necessary for the command to execute properly
        while ssh.recv_ready():
            output += ssh.recv(1024).decode('utf-8')  # Read output in chunks
    return output

def main():
    # Establish SSH connection
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password, port=port)

    # Run commands and collect output
    results = []
    for objective, cmds in commands.items():
        output = execute_commands(client, cmds)
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
