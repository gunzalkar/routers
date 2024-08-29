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
        "display aaa configuration",
        "display current-configuration | include password",
        "quit"
    ],
    "User Identity Management": [
        "system-view",
        "display local-user",
        "display current-configuration | include local-user",
        "quit"
    ],
    "Access Control Policies": [
        "system-view",
        "display acl",
        "display current-configuration | include rbac",
        "quit"
    ]
}

def execute_commands(client, commands):
    ssh = client.invoke_shell()
    output = ""
    
    for command in commands:
        print(f"Executing: {command}")
        ssh.send(command + '\n')
        time.sleep(2)  # Allow time for the command to be processed
        
        while True:
            if ssh.recv_ready():
                output_chunk = ssh.recv(1024).decode('utf-8')
                output += output_chunk
                if ">" in output_chunk or "%" in output_chunk:
                    break
            time.sleep(1)  # Wait for more output if available

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
        output += execute_commands(client, cmds)
        results.append({"Objective": objective, "Result": output})

    # Close SSH connection
    client.close()

    # Write results to CSV
    with open('router_compliance_report.csv', 'w', newline='') as csvfile:
        fieldnam
