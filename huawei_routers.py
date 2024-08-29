import paramiko
import csv

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
        "display aaa local-user",
        "display current-configuration | include local-user",
        "quit"
    ],
    "Access Control Policies": [
        "system-view",
        "display current-configuration | include acl",
        "display current-configuration | include rbac",
        "quit"
    ]
}

def execute_commands(client, commands):
    output = ""
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command)
        output += stdout.read().decode('utf-8')
        output += stderr.read().decode('utf-8')
    return output

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password, port=22)

    results = []
    for objective, cmds in commands.items():
        output = execute_commands(client, cmds)
        results.append({"Objective": objective, "Result": output})

    client.close()

    with open('router_compliance_report.csv', 'w', newline='') as csvfile:
        fieldnames = ['Objective', 'Result']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)

if __name__ == "__main__":
    main()
