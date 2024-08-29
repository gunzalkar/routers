import paramiko
import time
import csv

# SSH connection details
router_ip = '192.168.1.254'  # Replace with your router's IP
username = 'admin'  # Replace with your router's username
password = 'password'  # Replace with your router's password

# Commands for console port security check and AAA authentication configuration
commands = [
    'system-view',
    'user-interface console 0',
    'display this',  # Check current configuration
    'authentication-mode aaa',  # Ensure AAA authentication is set
    'quit',
    'aaa',
    'display this',  # Check AAA configuration
    'quit'
]

# Function to execute commands on the router
def execute_commands(commands):
    output = []
    try:
        # Initialize SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(router_ip, username=username, password=password)

        # Start an interactive shell session
        remote_conn = ssh.invoke_shell()
        time.sleep(1)
        remote_conn.recv(1000)  # Clear the initial buffer

        for command in commands:
            remote_conn.send(command + '\n')
            time.sleep(1)
            output.append(remote_conn.recv(5000).decode('utf-8'))

        ssh.close()
    except Exception as e:
        print(f"Error: {str(e)}")
    
    return output

# Save results to a CSV file
def save_to_csv(output):
    with open('security_check_results.csv', mode='w') as file:
        writer = csv.writer(file)
        writer.writerow(['Objective', 'Result'])

        objectives = [
            "Check console port authentication mode",
            "Check AAA configuration"
        ]
        
        for i, obj in enumerate(objectives):
            writer.writerow([obj, output[i]])

if __name__ == "__main__":
    output = execute_commands(commands)
    save_to_csv(output)
    print("Security check completed. Results saved to 'security_check_results.csv'.")
