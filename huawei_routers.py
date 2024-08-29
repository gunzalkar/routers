import paramiko
import csv

# Define router details
hostname = '192.168.1.254'  # Replace with the router's IP address
username = 'admin'          # Replace with the router's username
password = 'password'       # Replace with the router's password
port = 22

# SSH connection to the router
def ssh_connect(hostname, username, password, port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, port, username, password)
    return ssh

# Send command and receive output
def send_command(ssh, command):
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
    return output

# Configure AAA User Management Security
def configure_aaa(ssh):
    commands = [
        'system-view',
        'aaa',
        'local-aaa-user wrong-password retry-interval 6 retry-time 4 block-time 6',
        'return'
    ]
    output = []
    for command in commands:
        cmd_output = send_command(ssh, command)
        output.append(cmd_output)
    return output

# Verify the configuration
def verify_configuration(ssh):
    command = 'display aaa configuration'
    return send_command(ssh, command)

# Save results to CSV
def save_results_to_csv(objective, result, filename='validation_results.csv'):
    with open(filename, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([objective, result])

# Main function
def main():
    try:
        ssh = ssh_connect(hostname, username, password, port)
        # Configure AAA User Management
        config_output = configure_aaa(ssh)
        # Verify the configuration
        verify_output = verify_configuration(ssh)

        # Save the results to CSV
        save_results_to_csv('AAA User Management Security Configuration', 'Success' if 'wrong-password' in verify_output else 'Failed')
        save_results_to_csv('Configuration Verification', verify_output.strip())

        print("Configuration and verification complete. Results saved to CSV.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        ssh.close()

if __name__ == '__main__':
    main()
