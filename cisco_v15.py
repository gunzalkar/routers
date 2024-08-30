import paramiko
import re

def connect_to_router(hostname, port, username, password):
    """Establish SSH connection to the router."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port, username, password)
        return ssh
    except paramiko.AuthenticationException:
        print("Authentication failed.")
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    return None

def execute_command(ssh, command):
    """Execute a command on the router and return the output."""
    stdin, stdout, stderr = ssh.exec_command(command)
    return stdout.read().decode()

def validate_privilege_level(output):
    """Validate that the output contains users with 'privilege 1'."""
    users_with_privilege_1 = re.findall(r'username \S+ privilege 1', output)
    if users_with_privilege_1:
        print("Validation successful: The following users have 'privilege 1':")
        for user in users_with_privilege_1:
            print(user)
    else:
        print("Validation failed: No users found with 'privilege 1'.")

def main():
    # Replace these with your router's details
    hostname = "192.168.1.1"  # Replace with the router's IP
    port = 22
    username = "admin"
    password = "password"

    ssh = connect_to_router(hostname, port, username, password)
    if ssh:
        command = "show running-config | include privilege"
        output = execute_command(ssh, command)
        validate_privilege_level(output)
        ssh.close()

if __name__ == "__main__":
    main()
