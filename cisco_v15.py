import paramiko
import re
import sys

def connect_to_router(hostname, port, username, password):
    """
    Establish SSH connection to the router.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port=port, username=username, password=password, look_for_keys=False, allow_agent=False)
        print(f"Successfully connected to {hostname}")
        return ssh
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        sys.exit(1)
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

def execute_command(ssh, command):
    """
    Execute a command on the router and return the output.
    """
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()
    if error:
        print(f"Error executing command '{command}': {error}")
        return None
    return output

def validate_privilege_level(output):
    """
    Validate that all local users have 'privilege 1'.
    """
    print("\nValidating local user privilege levels...")
    user_entries = re.findall(r'^username\s+(\S+)\s+privilege\s+(\d+)', output, re.MULTILINE)
    
    if not user_entries:
        print("No local users found.")
        return False
    
    invalid_users = [user for user, privilege in user_entries if privilege != '1']
    
    if invalid_users:
        print("Validation failed: The following users do not have 'privilege 1':")
        for user in invalid_users:
            print(f" - {user}")
        return False
    else:
        print("All local users have 'privilege 1'.")
        return True

def validate_transport_input_ssh(output):
    """
    Validate that all VTY lines have 'transport input ssh' configured.
    """
    print("\nValidating VTY lines for 'transport input ssh' configuration...")
    vty_blocks = re.findall(r'line vty [\d ]+\n(?: .*\n)*', output, re.MULTILINE)
    
    if not vty_blocks:
        print("No VTY line configurations found.")
        return False
    
    all_valid = True
    for block in vty_blocks:
        lines = block.strip().split('\n')
        line_range = lines[0].strip()
        transport_input = None
        for line in lines[1:]:
            if 'transport input' in line:
                transport_input = line.strip()
                break
        if transport_input != 'transport input ssh':
            print(f"Validation failed for {line_range}:")
            print(f" - Current setting: '{transport_input or 'None'}'")
            all_valid = False
        else:
            print(f"{line_range} is correctly configured with 'transport input ssh'.")
    
    return all_valid

def main():
    # Router connection details (Update these with actual credentials and IP)
    hostname = "192.168.1.1"
    port = 22
    username = "admin"
    password = "admin_password"
    
    ssh = connect_to_router(hostname, port, username, password)
    
    # Validate local user privilege levels
    user_command = "show running-config | include ^username"
    user_output = execute_command(ssh, user_command)
    if user_output is not None:
        validate_privilege_level(user_output)
    
    # Validate VTY line transport input configuration
    vty_command = "show running-config | section line vty"
    vty_output = execute_command(ssh, vty_command)
    if vty_output is not None:
        validate_transport_input_ssh(vty_output)
    
    ssh.close()
    print("\nValidation completed.")

if __name__ == "__main__":
    main()
