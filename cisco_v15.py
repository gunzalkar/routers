import paramiko
import re
import csv

def connect_to_router(hostname, port, username, password):
    """Establish SSH connection to the router."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port, username, password)
        ssh.get_transport().set_keepalive(30)  # Keep the SSH session alive
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
    try:
        stdin, stdout, stderr = ssh.exec_command(command, timeout=10)
        return stdout.read().decode()
    except Exception as e:
        print(f"Command execution failed: {e}")
        return ""

# (Validation functions and the rest of the script remain the same)

def main():
    # Replace these with your router's details
    hostname = "192.168.1.1"  # Replace with the router's IP
    port = 22
    username = "admin"
    password = "password"

    # Example policy checks
    policies = [
        {
            "sr_no": 1,
            "policy": "Set 'privilege 1' for local users",
            "command": "show running-config | include privilege",
            "validator": validate_privilege_level,
        },
        {
            "sr_no": 2,
            "policy": "Set 'transport input ssh' for 'line vty' connections",
            "command": "show running-config | section vty",
            "validator": validate_vty_transport_input,
        }
    ]

    # Connect to router
    ssh = connect_to_router(hostname, port, username, password)
    if not ssh:
        print("Failed to connect to the router.")
        return

    # Store results for all policies
    results = []

    for policy in policies:
        output = execute_command(ssh, policy["command"])
        compliance_status, description = policy["validator"](output)
        results.append([
            policy["sr_no"],
            policy["policy"],
            compliance_status,
            description
        ])

    # Close the SSH connection
    ssh.close()

    # Export results to CSV
    csv_filename = "router_compliance_results.csv"
    write_results_to_csv(results, csv_filename)
    print(f"Results have been written to {csv_filename}")

if __name__ == "__main__":
    main()
