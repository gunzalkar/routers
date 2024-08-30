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

def validate_privilege_level(output):
    """Validate that the output contains users with 'privilege 1'."""
    users_with_privilege_1 = re.findall(r'username \S+ privilege 1', output)
    if users_with_privilege_1:
        return "Compliant", "All local users have privilege level 1"
    else:
        return "Non-compliant", "No users found with privilege 1"

def validate_vty_transport_input(output):
    """Validate that the output shows only 'ssh' for 'transport input' on VTY lines."""
    vty_sections = re.findall(r'line vty \d+ \d+[\s\S]*?transport input \S+', output)
    non_ssh_transports = [section for section in vty_sections if "transport input ssh" not in section]

    if not non_ssh_transports:
        return "Compliant", "All VTY lines have 'transport input ssh' configured"
    else:
        return "Non-compliant", f"Non-SSH transport methods found in VTY configurations: {non_ssh_transports}"

def write_results_to_csv(results, csv_filename):
    """Write the validation results to a CSV file."""
    with open(csv_filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Sr. No.", "Policy", "Compliance Status", "Description"])
        for result in results:
            writer.writerow(result)

def print_results(results):
    """Print the validation results in the terminal."""
    print("\nValidation Results:")
    print(f"{'Sr. No.':<8} {'Policy':<50} {'Compliance Status':<15} {'Description'}")
    print("-" * 90)
    for result in results:
        print(f"{result[0]:<8} {result[1]:<50} {result[2]:<15} {result[3]}")

def check_policy(ssh, policy):
    """Execute the command and validate the policy."""
    output = execute_command(ssh, policy["command"])
    compliance_status, description = policy["validator"](output)
    return [
        policy["sr_no"],
        policy["policy"],
        compliance_status,
        description
    ]

def main():
    # Replace these with your router's details
    hostname = "192.168.1.1"  # Replace with the router's IP
    port = 22
    username = "admin"
    password = "password"

    # Policy definitions
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
        # You can add more policies here by adding new dictionaries to this list
    ]

    # Connect to router
    ssh = connect_to_router(hostname, port, username, password)
    if not ssh:
        print("Failed to connect to the router.")
        return

    # Store results for all policies
    results = [check_policy(ssh, policy) for policy in policies]

    # Close the SSH connection
    ssh.close()

    # Print results in terminal
    print_results(results)

    # Export results to CSV
    csv_filename = "router_compliance_results.csv"
    write_results_to_csv(results, csv_filename)
    print(f"\nResults have been written to {csv_filename}")

if __name__ == "__main__":
    main()
