import paramiko
import re
import csv

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
        return "Compliant", "All local users have privilege level 1"
    else:
        return "Non-compliant", "No users found with privilege 1"

def write_results_to_csv(results, csv_filename):
    """Write the validation results to a CSV file."""
    with open(csv_filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Sr. No.", "Policy", "Compliance Status", "Description"])
        for result in results:
            writer.writerow(result)

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
        }
        # You can add more policies here
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
