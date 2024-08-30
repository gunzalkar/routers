import paramiko
import re
import csv
import time
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def connect_to_router(hostname, port, username, password):
    """Establish SSH connection to the router."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port, username, password)
        ssh.get_transport().set_keepalive(60)  # Keep the SSH session alive
        logging.info("Successfully connected to the router.")
        return ssh
    except paramiko.AuthenticationException:
        logging.error("Authentication failed.")
    except paramiko.SSHException as e:
        logging.error(f"SSH connection error: {e}")
    except Exception as e:
        logging.error(f"Error: {e}")
    return None

def execute_command(ssh, command, retries=3):
    """Execute a command on the router with retries."""
    for attempt in range(retries):
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=60)  # Increased timeout
            output = stdout.read().decode()
            error = stderr.read().decode()
            if error:
                logging.error(f"Command error output: {error}")
            logging.info(f"Command executed successfully: {command}")
            return output
        except paramiko.SSHException as e:
            logging.warning(f"Attempt {attempt + 1}: Command execution failed: {e}")
            time.sleep(5)  # Wait before retrying
        except Exception as e:
            logging.warning(f"Attempt {attempt + 1}: Error during command execution: {e}")
            time.sleep(5)  # Wait before retrying
    logging.error(f"Command execution failed after {retries} attempts.")
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

def validate_no_exec_aux(output):
    """Validate that the 'no exec' command is set for 'line aux 0'."""
    # Extract configuration section for 'line aux 0'
    aux_config = re.search(r'line aux 0[\s\S]*?(?=^line|\Z)', output, re.MULTILINE)
    
    if aux_config:
        config_text = aux_config.group(0)
        logging.debug(f"Extracted Configuration for aux 0:\n{config_text}")  # Debugging line
        if 'no exec' in config_text:
            return "Compliant", "'no exec' is configured for 'line aux 0'"
        else:
            return "Non-compliant", "'no exec' is not configured for 'line aux 0'"
    else:
        return "Non-compliant", "'line aux 0' configuration not found"

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
        },
        {
            "sr_no": 3,
            "policy": "Set 'no exec' for 'line aux 0'",
            "command": "show running-config | section aux",
            "validator": validate_no_exec_aux,
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
