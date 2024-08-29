import paramiko
import csv

# SSH connection details
router_ip = "192.168.1.254"  # Replace with your router's IP address
username = "admin"           # Replace with your username
password = "password"        # Replace with your password

# Connect to the router via SSH
def connect_to_router():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(router_ip, username=username, password=password)
        return client
    except Exception as e:
        print(f"Connection failed: {e}")
        return None

# Execute a command on the router and return the output
def execute_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')

# Validate the certificate
def validate_certificate(client):
    validation_results = {}

    # Enter system view
    execute_command(client, "system-view")

    # Certificate Authority (CA) Verification
    ca_output, _ = execute_command(client, "display pki certificate ca")
    if "trusted" in ca_output:
        validation_results['CA Verification'] = "Passed"
    else:
        validation_results['CA Verification'] = "Failed"

    # Certificate Revocation Status
    revocation_output, _ = execute_command(client, "display pki crl")
    if "Revoked" not in revocation_output:
        validation_results['Certificate Revocation Status'] = "Passed"
    else:
        validation_results['Certificate Revocation Status'] = "Failed"

    # Certificate Expiry
    expiry_output, _ = execute_command(client, "display pki certificate local")
    if "expired" not in expiry_output:
        validation_results['Certificate Expiry'] = "Passed"
    else:
        validation_results['Certificate Expiry'] = "Failed"

    # Exit system view
    execute_command(client, "quit")

    return validation_results

# Save results to CSV
def save_results_to_csv(results, filename="certificate_validation_results.csv"):
    with open(filename, mode='w') as file:
        writer = csv.writer(file)
        writer.writerow(['Objective', 'Result'])
        for objective, result in results.items():
            writer.writerow([objective, result])

# Main function
def main():
    client = connect_to_router()
    if client:
        results = validate_certificate(client)
        save_results_to_csv(results)
        print("Validation completed and results saved to CSV.")
        client.close()
    else:
        print("Could not connect to the router.")

if __name__ == "__main__":
    main()
