import paramiko
import time
from openpyxl import Workbook

def ssh_connect(host, username, password):
    """Establish SSH connection."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=password)
    return ssh

def enter_system_view(ssh_client):
    """Enter system view or privileged EXEC mode."""
    stdin, stdout, stderr = ssh_client.exec_command("system-view\n")
    time.sleep(1)  # Adjust this sleep time if necessary

def exit_system_view(ssh_client):
    """Exit system view or privileged EXEC mode."""
    stdin, stdout, stderr = ssh_client.exec_command("quit\n")
    time.sleep(1)  # Adjust this sleep time if necessary

def check_port_protection(ssh_client):
    enter_system_view(ssh_client)
    
    commands = [
        "display current-configuration | include physical security",
        "display current-configuration | include port security",
        "display current-configuration | include dynamic arp inspection"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    exit_system_view(ssh_client)

    physical_security = "Physical security measures are in place." if "physical security" in results[0][1] else "Physical security measures are not in place."
    port_security_config = "Port security configurations are implemented." if "port security" in results[1][1] else "Port security configurations are not implemented."
    dynamic_arp_inspection = "DAI is enabled to prevent ARP spoofing." if "dynamic arp inspection" in results[2][1] else "DAI is not enabled to prevent ARP spoofing."

    return [
        ["Port Protection - Physical Security", physical_security],
        ["Port Protection - Port Security Configuration", port_security_config],
        ["Port Protection - Dynamic ARP Inspection (DAI)", dynamic_arp_inspection]
    ]

def check_port_isolation(ssh_client):
    enter_system_view(ssh_client)

    commands = [
        "display current-configuration | include port isolation",
        "display current-configuration | include vlan",
        "display current-configuration | include port isolation testing"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    exit_system_view(ssh_client)

    port_isolation_config = "Port isolation settings are configured." if "port isolation" in results[0][1] else "Port isolation settings are not configured."
    traffic_segmentation = "Network traffic is segmented." if "vlan" in results[1][1] else "Network traffic is not segmented."
    connectivity_testing = "Port isolation is validated through testing." if "port isolation testing" in results[2][1] else "Port isolation is not validated through testing."

    return [
        ["Port Isolation - Port Isolation Configuration", port_isolation_config],
        ["Port Isolation - Traffic Segmentation", traffic_segmentation],
        ["Port Isolation - Testing Connectivity", connectivity_testing]
    ]

def check_port_security(ssh_client):
    enter_system_view(ssh_client)

    commands = [
        "display current-configuration | include port security",
        "display current-configuration | include mac address filtering",
        "display current-configuration | include mac address limiting"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    exit_system_view(ssh_client)

    port_security_config = "Port security features are configured." if "port security" in results[0][1] else "Port security features are not configured."
    mac_address_filtering = "MAC address filtering is configured." if "mac address filtering" in results[1][1] else "MAC address filtering is not configured."
    mac_address_limiting = "MAC address limiting is configured." if "mac address limiting" in results[2][1] else "MAC address limiting is not configured."

    return [
        ["Port Security - Port Security Configuration", port_security_config],
        ["Port Security - MAC Address Filtering", mac_address_filtering],
        ["Port Security - MAC Address Limiting", mac_address_limiting]
    ]

def perform_checks(cert_path, ca_path, output_file, ssh_client):
    results = []
    
    # Add the results of each check to the results list
    results.extend(check_port_protection(ssh_client))
    results.extend(check_port_isolation(ssh_client))
    results.extend(check_port_security(ssh_client))

    # Save the results to an Excel file
    wb = Workbook()
    ws = wb.active
    for row in results:
        ws.append(row)
    wb.save(output_file)

    # Print the results to the console
    for result in results:
        print(f"Objective: {result[0]}, Result: {result[1]}")

def main():
    router_ip = "192.168.1.254"
    username = "admin"
    password = "password"
    output_excel_file = "results.xlsx"
    
    # Establish SSH connection
    ssh_client = ssh_connect(router_ip, username, password)
    
    # Perform checks and save the results
    perform_checks("certificate.pem", "rootCA.pem", output_excel_file, ssh_client)
    
    # Close SSH connection
    ssh_client.close()

if __name__ == "__main__":
    main()
