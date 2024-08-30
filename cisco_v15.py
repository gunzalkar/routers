import paramiko
import csv

def execute_command(conn, command):
    stdin, stdout, stderr = conn.exec_command(command)
    return stdout.read().decode('utf-8')

def check_privilege_level(conn):
    command = "show run | include privilege"
    output = execute_command(conn, command)
    return 'Compliant' if 'privilege 15' in output else 'Non-Compliant'

def check_vty_transport(conn):
    command = "show run | section vty"
    output = execute_command(conn, command)
    return 'Compliant' if 'transport input ssh' in output else 'Non-Compliant'

def check_aux_no_exec(conn):
    command = "show run | section aux"
    output = execute_command(conn, command)
    return 'Compliant' if 'no exec' in output else 'Non-Compliant'

def check_vty_acl(conn, acl_number):
    acl_command = f"show ip access-lists {acl_number}"
    acl_output = execute_command(conn, acl_command)
    
    permit_found = any("permit" in line for line in acl_output.splitlines())
    deny_any_found = any("deny   any log" in line for line in acl_output.splitlines())
    
    if permit_found and deny_any_found:
        return 'Compliant'
    else:
        return 'Non-Compliant'

def check_access_class(conn, acl_number):
    command = "show run | section vty"
    output = execute_command(conn, command)
    
    if f"access-class {acl_number} in" in output:
        return 'Compliant'
    else:
        return 'Non-Compliant'

def main():
    router_ip = "192.168.1.1"
    username = "admin"
    password = "password"
    acl_number = 10  # The ACL number that should be used for the VTY lines
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(router_ip, username=username, password=password)
    
    compliance_data = [
        {'Policy': "Set 'privilege 1' for local users", 'Check': check_privilege_level(client)},
        {'Policy': "Set 'transport input ssh' for 'line vty'", 'Check': check_vty_transport(client)},
        {'Policy': "Set 'no exec' for 'line aux 0'", 'Check': check_aux_no_exec(client)},
        {'Policy': "Create 'access-list' for use with 'line vty'", 'Check': check_vty_acl(client, acl_number)},
        {'Policy': "Set 'access-class' for 'line vty'", 'Check': check_access_class(client, acl_number)}
    ]
    
    client.close()
    
    # Print the compliance results
    for entry in compliance_data:
        print(f"{entry['Policy']}: {entry['Check']}")
    
    # Export the results to a CSV file
    with open('compliance_report.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['Policy', 'Check'])
        writer.writeheader()
        writer.writerows(compliance_data)

if __name__ == "__main__":
    main()
