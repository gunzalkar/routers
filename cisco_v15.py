from netmiko import ConnectHandler
import csv

# Configuration
router = {
    'device_type': 'cisco_ios',
    'host': '192.168.1.1',
    'username': 'admin',
    'password': 'password',
    'port': 22,
}

def execute_command(conn, command):
    return conn.send_command(command)

def enforce_privilege_level_1(conn):
    exempt_users = ['admin', 'super', 'super 2']
    command = "show run | include privilege"
    output = execute_command(conn, command)
    lines = output.splitlines()
    compliant = True

    for line in lines:
        if 'privilege' in line:
            privilege_level = int(line.split('privilege')[1].split()[0])
            user = line.split()[1]
            if privilege_level > 1 and user not in exempt_users:
                set_privilege_command = f"username {user} privilege 1"
                conn.send_config_set([set_privilege_command])
                compliant = False  # Mark as non-compliant if any non-exempt user had a privilege level higher than 1

    return 'Compliant' if compliant else 'Non-Compliant'
    
def check_vty_transport(conn):
    command = "show run | section vty"
    output = execute_command(conn, command)
    
    # Debug output
    print("VTY Transport Check Output:")
    print(output)
    
    lines = output.splitlines()
    ssh_found = False
    for line in lines:
        if 'transport input ssh' in line:
            ssh_found = True
        if 'transport input telnet' in line or 'transport input all' in line:
            return 'Non-Compliant'

    return 'Compliant' if ssh_found else 'Non-Compliant'

def check_no_exec_aux(conn):
    command = "show run | section aux"
    output = execute_command(conn, command)
    return 'Compliant' if 'no exec' in output else 'Non-Compliant'

def check_vty_acl(conn, acl_number):
    acl_command = f"show ip access-lists {acl_number}"
    acl_output = execute_command(conn, acl_command)

    permit_found = any("permit" in line for line in acl_output.splitlines())
    deny_any_found = any("deny   any log" in line for line in acl_output.splitlines())

    return 'Compliant' if permit_found and deny_any_found else 'Non-Compliant'

def check_access_class(conn, acl_number):
    command = f"show run | section vty"
    output = execute_command(conn, command)
    
    # Debug output
    print("Access Class Check Output:")
    print(output)
    
    return 'Compliant' if f'access-class {acl_number} in' in output else 'Non-Compliant'

# Main function
def main():
    acl_number = '10'  # Replace with the actual ACL number

    with ConnectHandler(**router) as conn:
        # Policies
        policies = [
            {
                'Policy': 'Set privilege 1 for local users',
                'Description': 'All local users must have privilege level 1, except exempt users',
                'Command': 'show run | include privilege',
                'Check': enforce_privilege_level_1(conn)
            },
            {
                'Policy': 'Set transport input ssh for line vty connections',
                'Description': 'SSH should be the only transport method for incoming VTY logins',
                'Command': 'show run | section vty',
                'Check': check_vty_transport(conn)
            },
            {
                'Policy': 'Set no exec for line aux 0',
                'Description': 'The EXEC process on the auxiliary port should be disabled',
                'Command': 'show run | section aux',
                'Check': check_no_exec_aux(conn)
            },
            {
                'Policy': 'Create access-list for use with line vty',
                'Description': 'VTY ACLs control what addresses may attempt to log in to the router.',
                'Command': f'show ip access-list {acl_number}',
                'Check': check_vty_acl(conn, acl_number)
            },
            {
                'Policy': 'Set access-class for line vty',
                'Description': 'Restrict remote access to devices authorized to manage the device.',
                'Command': f'show run | section vty',
                'Check': check_access_class(conn, acl_number)
            }
        ]

        # Output to CSV and Terminal
        with open('policy_compliance_report.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Policy', 'Description', 'Command', 'Check'])
            for policy in policies:
                writer.writerow([policy['Policy'], policy['Description'], policy['Command'], policy['Check']])
                print(f"Policy: {policy['Policy']}")
                print(f"Description: {policy['Description']}")
                print(f"Command: {policy['Command']}")
                print(f"Check: {policy['Check']}")
                print('-' * 80)

if __name__ == "__main__":
    main()
