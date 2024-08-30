from netmiko import ConnectHandler
import csv

# Configuration
router = {
    'device_type': 'cisco_ios',
    'host': '192.168.1.254',
    'username': 'admin',
    'password': 'password',
    'port': 22,
}

def execute_command(conn, command):
    return conn.send_command(command)

def check_privilege_levels(conn):
    command = "show run | include privilege"
    output = execute_command(conn, command)
    return 'Compliant' if 'privilege 1' in output else 'Non-Compliant'

def check_vty_transport(conn):
    command = "show run | section vty"
    output = execute_command(conn, command)
    return 'Compliant' if 'transport input ssh' in output else 'Non-Compliant'

def check_no_exec_aux(conn):
    command = "show run | section aux"
    output = execute_command(conn, command)
    return 'Compliant' if 'no exec' in output else 'Non-Compliant'

def check_vty_acl(conn, acl_number):
    # Command to display the ACL details
    acl_command = f"show ip access-lists {acl_number}"
    acl_output = execute_command(conn, acl_command)

    # Check if there is at least one permit rule and one deny any rule
    permit_found = any("permit" in line for line in acl_output.splitlines())
    deny_any_found = any("deny   any log" in line for line in acl_output.splitlines())

    # Compliance if both a permit and a deny any rule exist
    if permit_found and deny_any_found:
        return 'Compliant'
    else:
        return 'Non-Compliant'

# Main function
def main():
    acl_number = '10'  # Replace with the actual ACL number

    with ConnectHandler(**router) as conn:
        # Policies
        policies = [
            {
                'Policy': 'Set privilege 1 for local users',
                'Description': 'All local users have privilege level 1 or more',
                'Command': 'show run | include privilege',
                'Check': check_privilege_levels(conn)
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
