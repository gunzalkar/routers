from netmiko import ConnectHandler

def connect_to_router():
    device = {
        'device_type': 'cisco_ios',
        'host': '192.168.1.1',
        'username': 'admin',
        'password': 'password',
    }
    return ConnectHandler(**device)

def verify_privilege_level(connection):
    output = connection.send_command('show run | incl privilege')
    return all('privilege 1' in line for line in output.splitlines())

def verify_ssh_transport(connection):
    output = connection.send_command('show run | sec vty')
    return all('transport input ssh' in line for line in output.splitlines() if 'transport input' in line)

def verify_aux_exec_disabled(connection):
    output = connection.send_command('show run | sec aux')
    return all('no exec' in line for line in output.splitlines() if 'exec' in line)

def verify_acl_entries(connection, vty_acl_number, required_entries):
    command = f'show ip access-lists {vty_acl_number}'
    output = connection.send_command(command)
    return all(f'{entry} ' in output for entry in required_entries)

# In the main function or wherever you are doing the checks
vty_acl_number = '10'  # Replace with the actual ACL number
required_entries = ['10', '20', '30']  # List the sequence numbers you want to verify

def verify_acl_set_on_vty(connection, start_line, end_line, acl_number):
    command = f'show run | sec vty {start_line} {end_line}'
    output = connection.send_command(command)
    acl_check_string = f'access-class {acl_number} in'
    return acl_check_string in output

# In the main function or wherever you are doing the checks
start_line = '0'  # Replace with the actual starting VTY line number
end_line = '4'    # Replace with the actual ending VTY line number
acl_number = '10' # Replace with the ACL number you're verifying

def main():
    connection = connect_to_router()

    if verify_privilege_level(connection):
        print("All users are set to privilege level 1.")
    else:
        print("There are users not set to privilege level 1.")

    if verify_ssh_transport(connection):
        print("SSH is the only transport method for VTY logins.")
    else:
        print("Non-SSH transport methods are configured for VTY logins.")

    if verify_aux_exec_disabled(connection):
        print("The EXEC process for the AUX port is disabled.")
    else:
        print("The EXEC process for the AUX port is not disabled.")

    if verify_acl_entries(connection, vty_acl_number, required_entries):
        print(f"ACL {vty_acl_number} contains the required entries: {', '.join(required_entries)}.")

    else:
        print(f"ACL {vty_acl_number} is missing one or more required entries: {', '.join(required_entries)}.")

    if verify_acl_set_on_vty(connection, start_line, end_line, acl_number):
        print(f"ACL {acl_number} is set on VTY lines {start_line} to {end_line}.")
    else:
        print(f"ACL {acl_number} is not set on VTY lines {start_line} to {end_line}.")

    connection.disconnect()

if __name__ == "__main__":
    main()
