from netmiko import ConnectHandler
import logging

# Enable logging for debugging
logging.basicConfig(filename='netmiko_debug.log', level=logging.DEBUG)

def connect_to_router():
    device = {
        'device_type': 'cisco_ios',
        'host': '192.168.1.1',
        'username': 'kshitij',
        'password': 'password',
        'secret': 'password',  # Replace with your enable password
        'timeout': 60,  # Increase the timeout if needed
    }
    return ConnectHandler(**device)

def enable_mode(connection):
    try:
        connection.enable()
    except ValueError as e:
        print(f"Failed to enter enable mode: {e}")
        raise

def verify_privilege_level(connection):
    excluded_users = {'kshitij', 'admin', 'super', 'super2'}
    
    command = 'show run | include privilege'
    output = connection.send_command(command)
    lines = output.splitlines()
    
    # Filter lines to find all 'username' entries with 'privilege'
    privilege_lines = [line.strip() for line in lines if 'username' in line and 'privilege' in line]

    # If there are no privilege lines, return True
    if not privilege_lines:
        return True

    # Check if any 'privilege' line is not set to 1 for non-excluded users
    for line in privilege_lines:
        username = line.split()[1]
        privilege = line.split('privilege')[1].strip().split()[0]
        if username not in excluded_users and privilege != '1':
            return False

    # Return True if all non-excluded 'privilege' lines are set to 1
    return True

def verify_ssh_transport(connection):
    command = 'show run | sec vty'
    output = connection.send_command(command)
    lines = output.splitlines()

    transport_input_lines = [line.strip() for line in lines if line.strip().startswith('transport input')]
    
    if not transport_input_lines:
        return False  # No transport input lines found
    
    return len(transport_input_lines) == 1 and transport_input_lines[0] == 'transport input ssh'

def verify_aux_exec_disabled(connection):
    # Check the running configuration for the AUX port
    command_run = 'show run | sec aux'
    output_run = connection.send_command(command_run)
    
    # Verify 'no exec' is present in the configuration output
    if 'no exec' not in output_run:
        return False

    # Check the AUX line status
    command_line = 'show line aux 0 | incl EXEC'
    output_line = connection.send_command(command_line)
    
    # Verify 'no exec' is present in the line status output
    if 'Capabilities: EXEC Suppressed' not in output_line:
        return False

    # Return True if both checks are passed
    return True

def verify_acl_entries(connection, vty_acl_number, required_entries):
    command = f'show ip access-lists {vty_acl_number}'
    output = connection.send_command(command)
    return all(f'{entry} ' in output for entry in required_entries)

vty_acl_number = '10'  # Replace with the actual ACL number
required_entries = ['10', '20', '30']  # List the sequence numbers you want to verify

def verify_acl_set(connection, line_start, line_end, vty_acl_number):
    command = f'show run | sec vty {line_start} {line_end}'
    output_line = connection.send_command(command)
    # Check if 'access-class' is present in the output

    if 'access-class' not in output_line:
        return False

    # Return True if both checks are passed
    return True

# Example usage
line_start = '0'  # Replace with the starting line number
line_end = '4'    # Replace with the ending line number

def verify_timeout_configured(connection):
    command = 'show run | sec line aux 0'
    output = connection.send_command(command)
    
    # Look for the 'exec-timeout' line in the output
    for line in output.splitlines():
        if line.strip().startswith('exec-timeout'):
            timeout_values = line.split()[1:]  # Get the timeout values (minutes and seconds)
            if len(timeout_values) == 2:
                minutes, seconds = map(int, timeout_values)
                if minutes <= 9:
                    return True
    
    # Return False if 'exec-timeout' is not found or not within the desired range
    return False

def main():
    connection = connect_to_router()
    enable_mode(connection)  # Enter enable mode

    if verify_privilege_level(connection):
        print("All non-excluded users are set to privilege level 1.")
    else:
        print("There are non-excluded users not set to privilege level 1.")

    if verify_ssh_transport(connection):
        print("SSH is the only transport method for VTY logins.")
    else:
        print("Non-SSH transport methods are configured for VTY logins or 'transport input ssh' is missing.")
    
    if verify_aux_exec_disabled(connection):
        print("The EXEC process for the AUX port is disabled.")
    else:
        print("The EXEC process for the AUX port is not disabled.")

    if verify_acl_entries(connection, vty_acl_number, required_entries):
        print(f"ACL {vty_acl_number} contains the required entries: {', '.join(required_entries)}.")
    else:
        print(f"ACL {vty_acl_number} is missing one or more required entries: {', '.join(required_entries)}.")

    if verify_acl_set(connection, line_start, line_end,vty_acl_number):
        print(f"Access-class is set for VTY lines {line_start} to {line_end}.")
    else:
        print(f"Access-class is not set for VTY lines {line_start} to {line_end}.")

    if verify_timeout_configured(connection):
        print("A timeout of 10 minutes or less is configured for the AUX line.")
    else:
        print("Timeout configuration is missing or exceeds 10 minutes for the AUX line.")

    connection.disconnect()

if __name__ == "__main__":
    main()
