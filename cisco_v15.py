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
    command = 'show run | include privilege'
    output = connection.send_command(command)
    lines = output.splitlines()
    
    # Filter lines that start with 'username' and include 'privilege'
    privilege_lines = [line.strip() for line in lines if line.strip().startswith('username') and 'privilege' in line]

    # Check if all 'privilege' lines are set to 1
    return all('privilege 1' in line for line in privilege_lines)


def verify_ssh_transport(connection):
    command = 'show run | sec vty'
    output = connection.send_command(command)
    lines = output.splitlines()

    transport_input_lines = [line.strip() for line in lines if line.strip().startswith('transport input')]
    
    if not transport_input_lines:
        return False  # No transport input lines found
    
    return len(transport_input_lines) == 1 and transport_input_lines[0] == 'transport input ssh'

def main():
    connection = connect_to_router()
    enable_mode(connection)  # Enter enable mode

    if verify_privilege_level(connection):
        print("All users are set to privilege level 1.")
    else:
        print("There are users not set to privilege level 1.")

    if verify_ssh_transport(connection):
        print("SSH is the only transport method for VTY logins.")
    else:
        print("Non-SSH transport methods are configured for VTY logins or 'transport input ssh' is missing.")

    connection.disconnect()

if __name__ == "__main__":
    main()
