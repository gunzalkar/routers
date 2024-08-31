from netmiko import ConnectHandler #type:ignore
import logging
import re
# Enable logging for debugging
logging.basicConfig(filename='netmiko_debug.log', level=logging.DEBUG)

def connect_to_router():
    device = {
        'device_type': 'cisco_ios',
        'host': '192.168.1.1',
        'username': 'super',
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

def verify_access_list_defined(connection, access_list_identifier):
    command = f'show ip access-list {access_list_identifier}'
    output = connection.send_command(command)
    
    # Print the command output for debugging
    print(output)
    list = """10 deny ip 10.0.0.0 0.255.255.255 any log
    20 deny ip 172.16.0.0 0.15.255.255 any log
    30 deny ip 192.168.0.0 0.0.255.255 any log
    40 deny ip 127.0.0.0 0.255.255.255 any log
    50 deny ip 0.0.0.0 0.255.255.255 any log
    60 deny ip 192.0.2.0 0.0.0.255 any log
    70 deny ip 169.254.0.0 0.0.255.255 any log
    80 deny ip 224.0.0.0 31.255.255.255 any log
    90 deny ip host 255.255.255.255 any log
    100 permit ip any any log"""
    # Check if any access-list definitions are present in the output
    if output == list:
        return True  # Access-list definitions are present
    return False

def main():
    connection = connect_to_router()
    enable_mode(connection)  # Enter enable mode

    access_list_identifier = '122'  # Replace with the actual access-list number or name
    if verify_access_list_defined(connection, access_list_identifier):
        print(f"Access-list definitions for '{access_list_identifier}' are present.")
    else:
        print(f"No access-list definitions found for '{access_list_identifier}'.")
    connection.disconnect()

if __name__ == "__main__":
    main()
