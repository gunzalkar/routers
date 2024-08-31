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

def main():
    connection = connect_to_router()
    if verify_privilege_level(connection):
        print("All users are set to privilege level 1.")
    else:
        print("There are users not set to privilege level 1.")
    connection.disconnect()

if __name__ == "__main__":
    main()
