import paramiko

def connect_to_router(host, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password, look_for_keys=False, allow_agent=False)
        return client
    except Exception as e:
        print(f"Failed to connect to {host}: {e}")
        return None

def execute_command(client, command, timeout=10):
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode()
        return output.strip()
    except Exception as e:
        print(f"Command execution failed: {e}")
        return None

def check_digital_certificate_management(client):
    print("Checking Digital Certificate Management...")
    certificate_info = execute_command(client, "display pki certificate")
    if certificate_info:
        print(f"Certificate Info: {certificate_info}")
    else:
        print("Failed to retrieve certificate information.")

def main():
    host = "192.168.1.1"
    username = "admin"
    password = "password"

    client = connect_to_router(host, username, password)
    if client:
        check_digital_certificate_management(client)
        client.close()
    else:
        print("Could not establish a connection to the router.")

if __name__ == "__main__":
    main()
