import paramiko

def connect_to_router(hostname, port, username, password):
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    
    # Automatically add the router's host key (you may want to handle this more securely)
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connect to the router
        ssh_client.connect(hostname, port=port, username=username, password=password)
        
        # Print a success message
        print("Connected to the router successfully!")
        
        # Run a command (optional, for testing)
        stdin, stdout, stderr = ssh_client.exec_command('show version')
        print("Command output:", stdout.read().decode())
    
    except paramiko.AuthenticationException:
        print("Authentication failed, please verify your credentials")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Close the connection
        ssh_client.close()

# Example usage
hostname = '192.168.1.10'  # Replace with your router's IP address
port = 22  # Default SSH port
username = 'admin'  # Replace with your username
password = 'password'  # Replace with your password

connect_to_router(hostname, port, username, password)
