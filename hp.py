import paramiko

def connect_and_run_command(hostname, port, username, password):
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    
    # Automatically add the router's host key (you may want to handle this more securely)
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connect to the router
        ssh_client.connect(hostname, port=port, username=username, password=password)
        print("Connected to the router successfully!")

        # Start an interactive session
        shell = ssh_client.invoke_shell()
        
        # Send commands
        shell.send('system-view\n')
        shell.send('display current-configuration | include telnet\n')
        shell.send('quit\n')
        
        # Wait for the commands to execute and retrieve output
        import time
        time.sleep(2)  # Adjust time as needed for command execution
        
        output = shell.recv(65535).decode()  # Adjust buffer size as needed
        
        # Print output
        print("Command output:\n", output)
    
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

connect_and_run_command(hostname, port, username, password)
