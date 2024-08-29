import subprocess

def run_command(command):
    """Helper function to run a command in the terminal."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
    else:
        print(f"Success: {result.stdout}")

# 1. Generate Root CA Private Key
def generate_root_ca_private_key(ca_password, key_file="rootCA.key"):
    command = f"openssl genpkey -algorithm RSA -out {key_file} -aes256 -pass pass:{ca_password}"
    run_command(command)

# 2. Generate Root CA Certificate
def generate_root_ca_certificate(ca_password, cert_file="rootCA.pem"):
    command = f"openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out {cert_file} -passin pass:{ca_password}"
    run_command(command)

# 3. Generate Server/Device Private Key
def generate_private_key(password, key_file="private.key"):
    command = f"openssl genpkey -algorithm RSA -out {key_file} -aes256 -pass pass:{password}"
    run_command(command)

# 4. Create CSR for Server/Device
def create_csr(password, csr_file="certificate.csr", key_file="private.key"):
    command = f"openssl req -new -key {key_file} -out {csr_file} -passin pass:{password}"
    run_command(command)

# 5. Generate Server/Device Certificate signed by CA
def generate_certificate(ca_password, cert_file="certificate.pem", csr_file="certificate.csr"):
    command = f"openssl x509 -req -in {csr_file} -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out {cert_file} -days 500 -sha256 -passin pass:{ca_password}"
    run_command(command)

if __name__ == "__main__":
    ca_password = "yourcapassword"  # Change as needed
    private_password = "yourpassword"  # Change as needed

    print("Generating Root CA Private Key...")
    generate_root_ca_private_key(ca_password)

    print("Generating Root CA Certificate...")
    generate_root_ca_certificate(ca_password)

    print("Generating Server/Device Private Key...")
    generate_private_key(private_password)

    print("Creating CSR for Server/Device...")
    create_csr(private_password)

    print("Generating Server/Device Certificate signed by CA...")
    generate_certificate(ca_password)

    print("Certificates and keys have been generated.")
