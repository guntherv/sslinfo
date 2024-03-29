import sys
import ssl
import socket
import OpenSSL.crypto as crypto
from datetime import datetime
import csv
import json
from colorama import init, Fore
import os

# Initialize colorama
init()

def check_output_file(output_file):
    """
    Check if the output file already exists.
    """
    if os.path.exists(output_file):
        raise FileExistsError("Output file already exists. Please choose a different file name.")

def get_ssl_info(domain, output_file=None, output_format="screen"):
    try:
        # Establish connection to the domain over SSL/TLS
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((domain, 443))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        s = context.wrap_socket(s, server_hostname=domain)
        
        # Retrieve the server's certificate
        cert = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
        
        # Prepare certificate data
        common_name = x509.get_subject().CN
        organization = x509.get_subject().O if x509.get_subject().O else "None"
        organizational_unit = x509.get_subject().OU if x509.get_subject().OU else "None"
        serial_number = '{0:x}'.format(int(x509.get_serial_number()))
        valid_from = datetime.strptime(x509.get_notBefore().decode(), "%Y%m%d%H%M%SZ").strftime("%Y-%m-%d %H:%M:%S")
        valid_until = datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ").strftime("%Y-%m-%d %H:%M:%S")
        issuer_common_name = x509.get_issuer().CN
        issuer_organization = x509.get_issuer().O if x509.get_issuer().O else "None"

        # Output format
        if output_format.lower() == "csv":
            # Append certificate data to CSV
            writer = csv.writer(output_file)
            writer.writerow([domain, common_name, organization, organizational_unit, serial_number, valid_from, valid_until, issuer_common_name, issuer_organization])
            print("SSL certificate information for", Fore.GREEN + domain, "appended to output file")
        elif output_format.lower() == "json":
            # Write certificate data to JSON
            data = {
                "Domain": domain,
                "Common Name": common_name,
                "Organization": organization,
                "Organizational Unit": organizational_unit,
                "Serial Number": serial_number,
                "Valid From": valid_from,
                "Valid Until": valid_until,
                "Issuer Common Name": issuer_common_name,
                "Issuer Organization": issuer_organization
            }
            json.dump(data, output_file, indent=4)
            output_file.write('\n')
            print("SSL certificate information for", Fore.GREEN + domain, "appended to output file")
        elif output_format.lower() == "screen":
            # Print certificate data to screen with color
            print(Fore.YELLOW + "Domain:", domain)
            print(Fore.YELLOW + "Common Name:", common_name)
            print(Fore.YELLOW + "Organization:", organization)
            print(Fore.YELLOW + "Organizational Unit:", organizational_unit)
            print(Fore.YELLOW + "Serial Number:", serial_number)
            print(Fore.YELLOW + "Valid From:", valid_from)
            print(Fore.YELLOW + "Valid Until:", valid_until)
            print(Fore.YELLOW + "Issuer Common Name:", issuer_common_name)
            print(Fore.YELLOW + "Issuer Organization:", issuer_organization)
        else:
            print("Invalid output format. Please choose 'csv', 'json', or 'screen'.")

        # Close the socket connection
        s.close()
        
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <host_or_input_file> [output_format] [output_file]")
        sys.exit(1)
    
    input_param = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else "screen"
    output_file_name = sys.argv[3] if len(sys.argv) > 3 else None
    
    output_file = None
    if output_file_name:
        check_output_file(output_file_name)
        output_file = open(output_file_name, "a", newline='')
    
    if input_param.endswith(".txt"):
        with open(input_param, "r") as file:
            domains = file.read().splitlines()

        for domain in domains:
            get_ssl_info(domain, output_file, output_format)
    else:
        get_ssl_info(input_param, output_file, output_format)
    
    if output_file:
        output_file.close()
