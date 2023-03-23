#!/usr/bin/python3
import socket
import struct

def test_sigred_vulnerability(server_ip):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Craft a DNS query for a non-existent domain
    query_id = 0x1234
    dns_query = struct.pack(
        ">HBBHHBB",
        query_id,  # Query ID
        0x01,      # Flags (Standard Query)
        0x00,      # Question count
        0x01,      # Answer record count
        0x00,      # Authority record count
        0x00,      # Additional record count
    )
    
    # Add a large response to trigger SIGRed vulnerability check
    dns_query += b'\x06' + b'a' * 0xFF + b'\x00\x20\x00\x01'
    
    # Send the DNS query to the target server
    sock.sendto(dns_query, (server_ip, 53))
    
    # Receive the DNS response
    data, _ = sock.recvfrom(4096)
    
    # Extract the response flags and error code
    _, response_flags, _, _, _, _ = struct.unpack(">HBBHHBB", data[:8])
    error_code = response_flags & 0xF

    # Check if the error code is 0x1 (Format Error)
    if error_code == 0x1:
        print(f"{server_ip} is likely patched against SIGRed (CVE-2020-1350)")
    else:
        print(f"{server_ip} might be vulnerable to SIGRed (CVE-2020-1350)")

if __name__ == "__main__":
    # Replace 'your_server_ip' with the IP address of your Windows DNS server
    test_sigred_vulnerability("your_server_ip")

"""
Replace "your_server_ip" with the IP address of the DNS server you want to test. This script sends a crafted DNS query and checks the error code in the response. If the server is patched against SIGRed, it should return a Format Error (error code 0x1). If not, the server might be vulnerable, and you should apply the necessary patches and follow security best practices to mitigate the risk.

"""
