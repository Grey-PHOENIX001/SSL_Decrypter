# SSL_Decrypter
An Python based SSL Decryption and Data Extraction tool

# Overview:

The SSL Decryptor Tool is a two-part project designed to capture encrypted SSL/TLS traffic, extract the decryption key from the TCP handshake, and then decrypt the captured packets. The tool consists of two separate files:

# Packet Capturer
This file captures SSL/TLS traffic from a specified network interface using tshark (a command-line version of Wireshark) and saves it as a PCAP file.
Decryptor: This file reads the PCAP file, extracts the TCP handshake packets, uses the public key obtained to establish an SSL/TLS connection, and then decrypts the captured packets.

# Key Features

Captures encrypted SSL/TLS traffic from a network interface
Saves the captured traffic as a PCAP file
Extracts the decryption key from the TCP handshake
Decrypts the captured packets using the extracted public key

# Benefits:
Allows for analysis of previously encrypted network traffic
Provides insight into secure communication protocols used by online services
Can be used for educational purposes or to identify potential security vulnerabilities

# Note that this project requires knowledge of network protocol analysis, SSL/TLS encryption, and Python programming. Additionally, please ensure that you have the necessary permissions to capture network traffic in your environment.

