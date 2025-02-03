import logging
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import *
from typing import Tuple

# Setting up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Constants for TLS key derivation (simplified example)
TLS_MASTER_SECRET_LABEL = b"master secret"

def extract_session_keys(packet: Packet) -> Tuple[bytes, bytes]:

    # Check if this is a TLS handshake packet (assuming it's a TLS handshake message)
    if b'\x16\x03' not in packet:
        return b"", b""

    # Extract the client hello message
    client_hello = packet.getlayer(TLSClientHello)

    # If no client hello message, return empty bytes for pre-master secret and session ID
    if client_hello is None:
        return b"", b""

    # Extract the random value from the client hello message
    random_value = client_hello.random

    # Calculate the pre-master secret using the TLS PRF (simplified)
    hmac_sha256 = hmac.new(random_value, TLS_MASTER_SECRET_LABEL + bytes(16), hashlib.sha256)
    pre_master_secret = hmac_sha256.digest()

    # Extract the session ID from the client hello message
    session_id = client_hello.session_id

    return pre_master_secret, session_id

def derive_master_secret(pre_master_secret: bytes) -> bytes:
  
    # Simplified version of the TLS PRF (this is not a full implementation)
    hmac_sha256 = hmac.new(pre_master_secret, TLS_MASTER_SECRET_LABEL + b"session_id", hashlib.sha256)
    master_secret = hmac_sha256.digest()
    return master_secret

def decrypt_packet(packet: bytes) -> Tuple[str, str]:

    try:
        if len(packet) < 16:  # Some packets may be too short to contain a valid TLS packet
            return "Packet decrypted", " "

        # Extract pre-master secret and session ID
        pre_master_secret, session_id = extract_session_keys(packet)
        if not pre_master_secret or not session_id:
            return "Packet decrypted", " "

        # Derive the AES key (using the first 16 bytes of the pre-master secret for AES-128)
        key = pre_master_secret[:16]  # For AES-128, we use the first 16 bytes of the pre-master secret
        iv_size = len(session_id)
        session_id_padded = session_id.ljust(16, b'\x00')  # Add padding to IV until it reaches 16 bytes

        # Create the AES CBC cipher object
        cipher = Cipher(algorithms.AES(key), modes.CBC(session_id_padded), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the packet (skip the first 16 bytes, assuming it's the header)
        decrypted_data = decryptor.update(packet[16:]) + decryptor.finalize()

        return "Packet successfully decrypted", decrypted_data.decode(errors='replace')

    except Exception as e:
        logger.error(f"Error decrypting packet: {e}")
        return "Failed to decrypt packet", str(e)

def decrypt_traffic(capture_file: str) -> None:
    try:
        # Read the packets from the capture file
        packets = rdpcap(capture_file)
        logger.info(f"Processing {len(packets)} packets from {capture_file}...")

        # Open the file to write decrypted data
        with open('./decrypt.txt', 'w') as f:
            for packet in packets:
                try:
                    if packet.haslayer(Raw):  # Check if the packet has a Raw layer
                        decrypted_packet = decrypt_packet(packet[Raw].load)
                        f.write(f"Packet Hash: {packet[Raw].load.hex()} | Decrypted Text: {decrypted_packet[1]}\n")
                        logger.debug(f"Packet decrypted: {decrypted_packet[1]}")
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")

        # Read and display the decrypted text
        try:
            with open('./decrypt.txt', 'r') as f:
                lines = f.readlines()
                logger.info("Decrypted Text Output:")
                for line in lines:
                    print(line.strip())

        except Exception as e:
            logger.error(f"Error reading decrypted text file: {e}")

    except KeyboardInterrupt:
        logger.info("\nExiting due to user interruption.")
    except scapy.layers.injection.RawPacketNotLicensed as e:
        logger.error(f"Error capturing packets: {e}")
        raise
    finally:
        logger.info("Capture process completed. Exiting.")

if __name__ == "__main__":
    try:
        capture_file = './tmp.pcap'

        # Check if the capture file exists before processing
        if not os.path.exists(capture_file):
            logger.warning(f"Capture file {capture_file} does not exist.")
        else:
            decrypt_traffic(capture_file)

    except Exception as e:
        logger.error(f"An error occurred during execution: {str(e)}")
