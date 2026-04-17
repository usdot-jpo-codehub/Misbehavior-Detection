import socket
import time
import os
import ast
from test_faultybsm import read_file



# # Currently set to oim-dev environment's ODE
# UDP_IP = "172.17.0.1"#os.getenv('DOCKER_HOST_IP')
# UDP_PORT = 46800
# MESSAGE = "0022e12d18466c65c1493800000e00e4616183e85a8f0100c000038081bc001480b8494c4c950cd8cde6e9651116579f22a424dd78fffff00761e4fd7eb7d07f7fff80005f11d1020214c1c0ffc7c016aff4017a0ff65403b0fd204c20ffccc04f8fe40c420ffe6404cefe60e9a10133408fcfde1438103ab4138f00e1eec1048ec160103e237410445c171104e26bc103dc4154305c2c84103b1c1c8f0a82f42103f34262d1123198103dac25fb12034ce10381c259f12038ca103574251b10e3b2210324c23ad0f23d8efffe0000209340d10000004264bf00"

# print("UDP target IP:", UDP_IP)
# print("UDP target port:", UDP_PORT)
# print("message:", bytes.fromhex(MESSAGE))

# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP

# while True:
#   time.sleep(5)
#   print("sending BSM every 5 second")
#   sent = sock.sendto(bytes.fromhex(MESSAGE), (UDP_IP, UDP_PORT))
#   print(f"Sent {sent} bytes")
# Try these in order
UDP_IPS = ["127.0.0.1"]
UDP_PORT = 46800
FILE = "/home/m34361/ode-stack/mbd-client/faulty-bsm-generator/data/example_IEEE/bsmLogDuringEvent_1582235136_563_0320.bin_no_header"

MESSAGE = read_file(FILE)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for UDP_IP in UDP_IPS:
    print(f"\nTrying UDP target IP: {UDP_IP}:{UDP_PORT}")
    try:
        sent = sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
        print(f"✓ Sent {sent} bytes successfully to {UDP_IP}")
        
        # Now check ODE logs immediately
        print("Check ODE logs now with: docker compose -f jpo-ode/docker-compose.yml logs --tail 20 ode")
        time.sleep(2)
    except Exception as e:
        print(f"✗ Error sending to {UDP_IP}: {e}")