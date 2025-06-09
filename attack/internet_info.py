import socket
import psutil
import wmi
# 自動取得本機IP
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 這個IP不需要真的連上，只是用來取得本機IP
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# 自動取得所有網卡名稱
def get_interfaces():
    return list(psutil.net_if_addrs().keys())

def get_interface_by_ip(ip):
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == ip:
                return iface
    return None

def get_interface_description(iface_name):
    c = wmi.WMI()
    for nic in c.Win32_NetworkAdapter():
        if nic.NetConnectionID == iface_name:
            return nic.Name
    return None


my_IP = get_my_ip()
iface_name = get_interface_by_ip(my_IP)
iface_desc = get_interface_description(iface_name)

if __name__ == "__main__":
    print(f"本機IP: {my_IP}")
    print(f"目前使用的介面名稱: {iface_name}")
    print(f"目前使用的介面描述: {iface_desc}")