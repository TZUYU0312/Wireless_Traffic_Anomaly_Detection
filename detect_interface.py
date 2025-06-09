#偵測任意網路介面的流量的程式
from nfstream import NFStreamer
import queue
import numpy as np
import pandas as pd
import threading
import psutil
import time
import os
import ctypes
import internet_info
from collections import deque,defaultdict
from keras.models import load_model
from sklearn.preprocessing import LabelEncoder
#setting
record_csv_mode=False # 是否要把每筆flow寫入csv檔
detect_mode=True # 是否要偵測攻擊流量
show_flow_message=False # 是否要顯示每筆flow的詳細資訊
collect_duration =2*60*60  # 收集幾秒
target_IP="203.0.113.123"#"172.20.10.15"  #用來標記攻擊的server IP
syn_flood_port=63209 #用來標記syn攻擊的server port
udp_flood_port=63211 #用來標記udp攻擊的server port
rst_flood_port=63212 #用來標記rst攻擊的server port
fin_flood_port=63213 #用來標記fin攻擊的server port
ack_flood_port=63214 #用來標記ack攻擊的server port
idle_timeout_setting=1 # 每筆flow幾秒沒封包就輸出 
inactive_timeout_setting=2 # 每筆flow最長幾秒就輸出
output_file_name = 'interface_flows.csv'  # 輸出檔案名稱
##########################################################


def flow_handler():  # 負責即時處理每筆flow的特徵並進行預測
    while True:
        flow= handler_memory.get()  
        if flow is None:
            return
        #拿掉非數值或僅用來辨別身分的特徵
        feature_dict = {
                            'expiration_id':flow.expiration_id,
                            'protocol': flow.protocol,
                            'bidirectional_duration_ms': flow.bidirectional_duration_ms, 
                            'bidirectional_packets': flow.bidirectional_packets, 
                            'bidirectional_bytes': flow.bidirectional_bytes, 
                            'src2dst_duration_ms': flow.src2dst_duration_ms, 
                            'src2dst_packets': flow.src2dst_packets, 
                            'src2dst_bytes': flow.src2dst_bytes, 
                            'dst2src_duration_ms': flow.dst2src_duration_ms, 
                            'dst2src_packets': flow.dst2src_packets, 
                            'dst2src_bytes': flow.dst2src_bytes, 
                            'bidirectional_min_ps': flow.bidirectional_min_ps,
                            'bidirectional_mean_ps': flow.bidirectional_mean_ps, 
                            'bidirectional_stddev_ps': flow.bidirectional_stddev_ps, 
                            'bidirectional_max_ps': flow.bidirectional_max_ps, 
                            'src2dst_min_ps': flow.src2dst_min_ps, 
                            'src2dst_mean_ps': flow.src2dst_mean_ps, 
                            'src2dst_stddev_ps': flow.src2dst_stddev_ps, 
                            'src2dst_max_ps': flow.src2dst_max_ps, 
                            'dst2src_min_ps': flow.dst2src_min_ps, 
                            'dst2src_mean_ps': flow.dst2src_mean_ps, 
                            'dst2src_stddev_ps':flow.dst2src_stddev_ps, 
                            'dst2src_max_ps': flow.dst2src_max_ps, 
                            'bidirectional_min_piat_ms': flow.bidirectional_min_piat_ms, 
                            'bidirectional_mean_piat_ms': flow.bidirectional_mean_piat_ms, 
                            'bidirectional_stddev_piat_ms': flow.bidirectional_stddev_piat_ms, 
                            'bidirectional_max_piat_ms': flow.bidirectional_max_piat_ms, 
                            'src2dst_min_piat_ms':flow.src2dst_min_piat_ms, 
                            'src2dst_mean_piat_ms': flow.src2dst_mean_piat_ms, 
                            'src2dst_stddev_piat_ms': flow.src2dst_stddev_piat_ms, 
                            'src2dst_max_piat_ms': flow.src2dst_max_piat_ms, 
                            'dst2src_min_piat_ms': flow.dst2src_min_piat_ms, 
                            'dst2src_mean_piat_ms': flow.dst2src_mean_piat_ms, 
                            'dst2src_stddev_piat_ms': flow.dst2src_stddev_piat_ms, 
                            'dst2src_max_piat_ms': flow.dst2src_max_piat_ms, 
                            'bidirectional_syn_packets': flow.bidirectional_syn_packets, 
                            'bidirectional_cwr_packets': flow.bidirectional_cwr_packets, 
                            'bidirectional_ece_packets':  flow.bidirectional_ece_packets, 
                            'bidirectional_urg_packets': flow.bidirectional_urg_packets, 
                            'bidirectional_ack_packets': flow.bidirectional_ack_packets, 
                            'bidirectional_psh_packets': flow.bidirectional_psh_packets, 
                            'bidirectional_rst_packets': flow.bidirectional_rst_packets, 
                            'bidirectional_fin_packets': flow.bidirectional_fin_packets, 
                            'src2dst_syn_packets': flow.src2dst_syn_packets, 
                            'src2dst_cwr_packets': flow.src2dst_cwr_packets, 
                            'src2dst_ece_packets': flow.src2dst_ece_packets, 
                            'src2dst_urg_packets': flow.src2dst_urg_packets, 
                            'src2dst_ack_packets': flow.src2dst_ack_packets, 
                            'src2dst_psh_packets': flow.src2dst_psh_packets, 
                            'src2dst_rst_packets': flow.src2dst_rst_packets, 
                            'src2dst_fin_packets': flow.src2dst_fin_packets, 
                            'dst2src_syn_packets': flow.dst2src_syn_packets, 
                            'dst2src_cwr_packets': flow.dst2src_cwr_packets, 
                            'dst2src_ece_packets': flow.dst2src_ece_packets, 
                            'dst2src_urg_packets': flow.dst2src_urg_packets, 
                            'dst2src_ack_packets': flow.dst2src_ack_packets, 
                            'dst2src_psh_packets': flow.dst2src_psh_packets, 
                            'dst2src_rst_packets': flow.dst2src_rst_packets, 
                            'dst2src_fin_packets': flow.dst2src_fin_packets, 
                            'application_confidence': flow.application_confidence
            }
        X = pd.DataFrame([feature_dict])

        #根據之前的k_best選擇前k重要的特徵，並從X中選出來
        X_selected = k_best.transform(X) 
        #根據scaler來標準化X的特徵
        X_scaled = scaler.transform(X_selected) 

        #因為多筆flow組成一個序列，所以需要一個buffer來存每筆flow的特徵
        flow_handler_buffer.append(X_scaled[0])
        input_seq = np.array(flow_handler_buffer)

        # 如果序列的長度小於window_size，則需要補0至window_size長度
        if len(input_seq) < window_size: 
            pad_width = window_size - len(input_seq)
            input_seq = np.pad(input_seq, ((pad_width, 0), (0, 0)), mode='constant')
        else:
            input_seq = input_seq[-window_size:]

        #因為model的輸入為(幾組序列(batch size), time_steps , features)，所以需要擴展維度
        X_input = np.expand_dims(input_seq, axis=0)  #axis=0代表在最前面增加一個維度
        y_probs = model.predict(X_input)[0]  # shape: (3,)
        pred_class_idx = np.argmax(y_probs)  # 取最大機率的類別 index
        pred_class_name = le.classes_[pred_class_idx]  # 取得類別名稱（需有 le.classes_）
        print("Predicted probability of attack:", y_probs)
        if pred_class_name in [ 'syn_flood', 'udp_flood', 'rst_flood', 'fin_flood', 'ack_flood']:
            time.sleep(1) 
            with process_info_lock:
                tmp_process_info=list(process_info.copy().items())  # 複製目前的process資訊
            # 用最大變化量排序
            def max_change(cpu_deque):
                if len(cpu_deque) ==0:
                    return 0
                elif len(cpu_deque) == 1:
                    return cpu_deque[0]
                return max(cpu_deque) - min(cpu_deque)
            tmp_process_info.sort(key=lambda x: max_change(x[1]), reverse=True)  # 按CPU使用率排序
            
            suspected_processes = [] # 用來儲存可疑的攻擊程序
            for pid, cpu_deque in tmp_process_info[:3]:
                p = psutil.Process(pid)
                name = p.name()
                suspected_processes.append((pid, name))
                
            
            show_popup(f"偵測到{pred_class_name}攻擊！\n 可能的攻擊程序:\n" +
                       "\n".join([f"PID: {pid}, Name: {name}" for pid, name in suspected_processes]))
            
            os._exit(0)

def show_popup(msg="這是彈出視窗！"):
    ctypes.windll.user32.MessageBoxW(0, msg, "提示", 1)

def is_syn_flood(flow): # 判斷是否為被label的SYN Flood 攻擊
    return flow.dst_port == syn_flood_port and flow.dst_ip == target_IP

def is_udp_flood(flow): # 判斷是否為被label的UDP Flood 攻擊
    return flow.dst_port == udp_flood_port and flow.dst_ip == target_IP

def is_rst_flood(flow): # 判斷是否為被label的RST Flood 攻擊
    return flow.dst_port == rst_flood_port and flow.dst_ip == target_IP

def is_fin_flood(flow): # 判斷是否為被label的FIN Flood 攻擊
    return flow.dst_port == fin_flood_port and flow.dst_ip == target_IP

def is_ack_flood(flow): # 判斷是否為被label的ACK Flood 攻擊
    return flow.dst_port == ack_flood_port and flow.dst_ip == target_IP

def save_flows_worker(): #負責把每筆flow寫入csv檔
    global first_write
    while True:
        flow = writer_memory.get()  # 取出 queue（佇列）最前面的一個元素，並且將這個元素從 queue 中移除
        if flow is None:
            break
        flow_info={ #每筆flow的所有特徵
            "id": flow.id,
            "expiration_id": flow.expiration_id,
            "src_ip": flow.src_ip,
            "src_mac": flow.src_mac,
            "src_oui": flow.src_oui,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_mac": flow.dst_mac,
            "dst_oui": flow.dst_oui,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "ip_version": flow.ip_version,
            "vlan_id": flow.vlan_id,
            "tunnel_id": flow.tunnel_id,
            "bidirectional_first_seen_ms": flow.bidirectional_first_seen_ms,
            "bidirectional_last_seen_ms": flow.bidirectional_last_seen_ms,
            "bidirectional_duration_ms": flow.bidirectional_duration_ms,
            "bidirectional_packets": flow.bidirectional_packets,
            "bidirectional_bytes": flow.bidirectional_bytes,
            "src2dst_first_seen_ms": flow.src2dst_first_seen_ms,
            "src2dst_last_seen_ms": flow.src2dst_last_seen_ms,
            "src2dst_duration_ms": flow.src2dst_duration_ms,
            "src2dst_packets": flow.src2dst_packets,
            "src2dst_bytes": flow.src2dst_bytes,
            "dst2src_first_seen_ms": flow.dst2src_first_seen_ms,
            "dst2src_last_seen_ms": flow.dst2src_last_seen_ms,
            "dst2src_duration_ms": flow.dst2src_duration_ms,
            "dst2src_packets": flow.dst2src_packets,
            "dst2src_bytes": flow.dst2src_bytes,
            "bidirectional_min_ps": flow.bidirectional_min_ps,
            "bidirectional_mean_ps": flow.bidirectional_mean_ps,
            "bidirectional_stddev_ps": flow.bidirectional_stddev_ps,
            "bidirectional_max_ps": flow.bidirectional_max_ps,
            "src2dst_min_ps": flow.src2dst_min_ps,
            "src2dst_mean_ps": flow.src2dst_mean_ps,
            "src2dst_stddev_ps": flow.src2dst_stddev_ps,
            "src2dst_max_ps": flow.src2dst_max_ps,
            "dst2src_min_ps": flow.dst2src_min_ps,
            "dst2src_mean_ps": flow.dst2src_mean_ps,
            "dst2src_stddev_ps": flow.dst2src_stddev_ps,
            "dst2src_max_ps": flow.dst2src_max_ps,
            "bidirectional_min_piat_ms": flow.bidirectional_min_piat_ms,
            "bidirectional_mean_piat_ms": flow.bidirectional_mean_piat_ms,
            "bidirectional_stddev_piat_ms": flow.bidirectional_stddev_piat_ms,
            "bidirectional_max_piat_ms": flow.bidirectional_max_piat_ms,
            "src2dst_min_piat_ms": flow.src2dst_min_piat_ms,
            "src2dst_mean_piat_ms": flow.src2dst_mean_piat_ms,
            "src2dst_stddev_piat_ms": flow.src2dst_stddev_piat_ms,
            "src2dst_max_piat_ms": flow.src2dst_max_piat_ms,
            "dst2src_min_piat_ms": flow.dst2src_min_piat_ms,
            "dst2src_mean_piat_ms": flow.dst2src_mean_piat_ms,
            "dst2src_stddev_piat_ms": flow.dst2src_stddev_piat_ms,
            "dst2src_max_piat_ms": flow.dst2src_max_piat_ms,
            "bidirectional_syn_packets": flow.bidirectional_syn_packets,
            "bidirectional_cwr_packets": flow.bidirectional_cwr_packets,
            "bidirectional_ece_packets": flow.bidirectional_ece_packets,
            "bidirectional_urg_packets": flow.bidirectional_urg_packets,
            "bidirectional_ack_packets": flow.bidirectional_ack_packets,
            "bidirectional_psh_packets": flow.bidirectional_psh_packets,
            "bidirectional_rst_packets": flow.bidirectional_rst_packets,
            "bidirectional_fin_packets": flow.bidirectional_fin_packets,
            "src2dst_syn_packets": flow.src2dst_syn_packets,
            "src2dst_cwr_packets": flow.src2dst_cwr_packets,
            "src2dst_ece_packets": flow.src2dst_ece_packets,
            "src2dst_urg_packets": flow.src2dst_urg_packets,
            "src2dst_ack_packets": flow.src2dst_ack_packets,
            "src2dst_psh_packets": flow.src2dst_psh_packets,
            "src2dst_rst_packets": flow.src2dst_rst_packets,
            "src2dst_fin_packets": flow.src2dst_fin_packets,
            "dst2src_syn_packets": flow.dst2src_syn_packets,
            "dst2src_cwr_packets": flow.dst2src_cwr_packets,
            "dst2src_ece_packets": flow.dst2src_ece_packets,
            "dst2src_urg_packets": flow.dst2src_urg_packets,
            "dst2src_ack_packets": flow.dst2src_ack_packets,
            "dst2src_psh_packets": flow.dst2src_psh_packets,
            "dst2src_rst_packets": flow.dst2src_rst_packets,
            "dst2src_fin_packets": flow.dst2src_fin_packets,
            "application_name": flow.application_name,
            "application_category_name": flow.application_category_name,
            "application_is_guessed": flow.application_is_guessed,
            "application_confidence": flow.application_confidence,
            "requested_server_name": flow.requested_server_name,
            "client_fingerprint": flow.client_fingerprint,
            "server_fingerprint": flow.server_fingerprint,
            "user_agent": flow.user_agent,
            "content_type": flow.content_type,
            "Label": "normal"  # 預設標記為正常流量
        }
        if is_syn_flood(flow): 
            flow_info["Label"] = "syn_flood"  # 標記為攻擊流量
        elif is_udp_flood(flow):
            flow_info["Label"] = "udp_flood"  # 標記為攻擊流量
        elif is_rst_flood(flow):
            flow_info["Label"] = "rst_flood" # 標記為攻擊流量
        elif is_fin_flood(flow):
            flow_info["Label"] = "fin_flood" # 標記為攻擊流量
        elif is_ack_flood(flow):
            flow_info["Label"] = "ack_flood" # 標記為攻擊流量
        df = pd.DataFrame([flow_info])
        df.to_csv(output_file_name, mode='a', header=first_write, index=False)
        first_write = False
        writer_memory.task_done()


def process_tracer():
    kernel_num=psutil.cpu_count(logical=True)
    # 先初始化一次
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except Exception:   
            pass
    while True:
        time.sleep(1)  # 取樣間隔，和工作管理員類似
        for p in psutil.process_iter(["pid", "name", "cpu_percent"]):
            try:
                name=p.info["name"]
                pid = p.info["pid"]
                # 過濾系統進程
                if pid in [0, 4, 8]:
                    continue
                cpu = p.info['cpu_percent']/kernel_num
                with process_info_lock:
                    process_info[pid].append(cpu)
            except Exception:
                continue


def timer_worker():
    time.sleep(collect_duration)
    if record_csv_mode:
        writer_memory.put(None)  # 通知寫入執行緒結束
    if detect_mode:
        handler_memory.put(None)  # 通知偵測執行緒結束
    # 強制結束主程式（可視需求調整）
    import os
    os._exit(0)


if __name__ == "__main__":
    # 載入模型和特徵選擇器
    if detect_mode:
        import joblib
        k_best = joblib.load('kbest.save')
        model=load_model('cnn_lstm_model.h5')
        scaler = joblib.load('scaler.save')
        window_size = 10
        flow_handler_buffer = deque(maxlen=window_size)
        os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
        le = joblib.load('label_encoder.save')
    # 取得網路介面資訊
    interface_name=internet_info.iface_desc  # 用終端機的ipconfig -all中的'描述'的內容
    my_IP=internet_info.my_IP  # 這台電腦的IP

    if record_csv_mode:
        first_write = not os.path.exists(output_file_name)# 是否第一次紀錄，如果不是第一次紀錄，會接著上次的結果繼續記錄
        writer_memory=queue.Queue()  # 用來儲存要寫入的資料
        writer_thread = threading.Thread(target=save_flows_worker, daemon=True)
        writer_thread.start()

    if detect_mode:
        process_info_lock = threading.Lock()
        handler_memory = queue.Queue()  # 用來儲存要偵測的資料
        handler_thread= threading.Thread(target=flow_handler, daemon=True)
        handler_thread.start()
        # 啟動一個執行緒來監控系統進程
        process_info = defaultdict(lambda: deque(maxlen=3))  # 用來儲存每個process的資訊
        process_monitor_thread = threading.Thread(target=process_tracer, daemon=True)
        process_monitor_thread.start()

    timer_thread = threading.Thread(target=timer_worker, daemon=True)
    timer_thread.start()



    streamer = NFStreamer(
        source=interface_name,  # 換成你的網卡英文名稱
        statistical_analysis=True,
        decode_tunnels=True,
        idle_timeout=idle_timeout_setting,      # 閒置 5 秒就輸出 flow
        active_timeout=inactive_timeout_setting    # 最長 30 秒就輸出 flow
    )

    for flow in streamer:
        if flow.src_ip==my_IP:
            if record_csv_mode:
                writer_memory.put(flow)
            if detect_mode:
                handler_memory.put(flow) 
            if show_flow_message:
                print(f"Flow: {flow}")
    writer_thread.join()
    handler_thread.join()
    timer_thread.join()
