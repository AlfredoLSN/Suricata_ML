import json
import pandas as pd
import time
from datetime import datetime


flow_data = []
datetime


def follow(file):
    file.seek(0,2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1) 
            continue
        yield line


def extractDuration(start, end):
    startDate = datetime.fromisoformat(start)
    endDate = datetime.fromisoformat(end)
    duration = endDate - startDate
    return duration.total_seconds() * 1_000_000

def process_line(line):
                #"src_ip": event.get("src_ip"),
                #"src_port": event.get("src_port"),
                #"dest_ip": event.get("dest_ip"),
                #"protocol": event.get("proto"),
                #"dest_port": event.get("dest_port"),
                #"total_fwd_packets": flow.get("pkts_toserver"),
                #"total_bwd_packets": flow.get("pkts_toclient"),
                #"flow_packets_per_sec": 
                #"total_fwd_bytes": flow.get("bytes_toserver"),
                #"total_bwd_bytes": flow.get("bytes_toclient"),
                #"duration": duration.microseconds
    try:
        event = json.loads(line)
        if event.get("event_type") == "flow":
            flow = event.get("flow", {})
            features = {}

            #dest_port     
            features["Destination Port"] = event.get("dest_port")

            #total_fwd_packets (pkts_toserver)   
            features["Total Fwd Packets"] = flow.get("pkts_toserver")

            #total_bwd_packets (pkts_toclient)
            features["Total Backward Packets"] = flow.get("pkts_toclient")

            
            #total_fwd_bytes (bytes_toserver)
            features["Total Length of Fwd Packets"] = flow.get("bytes_toserver")
            
            #total_bwd_bytes (bytes_toclient)
            features["Total Length of Bwd Packets"] = flow.get("bytes_toclient")


            #duration   (end - start)
            features["Flow Duration"] = extractDuration(flow.get("start"), flow.get("end"))
            
            
            duration = max(features["Flow Duration"] / 1000000, 0.001)
            #flow_packets_per_sec
            total_packets = features["Total Fwd Packets"] + features["Total Backward Packets"]
            features["Flow Packets/s"] = total_packets / duration

            #flow_bytes_per_sec 
            total_bytes = features["Total Length of Fwd Packets"] + features["Total Length of Bwd Packets"]
            features["Flow Bytes/s"] = total_bytes / duration
            
            #down_up_ratio
            features["Down/Up Ratio"] = features["Total Length of Bwd Packets"] / features["Total Length of Fwd Packets"]

           
            return features
        
    except json.JSONDecodeError:
        return None


flow_data_test_values = [
    [80, 3, 7, 26, 11607, 1293792, 7.729218, 8991.398927, 2],
    [80, 4, 0, 24, 0, 4421382, 0.9046945, 5.428167, 0],
    [80, 3, 6, 26, 11601, 1083538, 8.306123, 10730.59, 2],
    [80, 8, 4, 56, 11601, 80034360, 0.1499356, 145.6499, 0],
    #[80, 3, 6, 26, 11607, 642654, 14.00443, 18101.50, 2],
    #[80, 8, 5, 56, 11601, 79731718, 0.1630468, 146.2028, 0],
    #[80, 3, 6, 26, 11607, 306157, 29.39668, 37996.84, 2],
    #[80, 8, 4, 56, 11607, 79780371, 0.1504129, 146.1888, 0],
    #[80, 3, 5, 26, 11607, 682575, 11.72032, 17042.82, 1],
    #[80, 8, 6, 56, 11607, 79098660, 0.1769941, 147.4488, 0],
    #[80, 3, 6, 26, 11607, 670265, 13.42752, 17355.82, 2],
    #[80, 7, 6, 50, 11607, 79099557, 0.1643498, 147.3712, 0],
    #[80, 3, 6, 26, 11607, 1270646, 7.083011, 9155.186, 2],
    #[80, 8, 6, 56, 11601, 77818286, 0.1799063, 149.7977, 0],
    #[80, 3, 6, 26, 11607, 1281820, 7.021267, 9075.377, 2],
    #[80, 8, 6, 56, 11607, 77807512, 0.1799312, 149.8956, 0],
    #[80, 3, 6, 26, 11601, 13724, 655.7855, 847202.0, 2],
    #[80, 4, 0, 24, 0, 10453138, 0.3826602, 2.295961, 0],
    #[80, 3, 6, 26, 11607, 1632, 5514.706, 7128064.0, 2],
    #[80, 5, 0, 30, 0, 10440135, 0.4789210, 2.873526, 0],
    #[80, 3, 6, 26, 11607, 1604, 5610.973, 7252494.0, 2],
    #[80, 4, 0, 24, 0, 10426959, 0.3836210, 2.301726, 0],
    #[80, 3, 6, 26, 11607, 1533, 5870.841, 7588389.0, 2],
    #[80, 4, 0, 24, 0, 10417544, 0.3839677, 2.303806, 0]
]

flow_data_test_keys = [
    "Destination Port", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Duration", "Flow Packets/s", "Flow Bytes/s", "Down/Up Ratio"
]


flow_data_test = [
    dict(zip(flow_data_test_keys, values)) for values in flow_data_test_values
]

def follow_flows(eve_log_path, on_flow, test = '0'):
    if test == '0':
        with open(eve_log_path, 'r') as f:
            for line in follow(f):
                flow_data = process_line(line)
                if flow_data:
                    on_flow(flow_data)
    else:
        for _ in flow_data_test:
            on_flow(_)

