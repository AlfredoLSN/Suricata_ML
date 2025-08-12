from extract_flows import follow_flows
import joblib
import numpy as np
import warnings
import sys 
import requests

warnings.filterwarnings("ignore")
#Caminho onde é  salvo os logs do suricata
eve_log_path = '/var/log/suricata/eve.json'

randomForest = joblib.load("modelo/random_forest_model.joblib")
scaler = joblib.load("modelo/minmax_scaler.joblib")

# Telegram config
TELEGRAM_TOKEN = '8401232737:AAFeQLDg1ceRNCL1VLM1gAyremsG1zq6-xE'
TELEGRAM_CHAT_ID = '-1002368384088'



def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"Erro ao enviar mensagem para o Telegram: {e}")

#Testando
def meu_callback(flow_data):
    flow_data_values  = np.array(list(flow_data.values())).reshape(1, -1)
    flow_data_scaled = scaler.transform(flow_data_values)
    predict = randomForest.predict(flow_data_scaled)
    if predict == 0:
        flow_data["Classification"] = "BENIGN"
    else:
        flow_data["Classification"] = "MALIGNANT"
        send_telegram_message(f"[ALERTA] Ataque detectado: {flow_data}")

    print(flow_data)
    print("\n")

def print_flow(flow_data):
    teste = flow_data

test_arg = sys.argv[1] if len(sys.argv) > 1 else '0'
follow_flows(eve_log_path, meu_callback, test=test_arg)
