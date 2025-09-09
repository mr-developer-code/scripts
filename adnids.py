from sklearn.preprocessing import MinMaxScaler
from keras.models import load_model
from keras.utils import to_categorical
import pandas as pd
from utils_node import *
import os
import numpy as np
import time
import joblib

from ckks_scheme_owner import context
import tenseal as ts
import hashlib
import requests
import json
import tensorflow as tf
import gzip

FEATURES = [
    "IPV4_SRC_ADDR","L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT",
    "PROTOCOL", "L7_PROTO", "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS", "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS", "DURATION_IN", "DURATION_OUT", "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN", "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES", "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS", "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT", "NUM_PKTS_UP_TO_128_BYTES",
    "NUM_PKTS_128_TO_256_BYTES", "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES", "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT", "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE", "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
    "FIRST_SWITCHED", "LAST_SWITCHED"
]

## url
# server_url_encrypt = "http://127.0.0.1:4313/node/encrypt-parameter"
server_url_encrypt = "https://serverpost.huzaifa.cloud/node/encrypt-parameter"
# test_data = pd.read_csv("/sgi/sur_files/NF-UNSW-NB15-v2.csv")
KEY_FILE = "/sgi/sur_files/secret_key.bin"

## initialization
file_to_read = "/sgi/var/log/suricata/features.json"
condition_fed = False
re_transmit = False

## key generation
secret_key = context.serialize(save_secret_key = True)
with open(KEY_FILE, "wb") as f:
    f.write(secret_key)

context.make_context_public()
public_key = context.serialize()

    ## keys
client_context = ts.context_from(secret_key)
server_context = ts.context_from(public_key)

## check extracted features file
while True:
    if os.path.exists(file_to_read):
        print("[adnids] File Found")
        break
    print("[adnids] File not exist!")
    time.sleep(5)

while True:
    ## loading
    lm_model = load_model("adnids_model.h5")

    ## ADNIDS
    df_data = extract_feature_from_log(file_to_read)
    if not df_data.empty:
        x = df_data.copy()
        x_dashboard = df_data[FEATURES].copy()

        x_prediction = x_dashboard.drop(["IPV4_SRC_ADDR","L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT", "FIRST_SWITCHED", "LAST_SWITCHED"], axis=1)
        # print("\t",x_prediction.columns)
        # print("\t",x_prediction.shape)

        ## noramlization
        print("[adnids] normalization")
        for col in x_prediction.columns:
            x_prediction.loc[:, col] = pd.to_numeric(x_prediction[col], errors='coerce').fillna(0)

        scaler = joblib.load('sur_files/scaler.pkl')
        x_scaled = scaler.transform(x_prediction)

        ## model prediction
        print("[adnids] prediction")
        probabilities = lm_model.predict(x_scaled, batch_size=32)

        ## save model prediction
        prediction = np.argmax(probabilities, axis=1)
        x_dashboard["predictions"] = prediction
        x_dashboard.to_json("/sgi/var/log/suricata/adnids_alert.json", orient="records", lines=True)
        
        ## hash
        before_hash = get_model_weights_hash(lm_model)

        print("[adnids] training")
        confidences = np.max(probabilities, axis=1)
        print(confidences[:5])
        high_conf_mask = confidences > 0.90
        x_high_conf = x_scaled[high_conf_mask]
        y_high_conf = prediction[high_conf_mask]
        if len(x_high_conf) > 0:
            y_one_hot = to_categorical(y_high_conf, 21)
            lm_model.fit(x_high_conf, y_one_hot, epochs=1, batch_size=32)

        #testing
        # print("testing")
        # x_test, y_test = dataset_analysis(test_data)
        # loss, acc = lm_model.evaluate(x_test, y_test, batch_size=32)
        # print(f"\t Model Accuracy: {acc:.4%}, Model Loss: {loss:.4f}")

        ## hash
        after_hash = get_model_weights_hash(lm_model)

        ## rule generation
        print("[adnids] rules")

        x["predictions"] = prediction
        alert_features = x[x['predictions'] != 2]
        alert_features.to_json("/sgi/var/log/suricata/alert_features.json", orient="records", lines=True)
        res = rule_generator("/sgi/var/log/suricata/alert_features.json", "/sgi/var/lib/suricata/rules/local.rules")
        time.sleep(3)
        if res > 0:
            run_command("sudo /bin/systemctl --system restart suricata-pfring")

        if before_hash != after_hash:
            print("[adnids] hashes are not same")
            condition_fed = True

    ## federated learning
    if condition_fed or re_transmit:
        if re_transmit:
            with open("/sgi/sur_files/model_parameter_updated_by_server.txt", "w") as f:
                f.write("False")
                
        gm_model = load_model("adnids_model.h5")
        lm_model = apply_regularization(lm_model, gm_model, 0.3)

        lm_enc_weights, parameters_shapes = encrypt_parameter(lm_model, client_context)
        gm_enc_weights, parameters_shapes = encrypt_parameter(gm_model, client_context)

        ## serialization
        print("[adnids] serialization")
        node_weight_ser = [w.serialize() for w in lm_enc_weights]
        global_weight_ser = [w.serialize() for w in gm_enc_weights]

        node_weight_ser_hex = [w_bytes.hex() for w_bytes in node_weight_ser]
        global_weight_ser_hex = [w_bytes.hex() for w_bytes in global_weight_ser]
        
        all_node_weights_bytes = b"".join(node_weight_ser)
        all_global_weights_bytes = b"".join(global_weight_ser)

        shapes_bytes = json.dumps(parameters_shapes).encode("utf-8")
        
        server_context_ser = server_context.serialize()

        ## hashing
        print("[adnids] hashing")
        data_hash = hashlib.sha256(all_node_weights_bytes + all_global_weights_bytes + server_context_ser + shapes_bytes).hexdigest()

        data_enc = {
            'enc_param_node': node_weight_ser_hex,
            'enc_param_global': global_weight_ser_hex,
            'context': server_context_ser.hex(),
            'shapes': parameters_shapes,
            'hash': data_hash
        }

        ## compressing
        print("[adnids] compressing")
        payload = json.dumps(data_enc).encode("utf-8")
        compressed = gzip.compress(payload)

        headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "gzip"
        }

        ## communication with server
        while True:
            try:
                print("[adnids] sending")
                # response_server = requests.post(server_url_encrypt, json=data_enc)
                response_server = requests.post(server_url_encrypt, data=compressed, headers = headers)
                print("[adnids] sending done")
                reply = response_server.json()
            except Exception:
                continue

            if "Server is busy" in reply["message"]:
                time.sleep(3)
                break
            elif "No JSON data received" in reply["message"]:
                time.sleep(3)
                continue
            elif "Missing required field" in reply["message"]:
                time.sleep(3)
                continue
            elif "Hash Not Matched" in reply["message"]:
                time.sleep(3)
                continue
            elif "Proof verification failed" in reply["message"]:
                time.sleep(3)
                continue
            elif "Error processing request" in reply["message"]:
                print("[adnids] Issues on server end")
                break

            if "aggregated weights are ready" in reply['message']:
                # response = requests.get(server_url_aggregated)
                received = reply

                print("[adnids] received")
                if isinstance(received["weights"], list):
                    avg_weight_ser_hex = received["weights"]
                    avg_weight_ser_bytes = [bytes.fromhex(w) for w in avg_weight_ser_hex]
                else:
                    avg_weight_ser_bytes = [bytes.fromhex(received["weights"])]

                received_parameters_shapes = received['shapes']
                received_parameters = [tuple(s) for s in received_parameters_shapes]

                received_hash = received["hash"]

                ## hashing
                all_avg_weight_ser_bytes = b"".join(avg_weight_ser_bytes)

                weight_hash = hashlib.sha256(all_avg_weight_ser_bytes + shapes_bytes).hexdigest()

                if weight_hash != received_hash:
                    continue

                ## decrypting
                gm_enc_weights = [ts.ckks_vector_from(client_context, w_ser) for w_ser in avg_weight_ser_bytes]
                decrypted_weights = []
                gm_weights = []
                print("[adnids][INFO] Decrypting!")
                for layer in gm_enc_weights:
                    layer.link_context(client_context)
                    decrypted_weights.append(layer.decrypt())
                print("[adnids] \tDone")

                ind = 0
                print("[adnids][INFO] Shaping decrypted parameter!")
                for shape in received_parameters:
                    data = decrypted_weights[ind]
                    gm_weights.append(np.array(data).reshape(shape))
                    ind += 1
                print("[adnids] \tDone")

                with open("/sgi/sur_files/model_parameter_updated_by_server.txt", "r") as f:
                    line = f.readline()
                    if "true" in line.lower():
                        re_transmit = True
                        break
                    print("[adnids] model parameters are not updated by server")

                print("[adnids] setting parameters")
                model = load_model("adnids_model.h5")
                model.set_weights(gm_weights)
                model.save("adnids_model.h5")

                time.sleep(5)
                condition_fed = False
                break

#--------------------------------------------------------------------------------
