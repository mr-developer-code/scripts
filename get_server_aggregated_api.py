
import requests
import hashlib
import tenseal as ts
import time
import numpy as np
import json
from keras.models import load_model
from ckks_scheme_owner import context

server_url_aggregated = "https://serverpost.huzaifa.cloud/server/aggregated-parameter"
# server_url_aggregated = "http://127.0.0.1:4313/server/aggregated-parameter"

## key generation
secret_key = context.serialize(save_secret_key = True)
context.make_context_public()
public_key = context.serialize()

    ## keys
client_context = ts.context_from(secret_key)
server_context = ts.context_from(public_key)

while True:
    response = requests.get(server_url_aggregated)
    received = response.json()

    if "aggregated weights are ready" in received["message"]:

        print("[adnids] received")
        if isinstance(received["weights"], list):
            avg_weight_ser_hex = received["weights"]
            avg_weight_ser_bytes = [bytes.fromhex(w) for w in avg_weight_ser_hex]
        else:
            avg_weight_ser_bytes = [bytes.fromhex(received["weights"])]

        parameters_shapes = received['shapes']
        received_hash = received["hash"]

        ## serialization
        shapes_bytes = json.dumps(parameters_shapes).encode("utf-8")

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
        print("[adnids] [INFO] Shaping decrypted parameter!")
        for shape in parameters_shapes:
            data = decrypted_weights[ind]
            gm_weights.append(np.array(data).reshape(shape))
            ind += 1
        print("[adnids] \tDone")

        print("[adnids] setting parameters")
        model = load_model("adnids_model.h5")
        model.set_weights(gm_weights)
        model.save("adnids_model.h5")

        with open("/home/coder/Desktop/securegenai/sur_files/model_parameter_updated_by_server.txt", "w") as f:
            f.write("True")
            print("[adnids] model parameters are updated by server")

    time.sleep(120)