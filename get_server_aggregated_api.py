
import requests
import hashlib
import tenseal as ts
import time
import numpy as np
import json
from keras.models import load_model

server_url_aggregated = "https://serverpost.huzaifa.cloud/server/aggregated-parameter"

## key generation
with open("/sgi/sur_files/secret_key.bin", "rb") as f:
    secret_key = f.read()
client_context = ts.context_from(secret_key)

while True:
    response = requests.get(server_url_aggregated)
    received = response.json()

    if "aggregated weights are ready" in received["message"]:

        print("[server_aggregate] received")
        if isinstance(received["weights"], list):
            avg_weight_ser_hex = received["weights"]
            avg_weight_ser_bytes = [bytes.fromhex(w) for w in avg_weight_ser_hex]
        else:
            avg_weight_ser_bytes = [bytes.fromhex(received["weights"])]

        received_parameters_shapes = received['shapes']
        parameters_shapes = [tuple(s) for s in received_parameters_shapes]
        
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
        print("[server_aggregate][INFO] Decrypting!")
        for layer in gm_enc_weights:
            layer.link_context(client_context)
            decrypted_weights.append(layer.decrypt())
        print("[server_aggregate] \tDone")

        ind = 0
        print("[server_aggregate][INFO] Shaping decrypted parameter!")
        for shape in parameters_shapes:
            data = decrypted_weights[ind]
            gm_weights.append(np.array(data).reshape(shape))
            ind += 1
        print("[server_aggregate] \tDone")

        print("[server_aggregate] setting parameters")
        model = load_model("adnids_model.h5")
        model.set_weights(gm_weights)
        model.save("adnids_model.h5")

        with open("/sgi/sur_files/model_parameter_updated_by_server.txt", "w") as f:
            f.write("True")
            print("[server_aggregate] model parameters are updated by server")
    else:
        print("[server_aggregate] not available")

    time.sleep(120)