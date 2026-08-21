import os
import sys
import json
import time
import socket

import psutil
import paho.mqtt.client as mqtt

sys.path.insert(0, "/app")
from config_inspector import inspector                      
from config_inspector.devices import get_device              
from distributed import simdata                              

DEVICE_ID = os.environ.get("DEVICE_ID", "dev1")
BROKER = os.environ.get("MQTT_BROKER", "mqtt")
PORT = int(os.environ.get("MQTT_PORT", "1883"))
INTERVAL = int(os.environ.get("PUBLISH_INTERVAL", "15"))
                                                                           
DEVICE_TYPE = os.environ.get("DEVICE_TYPE", "ESP32")


def _profile():
    t0 = time.perf_counter()
    full = inspector.inspect_device(DEVICE_ID)                         
    dev = get_device(DEVICE_ID)
    sim = simdata.generate(DEVICE_ID, dev)                                      
    compute_ms = round((time.perf_counter() - t0) * 1000, 2)

    hp = full["hardware_pooling"]; cpu = full["cpu_capability_detection"]
    mem = full["memory_analysis"]

    profile = {
        "hardware_profiling": {
            "declared_cpu": cpu["declared_cpu"],
            "ram_kb": mem["ram_kb"], "flash_mb": mem["flash_mb"],
            "host_logical_cpus": hp.get("host_logical_cpus"),
            "host_total_ram_mb": hp.get("host_total_ram_mb"),
        },
        "memory_analysis": mem,
        "cpu_capability": cpu,
        "random_number_generator": full["random_number_generator"],
        "os_fingerprinting": full["os_fingerprinting"],
        "simulation_data": sim["record"],                                             
    }
    proc = psutil.Process()
    meta = {
        "device": DEVICE_ID, "name": dev["name"],
        "device_type": DEVICE_TYPE,                                                   
        "container_host": socket.gethostname(),
        "compute_ms": compute_ms,
        "memory_rss_mb": round(proc.memory_info().rss / 1e6, 1),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "payload_bytes": sim["payload_bytes"],                                  
        "telemetry_samples": sim["n_samples"],
        "crypto_ops": sim["n_crypto"],
        "timestamp": time.time(),
    }
    return {"meta": meta, "profile": profile}


def main():
    client = mqtt.Client(client_id="device-%s" % DEVICE_ID)
    for _ in range(30):                                                        
        try:
            client.connect(BROKER, PORT, keepalive=60)
            break
        except Exception as e:                                 
            print("[%s] waiting for broker (%s) ... %s" % (DEVICE_ID, BROKER, e), flush=True)
            time.sleep(2)
    client.loop_start()
    topic = "iiot/devices/%s/profile" % DEVICE_ID
    print("[%s] this container emulates a %s; publishing to %s every %ds" %
          (DEVICE_ID, DEVICE_TYPE, topic, INTERVAL), flush=True)
    while True:
        payload = _profile()
        client.publish(topic, json.dumps(payload, default=str), qos=1, retain=True)
        print("[%s/%s] published: compute=%.1fms mem=%.1fMB data=%.1fKB rng=%s" % (
            DEVICE_ID, DEVICE_TYPE, payload["meta"]["compute_ms"],
            payload["meta"]["memory_rss_mb"],
            payload["meta"]["payload_bytes"] / 1024.0,
            payload["profile"]["random_number_generator"]["quality"]), flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
