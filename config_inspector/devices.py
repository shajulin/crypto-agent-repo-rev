
DEVICES = [
    {
        "id": "dev1", "name": "Flame Sensor Node", "sensor": "flame_sensor",
        "cpu": "ESP32-S3 (Xtensa LX7 dual-core @240MHz)",
        "ram_kb": 512, "flash_mb": 16,
        "secure_boot": True, "tpm": False, "puf": True, "secure_element": False,
        "rng_gen": "os_urandom", "os": "FreeRTOS 10.4", "tls": "1.3",
        "cipher_bits": 256, "cipher_mode": "GCM", "curve": "P-256", "hash": "SHA-256",
        "cert_valid_days": 365,
    },
    {
        "id": "dev2", "name": "IR Receiver Node", "sensor": "ir_receiver",
        "cpu": "STM32F103 (Cortex-M3 @72MHz)",
        "ram_kb": 20, "flash_mb": 1,
        "secure_boot": False, "tpm": False, "puf": False, "secure_element": False,
        "rng_gen": "weak_lcg", "os": "bare-metal", "tls": "1.2",
        "cipher_bits": 128, "cipher_mode": "CBC", "curve": "P-224", "hash": "SHA-1",
        "cert_valid_days": -30,                                            
    },
    {
        "id": "dev3", "name": "Soil Moisture Node", "sensor": "soil_moisture",
        "cpu": "ESP8266 (Tensilica L106 @80MHz)",
        "ram_kb": 80, "flash_mb": 4,
        "secure_boot": False, "tpm": False, "puf": False, "secure_element": True,
        "rng_gen": "aes_ctr_drbg", "os": "NodeMCU / Lua", "tls": "1.2",
        "cipher_bits": 128, "cipher_mode": "GCM", "curve": "P-256", "hash": "SHA-256",
        "cert_valid_days": 90,
    },
    {
        "id": "dev4", "name": "Sound Sensor Gateway", "sensor": "sound_sensor",
        "cpu": "Raspberry Pi CM4 (Cortex-A72 quad @1.5GHz)",
        "ram_kb": 2048 * 1024, "flash_mb": 32 * 1024,
        "secure_boot": True, "tpm": True, "puf": False, "secure_element": True,
        "rng_gen": "secrets_csprng", "os": "Linux 6.1 (Yocto)", "tls": "1.3",
        "cipher_bits": 256, "cipher_mode": "GCM", "curve": "P-384", "hash": "SHA-384",
        "cert_valid_days": 730,
    },
    {
        "id": "dev5", "name": "Temp/Humidity Node", "sensor": "temperature_humidity",
        "cpu": "nRF52840 (Cortex-M4F @64MHz)",
        "ram_kb": 256, "flash_mb": 1,
        "secure_boot": True, "tpm": False, "puf": True, "secure_element": False,
        "rng_gen": "os_urandom", "os": "Zephyr 3.4", "tls": "1.2",
        "cipher_bits": 256, "cipher_mode": "GCM", "curve": "P-256", "hash": "SHA-256",
        "cert_valid_days": 20,                
    },
]


def get_devices(n=None):
    if n is None:
        return DEVICES
    return [get_device("dev%d" % (i + 1)) for i in range(n)]


def get_device(dev_id):
    for d in DEVICES:
        if d["id"] == dev_id:
            return d
                                                                                
                                                                            
    if dev_id.startswith("dev"):
        try:
            idx = int(dev_id[3:]) - 1
        except ValueError:
            raise KeyError(dev_id)
        if idx >= 0:
            base = dict(DEVICES[idx % len(DEVICES)])
            base["id"] = dev_id
            base["name"] = "%s #%d" % (base["name"], idx + 1)
            return base
    raise KeyError(dev_id)
