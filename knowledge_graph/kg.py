from common.timing import timed
from config_inspector.devices import get_device

MODULE = "KnowledgeGraph"

CHAIN = ["Firmware", "TLS Version", "Cipher Suite", "Key Length",
         "Attack", "Recommendation"]


def _node_values(dev_id, m1, m2col):
    dev = get_device(dev_id)
    rng = m1["random_number_generator"]
    if rng["quality"] == "weak":
        attack, rec = "Ransomware / key recovery", "Replace weak PRNG with hardware TRNG"
    elif dev["cert_valid_days"] < 0:
        attack, rec = "MITM (expired cert)", "Rotate/renew X.509 certificate"
    elif dev["hash"] == "SHA-1":
        attack, rec = "Signature forgery (SHA-1)", "Migrate to SHA-256+"
    elif not m1["os_fingerprinting"]["updatable"]:
        attack, rec = "Backdoor / firmware implant", "Enable signed OTA + secure boot"
    else:
        attack, rec = "Port scanning / recon", "Close unused services, restrict ports"
    fw = "%s (%s)" % (m1["os_fingerprinting"]["declared_os"],
                      "OTA" if m1["os_fingerprinting"]["updatable"] else "no-update")
    return {
        "Firmware": fw,
        "TLS Version": "TLS " + dev["tls"],
        "Cipher Suite": m2col["M2.1_cipher_suite"].split(" verified")[0],
        "Key Length": m2col["M2.2_key_length"],
        "Attack": attack,
        "Recommendation": rec,
    }


def _status_from_xai(xai):
    active = set(xai.get("active_nodes", []))
    status = {n: ("problem" if n in active else "ok") for n in CHAIN}
    status["Attack"] = "problem" if active else "ok"
    status["Recommendation"] = "ok"
    return status


def build(module1_results, module2_result, module3_result, module5_result=None):
    graphs = {}
    with timed(MODULE):
        for dev_id, m1 in module1_results.items():
            with timed(MODULE, f"trace/{dev_id}"):
                m2col = {m: module2_result["table"][m][dev_id]
                         for m in module2_result["methods"]}
                vals = _node_values(dev_id, m1, m2col)
                edges = [(CHAIN[i], CHAIN[i + 1]) for i in range(len(CHAIN) - 1)]
                entry = {"chain": CHAIN, "values": vals, "edges": edges,
                         "risk": module3_result["risk"][dev_id]}
                xai = (module5_result or {}).get(dev_id, {}).get("xai")
                if xai:
                    rc = xai.get("root_cause")
                    entry["node_status"] = _status_from_xai(xai)
                    entry["root_cause_node"] = rc["node"] if rc else None
                    entry["root_cause_message"] = rc["message"] if rc else \
                        "no crypto weakness detected"
                    entry["xai_best_method"] = xai["best_method"]
                    entry["highlight_node"] = xai["dominant_kg_node"]
                    entry["best_attribution"] = xai["best_attribution"]
                else:                          
                    entry["node_status"] = {n: "ok" for n in CHAIN}
                    entry["root_cause_node"] = None
                    entry["root_cause_message"] = "n/a"
                graphs[dev_id] = entry
    return graphs


def ascii_tree(dev_graph):
    status = dev_graph.get("node_status", {})
    root = dev_graph.get("root_cause_node")
    lines = []
    for i, node in enumerate(dev_graph["chain"]):
        mark = "[X]" if status.get(node) == "problem" else "[OK]"
        flag = "   <== ROOT CAUSE" if node == root else ""
        lines.append("%s %s : %s%s" % (mark, node, dev_graph["values"][node], flag))
        if i < len(dev_graph["chain"]) - 1:
            lines.append("         |"); lines.append("         v")
    return "\n".join(lines)
