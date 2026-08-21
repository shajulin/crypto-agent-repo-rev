from common.timing import timed
from config_inspector.devices import get_device
from . import xai, frameworks

MODULE = "MultiAgent"
STANDARDS = ["NIST SP800-193", "ETSI EN 303 645", "IEC 62443-4-2"]


def _configuration_agent(dev_id, m1):
    dev = get_device(dev_id)
    issues = []
    if not dev["secure_boot"]:
        issues.append("no secure boot")
    if not m1["os_fingerprinting"]["updatable"]:
        issues.append("no firmware update path")
    return {"agent": "ConfigurationAgent", "issues": issues or ["nominal"]}


def _cryptography_agent(dev_id, m2col):
    weak = [k for k, v in m2col.items()
            if any(t in v for t in ("weak", "EXPIRED", "DETECTED",
                                    "below-par", "deprecated", "verified=False"))]
    return {"agent": "CryptographyAgent", "weak_methods": weak or ["nominal"]}


def _threat_agent(dev_id, m3):
    return {"agent": "ThreatAgent", "risk": m3["risk"][dev_id],
            "top_metric": max(("CVSS", "KeyExposureProb", "FirmwareVulnScore"),
                              key=lambda k: m3["metrics"][k][dev_id] /
                              (10 if k != "KeyExposureProb" else 1))}


def _compliance_agent(dev_id, m3):
    compliant = m3["metrics"]["CryptoCompliance"][dev_id] >= 0.75
    return {"agent": "ComplianceAgent", "standards": STANDARDS,
            "status": "COMPLIANT" if compliant else "NON-COMPLIANT",
            "gap": round(1 - m3["metrics"]["CryptoCompliance"][dev_id], 2)}


def reason(module1_results, module2_result, module3_result):
    per_device = {}
                                                                            
    population = [xai.feature_vector(m1,
                     {m: module2_result["table"][m][d] for m in module2_result["methods"]},
                     module3_result, d)
                  for d, m1 in module1_results.items()]
    with timed(MODULE):
        for dev_id, m1 in module1_results.items():
            m2col = {m: module2_result["table"][m][dev_id]
                     for m in module2_result["methods"]}
            findings = {}
            with timed(MODULE, f"ConfigurationAgent/{dev_id}"):
                findings["config"] = _configuration_agent(dev_id, m1)
            with timed(MODULE, f"CryptographyAgent/{dev_id}"):
                findings["crypto"] = _cryptography_agent(dev_id, m2col)
            with timed(MODULE, f"ThreatAgent/{dev_id}"):
                findings["threat"] = _threat_agent(dev_id, module3_result)
            with timed(MODULE, f"ExplainabilityAgent/{dev_id}"):
                findings["xai"] = xai.explain(dev_id, m1, m2col, module3_result,
                                              population=population)
            with timed(MODULE, f"ComplianceAgent/{dev_id}"):
                findings["compliance"] = _compliance_agent(dev_id, module3_result)
            per_device[dev_id] = findings

                                                                                
    with timed(MODULE, "framework_comparison"):
        fw_comparison = frameworks.run_comparison(
            module1_results, module2_result, module3_result)

    return per_device, fw_comparison
