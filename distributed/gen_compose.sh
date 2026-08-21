#!/usr/bin/env bash
set -euo pipefail
N="$1"; ATK="$2"; MODEL="$3"
_TYPES=(ESP32 ESP32-S3 RaspberryPi RaspberryPi ESP32)
cat <<'HDR'
x-node: &node
  build:
    context: ..
    dockerfile: distributed/Dockerfile
  image: iiot-node:latest
  depends_on: [mqtt]
services:
  mqtt:
    image: eclipse-mosquitto:2
    volumes:
      - ./mqtt/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
    ports: ["1883:1883"]
HDR
for i in $(seq 1 "$N"); do
  t=${_TYPES[$(( (i-1) % ${#_TYPES[@]} ))]}
  cat <<DEV
  dev${i}:
    <<: *node
    environment: {DEVICE_ID: dev${i}, DEVICE_TYPE: ${t}}
    command: ["python", "distributed/device_agent.py"]
DEV
done
cat <<AGG
  aggregator:
    <<: *node
    environment: {EXPECTED_DEVICES: "${N}"}
    command: ["python", "distributed/aggregator.py"]
    ports: ["8000:8000"]
    volumes:
      - ../data:/app/data
  monitor:
    <<: *node
    depends_on: [aggregator]
    environment:
      AGGREGATOR_URL: http://aggregator:8000
      MONITOR_SAMPLES: "10"
      MONITOR_INTERVAL: "4"
    command: ["python", "distributed/monitor.py"]
    volumes:
      - ../data:/app/data
      - /var/run/docker.sock:/var/run/docker.sock
  ollama:
    image: ollama/ollama:latest
    entrypoint: ["/bin/sh", "-c",
                 "ollama serve & sleep 8 && (ollama pull ${MODEL} || true) && wait"]
    volumes:
      - ollama_models:/root/.ollama
    ports: ["11434:11434"]
  agent-config:
    <<: *node
    depends_on: [aggregator]
    environment: {AGENT_ROLE: config, FRAMEWORK: own, AGGREGATOR_URL: "http://aggregator:8000"}
    command: ["python", "distributed/agent.py"]
    volumes: ["../data:/app/data"]
  agent-crypto:
    <<: *node
    depends_on: [aggregator]
    environment: {AGENT_ROLE: crypto, FRAMEWORK: own, AGGREGATOR_URL: "http://aggregator:8000"}
    command: ["python", "distributed/agent.py"]
    volumes: ["../data:/app/data"]
  agent-threat:
    <<: *node
    depends_on:
      agent-crypto: {condition: service_completed_successfully}
    environment:
      AGENT_ROLE: threat
      FRAMEWORK: own
      AGGREGATOR_URL: "http://aggregator:8000"
      ATTACK_TARGETS: "${ATK}"
    command: ["python", "distributed/agent.py"]
    volumes: ["../data:/app/data"]
  agent-xai:
    <<: *node
    depends_on:
      agent-threat: {condition: service_completed_successfully}
      ollama: {condition: service_started}
    environment:
      AGENT_ROLE: xai
      FRAMEWORK: own
      AGGREGATOR_URL: "http://aggregator:8000"
      OLLAMA_BASE_URL: "http://ollama:11434"
      OLLAMA_MODEL: "${MODEL}"
    command: ["python", "distributed/agent.py"]
    volumes: ["../data:/app/data"]
  agent-kg:
    <<: *node
    depends_on:
      agent-xai: {condition: service_completed_successfully}
    environment: {AGENT_ROLE: kg, FRAMEWORK: own, AGGREGATOR_URL: "http://aggregator:8000"}
    command: ["python", "distributed/agent.py"]
    volumes: ["../data:/app/data"]
  agent-recommend:
    <<: *node
    depends_on:
      agent-kg: {condition: service_completed_successfully}
    environment: {AGENT_ROLE: recommend, FRAMEWORK: own, AGGREGATOR_URL: "http://aggregator:8000"}
    command: ["python", "distributed/agent.py"]
    volumes: ["../data:/app/data"]
  agent-report:
    <<: *node
    depends_on:
      agent-recommend: {condition: service_completed_successfully}
    environment: {AGENT_ROLE: report, FRAMEWORK: own, AGGREGATOR_URL: "http://aggregator:8000"}
    command: ["python", "distributed/agent.py"]
    volumes: ["../data:/app/data"]
  agent-compare:
    <<: *node
    depends_on: [aggregator, ollama]
    environment:
      AGENT_ROLE: compare
      FRAMEWORK: own
      AGGREGATOR_URL: "http://aggregator:8000"
      OLLAMA_BASE_URL: "http://ollama:11434"
      OLLAMA_MODEL: "${MODEL}"
    command: ["python", "distributed/agent.py"]
    volumes: ["../data:/app/data"]
  crewai:
    build:
      context: ..
      dockerfile: distributed/Dockerfile.crewai
    depends_on: [ollama]
    environment:
      OLLAMA_BASE_URL: "http://ollama:11434"
      OLLAMA_MODEL: "${MODEL}"
      CREWAI_TRACING_ENABLED: "false"
      OTEL_SDK_DISABLED: "true"
    volumes: ["../data:/app/data"]
  akka:
    image: sbtscala/scala-sbt:eclipse-temurin-jammy-17.0.10_7_1.9.9_2.13.13
    working_dir: /project
    depends_on: [ollama]
    environment:
      OLLAMA_BASE_URL: "http://ollama:11434"
      OLLAMA_MODEL: "${MODEL}"
    volumes:
      - ../multi_agent_experiments/akka_framework:/project
      - ../data:/data
    command: ["bash", "/project/run_with_mem.sh"]
volumes:
  ollama_models:
AGG
