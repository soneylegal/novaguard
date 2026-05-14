#!/bin/bash
# Garante que as dependências estão instaladas no VENV
./.venv/bin/pip install -q httpx scapy pydantic-settings 

echo "🚀 Iniciando NovaGuard Agent..."
# Executa o sniffer usando o binário do venv com sudo preservando o path
sudo ./.venv/bin/python -m agent.sniffer "$@"
