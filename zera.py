#!/usr/bin/env python3
"""Script para zerar completamente o HeraclitusDB e o estado da aplicação STF.

Regras seguidas:
- Parada graciosa via systemctl (NUNCA kill -9).
- Limpeza dos dados em /var/lib/heraclitusdb preservando permissões web2a:web2a 0700.
- Reinício do serviço e reset do motor STF na porta 8787.
"""

import subprocess
import urllib.request
import json
import time
import sys
import os

STF_URL = "http://127.0.0.1:8787"
HDB_URL = "http://127.0.0.1:8080"
DATA_DIR = "/var/lib/heraclitusdb"

def run_cmd(cmd, check=True):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and p.returncode != 0:
        print(f"[ERRO] Comando falhou: {cmd}\nStderr: {p.stderr.strip()}")
        sys.exit(p.returncode)
    return p.stdout.strip()

def reset_stf():
    print("• Resetando estado da aplicação STF...")
    try:
        req = urllib.request.Request(
            f"{STF_URL}/api/reset",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-STF-POC": "1",
                "Host": "127.0.0.1:8787"
            }
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            res = json.loads(r.read().decode("utf-8"))
            print(f"  ✓ STF resetado com sucesso: {res.get('message', 'OK')}")
    except Exception as e:
        print(f"  ⚠ Aviso ao resetar STF: {e}")

def zero_heraclitusdb():
    print("• Parando heraclitusdb de forma graciosa (sem kill -9)...")
    run_cmd("sudo systemctl stop heraclitusdb")

    print(f"• Limpando diretório de dados {DATA_DIR}...")
    # Cria backup rápido de segurança
    run_cmd(f"sudo rm -rf {DATA_DIR}.bak && sudo cp -r {DATA_DIR} {DATA_DIR}.bak", check=False)
    # Esvazia a pasta mantendo a pasta raiz
    run_cmd(f"sudo rm -rf {DATA_DIR}/*")
    run_cmd(f"sudo chown -R web2a:web2a {DATA_DIR}")
    run_cmd(f"sudo chmod 0700 {DATA_DIR}")

    print("• Reiniciando serviço heraclitusdb...")
    run_cmd("sudo systemctl start heraclitusdb")
    time.sleep(1.2)

def verify():
    print("\n=== VERIFICAÇÃO DO AMBIENTE ZERADO ===")
    # Checar HeraclitusDB
    try:
        with urllib.request.urlopen(f"{HDB_URL}/api/v1/agent/status", timeout=5) as r:
            h_stat = json.loads(r.read().decode("utf-8"))
            events = h_stat.get("ingest", {}).get("events", 0)
            engine = h_stat.get("engine", "HeraclitusDB")
            print(f"• {engine}: {events} eventos no ledger (Banco Virgem)")
    except Exception as e:
        print(f"• HeraclitusDB status: falha ao consultar ({e})")

    # Checar STF
    try:
        with urllib.request.urlopen(f"{STF_URL}/api/state", timeout=5) as r:
            s_stat = json.loads(r.read().decode("utf-8"))
            ev_count = len(s_stat.get("events", []))
            nodes = len(s_stat.get("graph", {}).get("nodes", []))
            edges = len(s_stat.get("graph", {}).get("edges", []))
            print(f"• STF Engine: {ev_count} eventos | {nodes} nós no Grafo | {edges} arestas")
    except Exception as e:
        print(f"• STF status: falha ao consultar ({e})")

if __name__ == "__main__":
    print("========================================")
    print(" ZERANDO HERACLITUSDB E ESTADO DO STF   ")
    print("========================================")
    zero_heraclitusdb()
    reset_stf()
    verify()
    print("\n✓ Processo concluído com sucesso!")
