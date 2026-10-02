#!/usr/bin/env python3
"""Reset destrutivo controlado do laboratório STF/HeraclitusDB.

Exige --yes, valida o diretório permitido, cria backup obrigatório e nunca usa shell=True.
"""
from __future__ import annotations
import argparse, json, subprocess, time, urllib.request
from pathlib import Path

STF_URL="http://127.0.0.1:8787"
HDB_URL="http://127.0.0.1:8080"
DATA_DIR=Path("/var/lib/heraclitusdb")
ALLOWED_DATA_DIR=Path("/var/lib/heraclitusdb")

def run_cmd(args:list[str],*,check:bool=True)->str:
    proc=subprocess.run(args,capture_output=True,text=True,check=False)
    if check and proc.returncode!=0:
        raise RuntimeError(f"Comando falhou ({proc.returncode}): {args!r}\\n{proc.stderr.strip()}")
    return proc.stdout.strip()

def validated_data_dir()->Path:
    target=DATA_DIR.resolve(strict=False)
    allowed=ALLOWED_DATA_DIR.resolve(strict=False)
    if target!=allowed:
        raise RuntimeError(f"Safety gate: diretório recusado: {target}")
    if not target.is_absolute() or str(target) in {"/","/var","/var/lib"}:
        raise RuntimeError(f"Safety gate: diretório perigoso: {target}")
    return target

def reset_stf()->None:
    req=urllib.request.Request(
        f"{STF_URL}/api/reset",data=b"{}",method="POST",
        headers={"Content-Type":"application/json","Accept":"application/json","X-STF-POC":"1","Host":"127.0.0.1:8787"})
    with urllib.request.urlopen(req,timeout=5) as response:
        res=json.loads(response.read().decode("utf-8"))
        print(f"✓ STF resetado: {res.get('message','OK')}")

def zero_heraclitusdb()->None:
    data_dir=validated_data_dir()
    backup=Path(str(data_dir)+".bak")
    run_cmd(["sudo","systemctl","stop","heraclitusdb"])
    run_cmd(["sudo","rm","-rf","--",str(backup)])
    run_cmd(["sudo","cp","-a","--",str(data_dir),str(backup)])
    run_cmd(["sudo","find",str(data_dir),"-mindepth","1","-maxdepth","1","-exec","rm","-rf","--","{}","+"])
    run_cmd(["sudo","chown","-R","web2a:web2a",str(data_dir)])
    run_cmd(["sudo","chmod","0700",str(data_dir)])
    run_cmd(["sudo","systemctl","start","heraclitusdb"])
    time.sleep(1.2)

def verify()->None:
    with urllib.request.urlopen(f"{HDB_URL}/api/v1/agent/status",timeout=5) as response:
        stat=json.loads(response.read().decode("utf-8"))
        print(f"HeraclitusDB: {stat.get('ingest',{}).get('events',0)} eventos")
    with urllib.request.urlopen(f"{STF_URL}/api/state",timeout=5) as response:
        stat=json.loads(response.read().decode("utf-8"))
        print(f"STF Engine: {len(stat.get('events',[]))} eventos")

def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--yes",action="store_true",help="confirma o reset destrutivo")
    parser.add_argument("--dry-run",action="store_true",help="valida alvo sem apagar")
    args=parser.parse_args()
    target=validated_data_dir()
    if args.dry_run:
        print(f"DRY-RUN OK: {target}")
        return 0
    if not args.yes:
        parser.error("reset destrutivo recusado sem --yes")
    zero_heraclitusdb()
    reset_stf()
    verify()
    return 0

if __name__=="__main__":
    raise SystemExit(main())
