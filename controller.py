"""Custodian-owned parent observes the supervisor's OS exit, not its JSON claim."""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from .common import publish, read, sha
from .service import store


def completed(receipt, authorization_hash):
    return (receipt.get('authorization_sha256')==authorization_hash and
            type(receipt.get('returncode')) is int and receipt['returncode']==0 and
            receipt.get('cancelled') is False and receipt.get('timed_out') is False)


def supervise(argv):
    import argparse
    p=argparse.ArgumentParser()
    for name in ('source','bundle','state'): p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args(argv)
    from pilot.supervisor import validate_authorization
    validate_authorization(args.bundle,os.environ.get('GITHUB_SHA',''),os.environ.get('GITHUB_RUN_ID',''),
                           os.environ.get('GITHUB_RUN_ATTEMPT',''),os.environ.get('AUTHORIZATION_REFERENCE',''))
    receipt_path=store(args.bundle)/'controller.json'
    if receipt_path.exists(): raise ValueError('Invocation controller receipt already exists')
    signals=[]; previous={}
    def cancel(number,frame):
        if len(signals)<8: signals.append(number)
    proc=None; timed_out=False; rc=None
    try:
        for sig in (signal.SIGINT,signal.SIGTERM): previous[sig]=signal.signal(sig,cancel)
        proc=subprocess.Popen([sys.executable,'-I',str(args.bundle/'launch.py'),'supervise-inner',*argv],
                              stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        end=time.monotonic()+1440
        while proc.poll() is None and not signals and time.monotonic()<end: time.sleep(.1)
        timed_out=time.monotonic()>=end
        if signals or timed_out:
            for sig,seconds in ((signal.SIGTERM,10),(signal.SIGKILL,1)):
                try: os.killpg(proc.pid,sig)
                except ProcessLookupError: pass
                try: proc.wait(timeout=seconds); break
                except subprocess.TimeoutExpired: pass
        rc=proc.poll()
    finally:
        receipt={'authorization_sha256':sha(read(args.bundle/'authorization.json')),'returncode':rc,
                 'cancelled':bool(signals),'timed_out':timed_out,'signals':signals}
        try: publish(receipt_path,receipt)
        finally:
            for sig,handler in previous.items(): signal.signal(sig,handler)
    return 0 if completed(receipt,sha(read(args.bundle/'authorization.json'))) else 1
