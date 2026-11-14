import hashlib
import json
import os
import selectors
import signal
import subprocess
import tempfile
import time
from pathlib import Path


def sha(raw): return hashlib.sha256(raw).hexdigest()


def read(path, limit=8*1024**2):
    path = Path(path)
    if path.is_symlink() or not path.is_file(): raise ValueError('Unsafe/missing artifact: '+str(path))
    with path.open('rb') as stream: raw=stream.read(limit+1)
    if len(raw)>limit: raise ValueError('Artifact capacity exceeded')
    return raw


def load(path): return json.loads(read(path))


def publish(path, value):
    path=Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    raw=(json.dumps(value, sort_keys=True, indent=2)+'\n').encode()
    fd,name=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(name,path)
        fd=os.open(path.parent,os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(name): os.unlink(name)


def command(argv, env, timeout=10, stdin=None):
    """Bounded capture, including descendants retaining pipes; never shell=True."""
    end=time.monotonic()+timeout
    with tempfile.TemporaryFile() as source:
        source.write((stdin or '').encode()); source.seek(0)
        proc=subprocess.Popen(argv,stdin=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              env=env,start_new_session=True,bufsize=0)
        sel=selectors.DefaultSelector(); output=[bytearray(),bytearray()]
        try:
            for index,pipe in enumerate((proc.stdout,proc.stderr)):
                os.set_blocking(pipe.fileno(),False); sel.register(pipe,selectors.EVENT_READ,index)
            while sel.get_map() or proc.poll() is None:
                if time.monotonic()>=end: raise TimeoutError('Command deadline')
                for key,_ in sel.select(min(.05,max(0,end-time.monotonic()))):
                    chunk=os.read(key.fd,65536)
                    if not chunk: sel.unregister(key.fileobj); continue
                    output[key.data].extend(chunk)
                    if sum(map(len,output))>2*1024**2: raise ValueError('Command output exceeded capacity')
            rc=proc.poll()
            if rc!=0: raise RuntimeError('Command failed: '+argv[0]+' exit '+str(rc))
            return output[0].decode()
        finally:
            try: os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            sel.close(); proc.stdout.close(); proc.stderr.close()
            try: proc.wait(timeout=.25)
            except subprocess.TimeoutExpired: raise RuntimeError('Command could not be reaped')
