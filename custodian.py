"""Bundle entrypoint: copy to the bundle root as custodian.py."""
import argparse
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from custodian.common import load, publish, read, sha
from custodian.observer import Observer, require
from custodian.service import prepare, recover, archive, accept_archive, store


def main():
    p=argparse.ArgumentParser()
    p.add_argument('phase',choices=['prepare','inventory','observe','recover','seal','accept'])
    for arg in ('bundle','output','destination','run-root','before','runs','initial','quiescence','state'):
        p.add_argument('--'+arg,type=Path,required=arg in ('bundle','output'))
    a=p.parse_args(); auth=load(a.bundle/'authorization.json')
    observer=Observer(a.bundle,a.output.parent/('private-'+a.phase))
    if a.phase=='prepare': result=prepare(a.bundle,a.destination,observer)
    elif a.phase=='inventory': result=observer.inventory()
    elif a.phase=='observe':
        target=store(a.bundle)/'observer.json'; require(not target.exists(),'Observer replay/replacement')
        result=observer.observe(a.run_root,load(a.before),auth['issued_at'])
        result['authorization_sha256']=sha(read(a.bundle/'authorization.json'))
        publish(target,result)
        result={'run_id':result['run_id'],'passed':True,'receipt_sha256':sha(read(target))}
    elif a.phase=='recover': result=recover(observer,a.runs,load(a.before),load(a.initial),load(a.quiescence),auth['issued_at'])
    elif a.phase=='seal': result=archive(a.bundle,a.state)
    else: result=accept_archive(a.bundle)
    publish(a.output,result)
    return 0


if __name__=='__main__': raise SystemExit(main())
