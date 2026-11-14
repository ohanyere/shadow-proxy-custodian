"""Stage only operator-published data from a separately pinned approval revision.

No approval synthesis, no lock editing, and no executable overlay are allowed.
The authorization payload is not committed into the code revision it names.
"""
import argparse
import os
from pathlib import Path
from .common import read


def main(argv):
    p=argparse.ArgumentParser()
    p.add_argument('--approval',type=Path,required=True)
    p.add_argument('--bundle',type=Path,required=True)
    a=p.parse_args(argv)
    for name in ('authorization.json','authorized-lock.json','worker.json','tool-manifest.json'):
        destination=a.bundle/name
        if destination.exists() or destination.is_symlink(): raise ValueError('Refusing approval replacement')
        raw=read(a.approval/name)
        with destination.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    from pilot.supervisor import validate_authorization
    validate_authorization(a.bundle,os.environ.get('GITHUB_SHA',''),os.environ.get('GITHUB_RUN_ID',''),
        os.environ.get('GITHUB_RUN_ATTEMPT',''),os.environ.get('AUTHORIZATION_REFERENCE',''))
    return 0
