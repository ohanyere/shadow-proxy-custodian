"""Export an inert review bundle. Does not create authorization or enable locks."""
import argparse
import shutil
from pathlib import Path


def export(source,destination):
    destination.mkdir(parents=True,exist_ok=False)
    for package in ('custodian','pilot','harness'):
        target=destination/package; target.mkdir()
        for path in (source/package).glob('*.py'):
            shutil.copyfile(path,target/path.name)
    shutil.copyfile(source/'custodian/expected.json',destination/'expected.json')
    for name in ('worker.example.json','tool-manifest.example.json'):
        shutil.copyfile(source/'custodian'/name,destination/name)
    shutil.copyfile(source/'custodian/custodian.py',destination/'custodian.py')
    shutil.copyfile(source/'custodian/launch.py',destination/'launch.py')
    shutil.copyfile(source/'config/execution-lock.github-candidate.json',destination/'candidate-lock.DISABLED.json')


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('destination',type=Path)
    a=p.parse_args(); export(Path(__file__).resolve().parents[1],a.destination)
