"""Pure authorization validation. No approval creation or lock enablement."""
import re
from datetime import datetime, timezone
from .common import load, read, sha


def validate(bundle, *, implementation_sha, workflow_sha256, custodian_revision,
             repository, workflow_ref, run_id, attempt, approval):
    auth=load(bundle/'authorization.json')
    expected={'implementation_sha':implementation_sha,'workflow_sha256':workflow_sha256,
              'custodian_revision':custodian_revision,'repository':repository,'workflow_ref':workflow_ref,
              'github_run_id':run_id,'github_run_attempt':attempt,'approval':approval}
    for key,value in expected.items():
        if not isinstance(value,str) or not value or auth.get(key)!=value:
            raise ValueError('Authorization binding mismatch: '+key)
    for key in ('implementation_sha','custodian_revision'):
        if not re.fullmatch('[0-9a-f]{40}',auth[key]): raise ValueError('Exact revision required')
    if not re.fullmatch('[0-9a-f]{64}',workflow_sha256): raise ValueError('Exact workflow bytes required')
    if not re.fullmatch('[1-9][0-9]*',run_id) or not re.fullmatch('[1-9][0-9]*',attempt):
        raise ValueError('Invalid invocation identity')
    if auth.get('operator_approved') is not True or not isinstance(auth.get('operator'),str) or not auth['operator'].strip():
        raise ValueError('Explicit named operator approval required')
    issued=datetime.fromisoformat(auth['issued_at'].replace('Z','+00:00'))
    expires=datetime.fromisoformat(auth['expires_at'].replace('Z','+00:00'))
    now=datetime.now(timezone.utc)
    if not issued<=now<expires or (expires-issued).total_seconds()>86400:
        raise ValueError('Stale/future/overlong authorization')
    files=auth.get('files',{})
    required={'authorized-lock.json','tool-manifest.json','worker.json','expected.json','custodian.py'}
    if not isinstance(files,dict) or not required <= set(files): raise ValueError('Incomplete bundle inventory')
    for name,expected_hash in files.items():
        from pathlib import PurePosixPath
        p=PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts or not re.fullmatch('[0-9a-f]{64}',str(expected_hash)):
            raise ValueError('Unsafe bundle manifest')
        path=bundle/name
        if any(part.is_symlink() for part in [path,*path.parents] if part!=bundle.parent):
            raise ValueError('Symlinked bundle path')
        if sha(read(path,128*1024**2))!=expected_hash: raise ValueError('Modified bundle artifact: '+name)
    # Every executable/policy module in the bundle must be covered, not just its entrypoint.
    for path in bundle.rglob('*.py'):
        if str(path.relative_to(bundle)) not in files: raise ValueError('Unbound custodian module')
    lock=load(bundle/'authorized-lock.json'); manifest=load(bundle/'tool-manifest.json'); worker=load(bundle/'worker.json')
    if lock.get('execution_enabled') is not True or lock.get('approval')!=approval:
        raise ValueError('Separately enabled approved lock required')
    if manifest.get('tools')!=lock.get('tools') or manifest.get('images')!=lock.get('images'):
        raise ValueError('Tool manifest differs from approved lock')
    if worker.get('architecture')!='x86_64' or worker.get('os')!='ubuntu-24.04':
        raise ValueError('Unsupported approved worker')
    if worker.get('custody_deployed') is not True or not worker.get('receipt_store'):
        raise ValueError('Custody deployment must be independently configured')
    return auth
