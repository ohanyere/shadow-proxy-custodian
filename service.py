"""Minimal custodian phases. Deploy with independently controlled code and storage."""
import json
import os
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from .common import load, read, publish, sha
from .observer import Observer, owned, require, verify_baseline, verify_receipt
from .recovery import inventory, assess


def store(bundle):
    auth=load(bundle/'authorization.json'); worker=load(bundle/'worker.json')
    root=Path(worker['receipt_store'])
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(),'Custodian store not deployed')
    require(root.stat().st_uid==os.getuid() and root.stat().st_mode & 0o077==0,'Custodian store permissions')
    invocation=auth['github_run_id']+'-'+auth['github_run_attempt']
    require(all(v.isdigit() for v in invocation.split('-')),'Invalid invocation')
    path=root/invocation
    path.mkdir(mode=0o700,exist_ok=True)
    return path


def prepare(bundle,destination,observer):
    manifest=load(bundle/'tool-manifest.json'); lock=load(bundle/'authorized-lock.json'); worker=load(bundle/'worker.json')
    require(platform.machine()==worker['architecture']=='x86_64','Architecture mismatch')
    os_release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(os_release['ID'].strip('"')=='ubuntu' and os_release['VERSION_ID'].strip('"')=='24.04','Wrong worker OS')
    require(worker.get('runner_image_version') and os.environ.get('E001_RUNNER_IMAGE')==worker['runner_image_version'],'Unapproved runner image revision')
    require(manifest['tools']==lock['tools'] and manifest['images']==lock['images'],'Manifest/lock mismatch')
    require(load(bundle/'expected.json')['images']==lock['images'],'Expected image contract differs')
    require(worker.get('custody_deployed') is True,'Custody gate not deployed')
    store(bundle)
    destination.mkdir(parents=True,exist_ok=False)
    for name in ('kind','kubectl'):
        item=manifest['binaries'][name]; raw=read(bundle/'tools'/name,128*1024**2)
        require(item['architecture']=='linux/amd64' and item['version']==lock['tools'][name] and
                sha(raw)==item['sha256'] and item['provenance_review'],'Unverified binary')
        (destination/name).write_bytes(raw); (destination/name).chmod(0o500)
    kind=observer.run_command([str(destination/'kind'),'version'],observer.env).split()[1]
    kubectl=json.loads(observer.run_command([str(destination/'kubectl'),'--kubeconfig',str(observer.work/'never-default'),
                                           'version','--client=true','-o','json'],observer.env))['clientVersion']['gitVersion']
    require(kind==lock['tools']['kind'] and kubectl==lock['tools']['kubectl'],'Tool binary/version disagreement')
    docker_binary=shutil.which('docker',path=observer.env['PATH'])
    require(docker_binary and sha(read(docker_binary,128*1024**2))==manifest['docker_client_sha256'] and
            manifest['docker_provenance_review'],'Unverified Docker client')
    require(json.loads(observer.docker('version','--format','{{json .Client.Version}}'))==lock['tools']['docker'],'Docker client version mismatch')
    platform_evidence={}
    for role,image in lock['images'].items():
        item=manifest['oci'][role]
        index_raw=read(bundle/item['index_file']); index=json.loads(index_raw)
        require(sha(index_raw)==image.split('@sha256:')[1],'OCI index mismatch')
        children=[v for v in index['manifests'] if v.get('platform',{}).get('os')=='linux' and v['platform'].get('architecture')=='amd64']
        require(len(children)==1 and children[0]['digest']==item['platform_digest'],'Ambiguous platform')
        child_raw=read(bundle/item['manifest_file'])
        require('sha256:'+sha(child_raw)==item['platform_digest'] and item['provenance_review'],'Unverified OCI child')
        platform_evidence[role]=item['platform_digest']
    info=json.loads(observer.docker('info','--format','{{json .}}'))
    require(info['ServerVersion']==lock['tools']['docker'] and info['OSType']=='linux','Docker version/platform mismatch')
    from harness.resources import host_resources  # custodian-controlled frozen copy in deployed bundle
    resources=host_resources(destination)
    for key in ('min_cpus','min_memory_bytes','min_disk_bytes'):
        require(type(worker.get(key)) is int and worker[key]>=lock[key],'Approved worker threshold below lock')
    require(resources['cpus']>=worker['min_cpus'] and resources['available_memory_bytes']>=worker['min_memory_bytes'] and
            resources['available_disk_bytes']>=worker['min_disk_bytes'] and shutil.disk_usage(info['DockerRootDir']).free>=worker['min_disk_bytes'],'Worker admission failed')
    return {'verified':True,'tools':lock['tools'],'platform_manifests':platform_evidence,'resources':resources,
            'worker':worker,'authorization_sha256':sha(read(bundle/'authorization.json'))}


def recover(observer,runs,before,initial,quiet,created_after):
    require(quiet.get('quiescent') is True and quiet.get('error') is None,'No quiescence proof; require worker destruction')
    before=inventory(before); initial=inventory(initial)
    require(observer.inventory()==initial,'Recovery start changed')
    extra=sorted(set(initial['containers']+initial['networks'])-set(before['containers']+before['networks']))
    deleted=[]; errors=[]
    try:
        if extra:
            roots=list(runs.iterdir()); require(len(roots)==1 and roots[0].is_dir() and not roots[0].is_symlink(),'Ambiguous run root')
            root=roots[0]; run_id=root.name.removeprefix('e001-')
            import re
            require(bool(re.fullmatch('[0-9a-f]{20}',run_id)),'Bad run identity')
            owned_ids=set()
            for role in ('target','shadow'):
                name='e001-'+run_id+'-'+role
                # Match by ID/name only after full daemon inspection. No guessed deletion.
                nodes=[observer.inspect(i) for i in initial['containers'] if i not in before['containers'] and i not in deleted]
                networks=[observer.network(i) for i in initial['networks'] if i not in before['networks'] and i not in deleted]
                selected=[n for n in nodes if n['Name']=='/'+name+'-control-plane']
                nets=[n for n in networks if n['Name']==name+'-net']
                if selected:
                    require(len(selected)==len(nets)==1,'Ambiguous node/network')
                    node,net=selected[0],nets[0]
                    owned(node,net,name,run_id,before,created_after)
                    owned(observer.inspect(node['Id']),observer.network(net['Id']),name,run_id,before,created_after)
                    observer.docker('rm','--force','--volumes',node['Id']); deleted.append(node['Id']); owned_ids.add(node['Id'])
                if nets:
                    require(len(nets)==1,'Ambiguous network')
                    net=observer.network(nets[0]['Id'])
                    require(net['Name']==name+'-net' and net['Labels'].get('e001.run')==run_id and
                            net['Labels'].get('e001.cluster')==name and not net.get('Containers'),'Unowned/nonempty network')
                    require(datetime.fromisoformat(net['Created'].replace('Z','+00:00'))>=datetime.fromisoformat(created_after.replace('Z','+00:00')),'Stale network')
                    observer.docker('network','rm',net['Id']); deleted.append(net['Id']); owned_ids.add(net['Id'])
            require(set(extra)==owned_ids,'Unknown resources left; require destruction')
    except Exception as exc:
        errors.append(str(exc))
    final=observer.inventory()
    result={'clean':final==before and not errors,'initial':initial,'final':final,
            'orphans_detected':extra,'deleted_owned':deleted,'errors':errors}
    # The supervisor independently assesses this same report and never converts
    # successful orphan removal into experiment success.
    return result


def archive(bundle,state):
    target=store(bundle); require(not (target/'manifest.json').exists(),'Invocation already sealed')
    receipt=load(state/'supervisor.json'); auth=load(bundle/'authorization.json')
    require(receipt['authorization']==auth,'Supervisor authorization mismatch')
    rid=receipt['run_id']; import re
    require(rid is None or (isinstance(rid,str) and re.fullmatch('[0-9a-f]{20}',rid)),'Invalid supervised run identity')
    paths=[state/name for name in ('supervisor.json','before.json','pre-recovery.json','quiescence.json','recover.json') if (state/name).is_file()]
    evidence=state/'runs'/('e001-'+str(rid))/'evidence'
    if evidence.is_dir(): paths += list(evidence.iterdir())
    require(len(paths)<=8200,'Evidence count exceeded')
    total=0; files={}
    for source in paths:
        require(source.suffix in ('.json','.sha256') and not source.is_symlink(),'Unexpected evidence file')
        raw=read(source,64*1024**2); total+=len(raw); require(total<=70*1024**2,'Evidence capacity exceeded')
        name=('evidence/' if source.parent==evidence else '')+source.name
        destination=target/name; destination.parent.mkdir(mode=0o700,exist_ok=True)
        require(not destination.exists(),'Archive replacement forbidden')
        # Raw artifact preservation, with fsync before publishing the manifest.
        with destination.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        files[name]={'sha256':sha(raw),'bytes':len(raw)}
    if (target/'observer.json').is_file():
        raw=read(target/'observer.json'); files['observer.json']={'sha256':sha(raw),'bytes':len(raw)}
    manifest={'schema':1,'run_id':rid,'authorization_sha256':sha(read(bundle/'authorization.json')),
              'github_run_id':auth['github_run_id'],'github_run_attempt':auth['github_run_attempt'],
              'sealed_at':datetime.now(timezone.utc).isoformat(),'files':files}
    publish(target/'manifest.json',manifest)
    return {'sealed':True,'run_id':rid,'manifest_sha256':sha(read(target/'manifest.json'))}


def accept_archive(bundle):
    root=store(bundle); manifest=load(root/'manifest.json'); auth=load(bundle/'authorization.json')
    from .controller import completed
    require(completed(load(root/'controller.json'),sha(read(bundle/'authorization.json'))),
            'Independent supervisor process completion is missing or failed')
    require(manifest['authorization_sha256']==sha(read(bundle/'authorization.json')) and
            manifest['github_run_id']==auth['github_run_id'] and manifest['github_run_attempt']==auth['github_run_attempt'],'Stale manifest')
    from pathlib import PurePosixPath
    for name,ref in manifest['files'].items():
        path=PurePosixPath(name); require(not path.is_absolute() and '..' not in path.parts,'Unsafe evidence path')
        raw=read(root/name,64*1024**2); require(len(raw)==ref['bytes'] and sha(raw)==ref['sha256'],'Modified evidence')
    receipt=load(root/'supervisor.json'); observer=load(root/'observer.json'); rid=manifest['run_id']
    from pilot.gates import receipt_ready  # independently deployed frozen supervisor policy
    require(receipt_ready(receipt,auth) and receipt['run_id']==rid,'Failed/unknown process or recovery required')
    require(observer['run_id']==rid and observer['passed'] is True and observer['authorization_sha256']==sha(read(bundle/'authorization.json')),'Missing/stale observer receipt')
    recovery=load(root/'recover.json')
    assessment=assess(load(root/'before.json'),load(root/'pre-recovery.json'),receipt['final_inventory'],recovery)
    require(assessment['cleanup_verified'] and assessment=={k:receipt[k] for k in assessment},'Contradictory recovery receipt')
    require(load(root/'quiescence.json')==receipt['process_custody'] and receipt['process_custody']['quiescent'] is True and not receipt['process_custody']['termination_required'],'No stable process completion')
    from harness.completion import accept_result  # frozen consistency checker, not the independent oracle
    report=accept_result(root/'evidence',rid,receipt['process_returncode'])
    expected=load(bundle/'expected.json')
    verify_receipt(observer,expected)
    for role in ('target','shadow'):
        cluster=observer['clusters'][role]
        for key in ('server','container_id','network_id','ca_sha256','config_sha256','kube_system_uid'):
            require(report['clusters'][role][key]==cluster[key],'Implementation/independent identity mismatch')
        observations=observer['observations'][role]
        require(verify_baseline(observations['before'],rid,role,expected)==verify_baseline(observations['after'],rid,role,expected),'Independent baseline changed')
        probes=observer['probes'][role]
        require(len(probes)==3 and len({p['uid'] for p in probes})==3,'Missing independent probes')
        for p in probes:
            require(p['passed'] is True and p['logs']==expected['body']+'\nE001_STATUS:200\n' and p['uid']==p['pod']['metadata']['uid'],'Contradictory independent HTTP evidence')
    return {'run_id':rid,'passed':True,'manifest_sha256':sha(read(root/'manifest.json')),
            'scope':'assignment-003-runtime-baseline-only'}
