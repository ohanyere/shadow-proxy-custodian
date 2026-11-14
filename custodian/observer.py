"""Independent fixed-fixture observations; no imports from the implementation harness."""
import base64
import json
import re
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from .common import command, load, read, sha, publish


def require(value, message):
    if not value: raise ValueError(message)


def owned(node, network, name, run_id, before, created_after):
    require(node['Id'] not in before['containers'] and re.fullmatch('[0-9a-f]{64}',node['Id']), 'Preexisting/invalid node')
    labels=node['Config']['Labels']; netlabels=network['Labels']
    require(node['Name']=='/'+name+'-control-plane' and labels.get('io.x-k8s.kind.cluster')==name and
            labels.get('io.x-k8s.kind.role')=='control-plane','Wrong Kind ownership')
    require(datetime.fromisoformat(node['Created'].replace('Z','+00:00'))>=datetime.fromisoformat(created_after.replace('Z','+00:00')),'Stale node')
    require(network['Id'] not in before['networks'] and network['Name']==name+'-net' and
            netlabels.get('e001.run')==run_id and netlabels.get('e001.cluster')==name,'Wrong network ownership')
    membership=node['NetworkSettings']['Networks']
    require(set(membership)=={name+'-net'} and membership[name+'-net']['NetworkID']==network['Id'],'Unexpected membership')
    require(set(network.get('Containers',{}))=={node['Id']},'Foreign network member')
    ports=node['NetworkSettings']['Ports'].get('6443/tcp')
    require(isinstance(ports,list) and len(ports)==1 and ports[0]['HostIp']=='127.0.0.1','Nonlocal API exposure')
    port=ports[0]['HostPort']; require(str(port).isdigit() and 0<int(port)<65536,'Bad API port')
    return 'https://127.0.0.1:'+str(port)


def kubeconfig(path, context, endpoint):
    obj=load(path)
    require(obj['current-context']==context,'Wrong context')
    for key in ('clusters','contexts','users'):
        require(len(obj[key])==1 and obj[key][0]['name']==context,'Ambiguous config')
    require(obj['contexts'][0]['context']=={'cluster':context,'user':context},'Wrong references')
    cluster=obj['clusters'][0]['cluster']; user=obj['users'][0]['user']
    require(set(cluster)=={'server','certificate-authority-data'} and cluster['server']==endpoint,'Unsafe endpoint/auth')
    require(set(user)=={'client-certificate-data','client-key-data'},'Unsafe credential source')
    for value in [cluster['certificate-authority-data'],*user.values()]:
        require(bool(base64.b64decode(value,validate=True)),'Empty credential')
    return sha(base64.b64decode(cluster['certificate-authority-data'])),sha(read(path))


def owner(obj,parent):
    refs=[r for r in obj['metadata'].get('ownerReferences',[]) if r.get('controller') is True]
    require(len(refs)==1 and all(refs[0].get(k)==v for k,v in
        {'uid':parent['metadata']['uid'],'name':parent['metadata']['name'],'kind':parent['kind']}.items()),'Wrong owner')


def verify_probe(probe, expected):
    pod=probe['pod']; uid=probe['uid']; cs=pod['status']['containerStatuses']
    require(isinstance(uid,str) and uid and pod['metadata']['uid']==uid,'Missing/replaced probe UID')
    require(len(pod['spec']['containers'])==1 and pod['spec']['containers'][0]['name']=='probe' and
            pod['spec']['containers'][0]['image']==expected['images']['probe'],'Wrong independent probe image')
    require(len(cs)==1 and cs[0]['name']=='probe' and type(cs[0]['restartCount']) is int and cs[0]['restartCount']==0 and
            set(cs[0]['state'])=={'terminated'},'Bad independent probe lifecycle')
    terminated=cs[0]['state']['terminated']
    require(pod['status']['phase']=='Succeeded' and type(terminated['exitCode']) is int and terminated['exitCode']==0 and
            cs[0].get('containerID') and terminated.get('containerID')==cs[0]['containerID'] and cs[0].get('imageID'),'Independent probe failed')
    require(probe['passed'] is True and probe['logs']==expected['body']+'\nE001_STATUS:200\n','Independent HTTP mismatch')


def verify_receipt(observer, expected):
    rid=observer['run_id']; require(observer['passed'] is True,'Observer did not pass')
    for role in ('target','shadow'):
        binding=observer['clusters'][role]
        raw_json=[]; logs=[]
        for item in observer['raw']:
            if item['role']!=role: continue
            require(item['cluster_uid']==binding['kube_system_uid'],'Raw cluster UID mismatch')
            if item['arguments'][0]=='logs': logs.append((item['arguments'][1],item['stdout']))
            else:
                decoded=json.loads(item['stdout']); raw_json.append(decoded)
                if isinstance(decoded,dict) and isinstance(decoded.get('items'),list): raw_json.extend(decoded['items'])
        observations=observer['observations'][role]
        first=verify_baseline(observations['before'],rid,role,expected)
        require(first==verify_baseline(observations['after'],rid,role,expected),'Independent fixture changed')
        for view in observations.values():
            require(all(obj in raw_json for obj in view.values()),'Derived observation lacks raw evidence')
        probes=observer['probes'][role]
        require(len(probes)==3 and len({p['uid'] for p in probes})==3,'Missing/duplicate independent probes')
        for probe in probes:
            verify_probe(probe,expected)
            require(probe['pod'] in raw_json and (probe['pod']['metadata']['name'],probe['logs']) in logs,'Independent probe lacks raw evidence')


def verify_baseline(objects, run_id, role, expected):
    ns='e001-'+run_id+'-'+role
    namespace,dep,rs,pod,service,slices=(objects[k] for k in ('namespace','deployment','replicaset','pod','service','slices'))
    for obj in (namespace,dep,rs,pod,service):
        m=obj['metadata']
        require(all(isinstance(m.get(k),str) and m[k] for k in ('uid','resourceVersion','name')),'Missing immutable identity')
        require(not m.get('deletionTimestamp'),'Terminating object')
        require(m['labels'].get('e001.run')==run_id and m['labels'].get('e001.role')==role,'Wrong run labels')
        require(obj is namespace or m.get('namespace')==ns,'Wrong namespace')
    require(namespace['metadata']['name']==ns and dep['metadata']['name']==service['metadata']['name']=='http','Wrong fixture identity')
    owner(rs,dep); owner(pod,rs)
    require(dep['spec']['replicas']==1 and dep['status']['availableReplicas']==1 and dep['status']['readyReplicas']==1 and
            dep['status']['observedGeneration']==dep['metadata']['generation'],'Deployment unavailable')
    require(all(pod['metadata']['labels'].get(k)==v for k,v in {'app':'e001-http','tier':'api'}.items()),'Wrong app labels')
    spec=pod['spec']; containers=spec['containers']
    require(len(containers)==1 and containers[0]['name']=='http' and containers[0]['image']==expected['images']['app'],'Wrong app image')
    c=containers[0]
    health=dict(c['readinessProbe']['httpGet'])
    require(health.pop('scheme','HTTP')=='HTTP' and health.pop('host','')=='','Unexpected probe endpoint')
    require('startupProbe' not in c and 'lifecycle' not in c and health=={'path':'/health','port':8080},'Unexpected application behavior')
    require(spec.get('automountServiceAccountToken') is False and c['securityContext']['allowPrivilegeEscalation'] is False and
            c['securityContext']['readOnlyRootFilesystem'] is True and c['securityContext']['capabilities']['drop']==['ALL'],'Unsafe fixture')
    status=pod['status']; cs=status['containerStatuses']
    require(status['phase']=='Running' and len(cs)==1,'Wrong lifecycle')
    c=cs[0]
    require(c['name']=='http' and c.get('ready') is True and c.get('started') is True and type(c.get('restartCount')) is int and c['restartCount']==0 and
            set(c['state'])=={'running'} and not c.get('lastState') and c.get('containerID') and c.get('imageID'),'Contradictory lifecycle')
    require(bool(c['state']['running'].get('startedAt')),'Missing start timestamp')
    conditions=status['conditions']; mapping={v['type']:v['status'] for v in conditions}
    require(len(mapping)==len(conditions) and all(mapping.get(k)=='True' for k in ('Ready','ContainersReady','Initialized','PodScheduled')),'Not ready')
    s=dict(service['spec'])
    for key,value in {'sessionAffinity':'None','internalTrafficPolicy':'Cluster','ipFamilyPolicy':'SingleStack',
                      'ipFamilies':['IPv4'],'publishNotReadyAddresses':False}.items():
        if key in s: require(s.pop(key)==value,'Unapproved Service default')
    ip=s.pop('clusterIP'); ips=s.pop('clusterIPs', [ip]); require(ips==[ip] and ip not in ('','None'),'Invalid ClusterIP')
    ports=s.get('ports',[])
    require(len(ports)==1,'Unexpected ports')
    ports=[dict(ports[0])]; require(ports[0].pop('protocol','TCP')=='TCP','Wrong protocol'); s['ports']=ports
    require(s=={'type':'ClusterIP','selector':{'app':'e001-http'},'ports':[{'name':'http','port':80,'targetPort':8080}]},'Unapproved Service configuration')
    endpoints=[]
    for item in slices['items']:
        owner(item,service)
        require(item['metadata']['namespace']==ns and item['addressType']=='IPv4','Wrong EndpointSlice')
        require(item['ports']==[{'name':'http','port':8080,'protocol':'TCP'}],'Wrong backend ports')
        endpoints.extend(item['endpoints'])
    require(len(endpoints)==1,'Unexpected backend set')
    ep=endpoints[0]; target=ep['targetRef']
    require(target['uid']==pod['metadata']['uid'] and target['name']==pod['metadata']['name'] and target['namespace']==ns and target['kind']=='Pod' and
            ep['conditions'].get('ready') is True and ep['conditions'].get('terminating') is not True and
            ep['addresses']==[status['podIP']],'Wrong/unready backend')
    return {k:objects[k]['metadata']['uid'] for k in ('namespace','deployment','replicaset','pod','service')}


class Observer:
    def __init__(self,bundle,work,runner=command):
        self.bundle=bundle; self.work=work; work.mkdir(parents=True,exist_ok=True)
        self.run_command=runner; self.expected=load(bundle/'expected.json'); self.records=[]
        self.env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LANG':'C.UTF-8','KUBECONFIG':str(work/'never-default'),
                  'DOCKER_CONFIG':str(work/'docker'),'DOCKER_HOST':'unix:///var/run/docker.sock'}
        (work/'docker').mkdir(exist_ok=True); (work/'never-default').write_text('{}')

    def docker(self,*args):
        return self.run_command(['docker','--host','unix:///var/run/docker.sock','--config',str(self.work/'docker'),*args],self.env)

    def inventory(self):
        from .recovery import inventory
        return inventory({'containers':self.docker('ps','-aq','--no-trunc').split(),
                          'networks':self.docker('network','ls','--quiet','--no-trunc').split()})

    def inspect(self,name): return json.loads(self.docker('inspect',name))[0]
    def network(self,name): return json.loads(self.docker('network','inspect',name))[0]

    def bind(self,run_root,role,before,created_after):
        run_id=run_root.name.removeprefix('e001-'); require(bool(re.fullmatch('[0-9a-f]{20}',run_id)),'Bad run ID')
        name='e001-'+run_id+'-'+role
        node=self.inspect(name+'-control-plane'); network=self.network(name+'-net')
        endpoint=owned(node,network,name,run_id,before,created_after)
        config=run_root/'private'/(name+'.json'); context='kind-'+name
        ca,config_hash=kubeconfig(config,context,endpoint)
        binding={'run_id':run_id,'role':role,'name':name,'server':endpoint,'ca_sha256':ca,'config_sha256':config_hash,
                 'container_id':node['Id'],'network_id':network['Id'],'context':context}
        def api(args,stdin=None):
            # Repeat independent Docker/config checks before every API operation.
            require(owned(self.inspect(node['Id']),self.network(network['Id']),name,run_id,before,created_after)==endpoint,'Endpoint changed')
            require(kubeconfig(config,context,endpoint)==(ca,config_hash),'Config changed')
            binary=shutil.which('kubectl',path=self.env['PATH'])
            require(binary and sha(read(binary,128*1024**2))==load(self.bundle/'tool-manifest.json')['binaries']['kubectl']['sha256'],
                    'Unverified kubectl binary')
            argv=[binary,'--kubeconfig',str(config),'--context',context,
                  '--cache-dir',str(self.work/'cache'),'--request-timeout=5s']
            identity=json.loads(self.run_command(argv+['get','namespace','kube-system','-o','json'],self.env))['metadata']['uid']
            if 'kube_system_uid' in binding: require(identity==binding['kube_system_uid'],'Cluster UID changed')
            binding['kube_system_uid']=identity
            raw=self.run_command(argv+args,self.env,stdin=stdin)
            self.records.append({'role':role,'arguments':args,'stdout':raw,'cluster_uid':identity,'at':time.time()})
            return raw
        return binding,api

    def observe(self,run_root,before,created_after):
        run_id=run_root.name.removeprefix('e001-'); result={'run_id':run_id,'passed':False,'clusters':{},'observations':{},'probes':{}}
        for role in ('target','shadow'):
            binding,api=self.bind(run_root,role,before,created_after); ns='e001-'+run_id+'-'+role
            def objects():
                values={}
                for key,resource,name in (('namespace','namespace',ns),('deployment','deployment','http'),('service','service','http')):
                    values[key]=json.loads(api(['get',resource,name,'-n',ns,'-o','json']))
                for key,resource in (('replicaset','replicasets'),('pod','pods')):
                    items=json.loads(api(['get',resource,'-n',ns,'-l','app=e001-http','-o','json']))['items']
                    require(len(items)==1,'Unexpected workload count'); values[key]=items[0]
                values['slices']=json.loads(api(['get','endpointslices','-n',ns,'-l','kubernetes.io/service-name=http','-o','json']))
                return values
            first=objects(); bound=verify_baseline(first,run_id,role,self.expected); probes=[]
            for index in range(3):
                name='custodian-probe-'+str(index)
                manifest={'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':ns,'labels':{'e001.run':run_id,'e001.role':role,'app':'e001-custodian'}},
                  'spec':{'restartPolicy':'Never','automountServiceAccountToken':False,'activeDeadlineSeconds':20,
                    'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'seccompProfile':{'type':'RuntimeDefault'}},
                    'containers':[{'name':'probe','image':self.expected['images']['probe'],'command':['curl'],
                      'args':['-q','--silent','--show-error','--noproxy','*','--connect-timeout','2','--max-time','5','--write-out','\nE001_STATUS:%{http_code}\n','http://http.'+ns+'.svc.cluster.local/health'],
                      'resources':{'requests':{'cpu':'25m','memory':'16Mi'},'limits':{'cpu':'100m','memory':'64Mi'}},
                      'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}}
                created=json.loads(api(['create','-f','-','-o','json'],json.dumps(manifest))); uid=created['metadata']['uid']
                end=time.monotonic()+20
                while True:
                    pod=json.loads(api(['get','pod',name,'-n',ns,'-o','json']))
                    require(pod['metadata']['uid']==uid,'Replaced observer probe')
                    if pod.get('status',{}).get('phase') in ('Succeeded','Failed'): break
                    if time.monotonic()>=end: raise TimeoutError('Independent probe timeout')
                    time.sleep(.2)
                logs=api(['logs',name,'-n',ns,'--container','probe'])
                after=json.loads(api(['get','pod',name,'-n',ns,'-o','json']))
                require(after==pod,'Probe changed during log capture')
                cs=pod['status']['containerStatuses']; require(len(cs)==1 and cs[0]['name']=='probe' and cs[0]['restartCount']==0 and set(cs[0]['state'])=={'terminated'},'Bad probe state')
                require(pod['status']['phase']=='Succeeded' and type(cs[0]['state']['terminated']['exitCode']) is int and cs[0]['state']['terminated']['exitCode']==0,'Probe failed')
                require(logs==self.expected['body']+'\nE001_STATUS:200\n','HTTP response mismatch')
                probes.append({'uid':uid,'pod':pod,'logs':logs,'passed':True})
            final=objects(); require(verify_baseline(final,run_id,role,self.expected)==bound,'Fixture replaced')
            result['clusters'][role]=binding; result['observations'][role]={'before':first,'after':final}; result['probes'][role]=probes
        for key in ('container_id','network_id','server','ca_sha256','kube_system_uid','config_sha256'):
            require(result['clusters']['target'][key]!=result['clusters']['shadow'][key],'Clusters are not independent')
        result['passed']=True; result['raw']=self.records
        verify_receipt(result,self.expected)
        return result
