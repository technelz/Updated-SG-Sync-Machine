#!/usr/bin/env python3
"""Workload-aware AWS SG reconciliation. Default is read-only; fail-closed on unknowns.

No source CIDR is translated solely because of its numeric offset, subnet size,
route shape, or matching network name. Network evidence is included in reports.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

LOG = logging.getLogger('sg-workload')
BCFG = Config(retries={'mode':'adaptive','max_attempts':8})
RULE_FIELDS = [('IpRanges','CidrIp','ipv4'),('Ipv6Ranges','CidrIpv6','ipv6'),('UserIdGroupPairs','GroupId','sg'),('PrefixListIds','PrefixListId','prefix')]
ENV = {'prod','prd','production','dr','disaster','recovery'}


def normalized(value):
    return '-'.join(x for x in re.sub(r'[^a-z0-9]+','-',str(value or '').lower()).strip('-').split('-') if x not in ENV)


def tags(resource):
    return {x['Key']:x.get('Value','') for x in resource.get('Tags',[]) if x.get('Key')}


def name(resource):
    return tags(resource).get('Name') or resource.get('GroupName') or ''


def identity(resource):
    t=tags(resource)
    return tuple((k,normalized(t[k])) for k in ('Application','Service','Component','Tier','Role') if t.get(k))


def paginate(client, operation, key, **kwargs):
    return [item for page in client.get_paginator(operation).paginate(**kwargs) for item in page.get(key,[])]


def network(value):
    return ipaddress.ip_network(value,strict=False)


def atomic(rule):
    for field,key,kind in RULE_FIELDS:
        for entry in rule.get(field,[]) or []:
            if entry.get(key):
                proto=str(rule['IpProtocol']); fp=rule.get('FromPort') if proto!='-1' else None
                tp=rule.get('ToPort') if proto!='-1' else None
                value=entry[key]
                if kind in ('ipv4','ipv6'): value=str(network(value))
                yield (proto,fp,tp,kind,value),entry


def permission(key, description=None):
    proto,fp,tp,kind,value=key
    result={'IpProtocol':proto}
    if proto!='-1':
        if fp is not None: result['FromPort']=fp
        if tp is not None: result['ToPort']=tp
    field,fieldkey=next((f,k) for f,k,t in RULE_FIELDS if t==kind)
    entry={fieldkey:value}
    if description: entry['Description']=description[:255]
    result[field]=[entry]
    return result


def atom_map(rules):
    return {key:permission(key,entry.get('Description')) for r in rules for key,entry in atomic(r)}


def serialize_key(key):
    return '|'.join(str(x) for x in key)


def unique_pair(source,target,explicit,what):
    """Match names within scoped VPCs, with explicit ID overrides and ambiguity rejection."""
    result={}; problems=[]; used=set()
    target_ids={x['GroupId'] if what=='sg' else x['SubnetId']:x for x in target}
    index=defaultdict(list)
    def match_name(obj):
        return obj.get('GroupName','') if what=='sg' else name(obj)
    for t in target: index[normalized(match_name(t))].append(t)
    for s in source:
        sid=s['GroupId'] if what=='sg' else s['SubnetId']
        if sid in explicit:
            tid=explicit[sid]
            if tid not in target_ids: problems.append({'kind':what,'source':sid,'reason':'explicit target ID not found'});continue
            candidates=[target_ids[tid]];method='explicit'
        else:
            candidates=index.get(normalized(match_name(s)),[]) if normalized(match_name(s)) else []
            if len(candidates)>1 and identity(s):
                narrowed=[t for t in candidates if identity(t)==identity(s)]
                if narrowed: candidates=narrowed
            method='unique_name_and_identity' if identity(s) else 'unique_name'
        if len(candidates)!=1:
            problems.append({'kind':what,'source':sid,'name':match_name(s),'reason':'no unique target name/identity match','candidates':[t['GroupId'] if what=='sg' else t['SubnetId'] for t in candidates]});continue
        t=candidates[0];tid=t['GroupId'] if what=='sg' else t['SubnetId']
        if tid in used: problems.append({'kind':what,'source':sid,'reason':'target already mapped','target':tid});continue
        used.add(tid);result[sid]={'target':tid,'method':method,'source_name':match_name(s),'target_name':match_name(t)}
    return result,problems


@dataclass
class Inventory:
    label:str
    account:str
    region:str
    vpc:str
    sgs:list=field(default_factory=list)
    subnets:list=field(default_factory=list)
    enis:list=field(default_factory=list)
    instances:list=field(default_factory=list)
    route_tables:list=field(default_factory=list)
    prefix_lists:list=field(default_factory=list)
    vpc_cidrs:list=field(default_factory=list)
    def subnet_by_id(self): return {x['SubnetId']:x for x in self.subnets}
    def sg_by_id(self): return {x['GroupId']:x for x in self.sgs}


def aws_client(conf,service='ec2'):
    sess=boto3.Session(profile_name=conf.get('profile'),region_name=conf['region'])
    return sess,sess.client(service,config=BCFG)


def collect(conf,label):
    sess,client=aws_client(conf)
    actual=sess.client('sts',config=BCFG).get_caller_identity()['Account']
    expected=str(conf.get('account_id') or '')
    if not expected or actual!=expected: raise RuntimeError(f'{label} AWS account mismatch/missing: expected {expected}, authenticated {actual}')
    vpc=conf['vpc_id']; found=client.describe_vpcs(VpcIds=[vpc])['Vpcs']
    if len(found)!=1: raise RuntimeError(f'{label} VPC not unique')
    cidrs=[x['CidrBlock'] for x in found[0].get('CidrBlockAssociationSet',[]) if x.get('CidrBlockState',{}).get('State')=='associated']
    cidrs+= [x['Ipv6CidrBlock'] for x in found[0].get('Ipv6CidrBlockAssociationSet',[]) if x.get('Ipv6CidrBlockState',{}).get('State')=='associated']
    fl=[{'Name':'vpc-id','Values':[vpc]}]
    groups=paginate(client,'describe_security_groups','SecurityGroups',Filters=fl)
    subs=paginate(client,'describe_subnets','Subnets',Filters=fl)
    enis=paginate(client,'describe_network_interfaces','NetworkInterfaces',Filters=fl)
    instances=[]
    for reservation in paginate(client,'describe_instances','Reservations',Filters=fl): instances.extend(reservation.get('Instances',[]))
    routes=paginate(client,'describe_route_tables','RouteTables',Filters=fl)
    prefixes=paginate(client,'describe_managed_prefix_lists','PrefixLists')
    LOG.info('%s account=%s region=%s vpc=%s SG=%d subnet=%d ENI=%d instance=%d',label,actual,conf['region'],vpc,len(groups),len(subs),len(enis),len(instances))
    return Inventory(label,actual,conf['region'],vpc,[x for x in groups if x.get('GroupName')!='default' and not re.match(r'^d-[a-z0-9]+_(controllers|workers)$',x.get('GroupName',''),re.I)],subs,enis,instances,routes,prefixes,cidrs)


def cidr_evidence(value,inventories):
    n=network(value); matches=[]
    for inv in inventories:
        for s in inv.subnets:
            for cidr in [s.get('CidrBlock')]+[x.get('Ipv6CidrBlock') for x in s.get('Ipv6CidrBlockAssociationSet',[])]:
                if not cidr:continue
                sn=network(cidr)
                if n.version==sn.version and n.subnet_of(sn):
                    matches.append({'account':inv.account,'region':inv.region,'vpc':inv.vpc,'subnet_id':s['SubnetId'],'subnet_name':name(s),'subnet_cidr':cidr,'role_tags':dict(identity(s)),'prefix_length':sn.prefixlen})
    matches.sort(key=lambda x:x['prefix_length'],reverse=True)
    return matches


def route_evidence(value,inventories):
    n=network(value);result=[]
    for inv in inventories:
        for rt in inv.route_tables:
            for route in rt.get('Routes',[]):
                d=route.get('DestinationCidrBlock') or route.get('DestinationIpv6CidrBlock')
                if not d:continue
                dn=network(d)
                if n.version==dn.version and n.subnet_of(dn):
                    result.append({'account':inv.account,'region':inv.region,'route_table':rt['RouteTableId'],'destination':d,'state':route.get('State'),'gateway':next((route[k] for k in ('TransitGatewayId','NatGatewayId','VpcPeeringConnectionId','GatewayId','NetworkInterfaceId') if route.get(k)),None)})
    result.sort(key=lambda x:network(x['destination']).prefixlen,reverse=True)
    return result[:30]


def workloads(value,inv):
    n=network(value);res=[]
    inst={x['InstanceId']:x for x in inv.instances}
    for eni in inv.enis:
        ips=[x['PrivateIpAddress'] for x in eni.get('PrivateIpAddresses',[]) if x.get('PrivateIpAddress')]
        ips+= [x['Ipv6Address'] for x in eni.get('Ipv6Addresses',[]) if x.get('Ipv6Address')]
        if not any(ipaddress.ip_address(ip) in n for ip in ips):continue
        iid=eni.get('Attachment',{}).get('InstanceId');ec2=inst.get(iid,{})
        res.append({'eni':eni['NetworkInterfaceId'],'eni_description':eni.get('Description',''),'eni_type':eni.get('InterfaceType',''),'instance':iid,'instance_name':name(ec2),'instance_tags':tags(ec2),'subnet':eni.get('SubnetId'),'private_ips':[ip for ip in ips if ipaddress.ip_address(ip) in n]})
    return res[:100]


def prefix_mapping(src,tgt,overrides):
    index=defaultdict(list);tids={p['PrefixListId']:p for p in tgt.prefix_lists}
    for p in tgt.prefix_lists:index[normalized(p.get('PrefixListName'))].append(p)
    result={};issues=[]
    for p in src.prefix_lists:
        sid=p['PrefixListId']
        if sid in overrides: candidates=[tids[overrides[sid]]] if overrides[sid] in tids else []
        else: candidates=index.get(normalized(p.get('PrefixListName')),[])
        if len(candidates)==1 and p.get('AddressFamily')==candidates[0].get('AddressFamily') and (sid in overrides or (p.get('OwnerId')==candidates[0].get('OwnerId') and p.get('OwnerId')=='AWS')):
            result[sid]=candidates[0]['PrefixListId']
        else:issues.append({'kind':'prefix','source':sid,'reason':'no unique matching prefix list and address family'})
    return result,issues


def resolve_source(kind,value,src,tgt,all_inv,subnet_map,prefix_map,sg_map,config):
    """Return mapped value only on explicit authorization or verified exact-subnet mapping."""
    evidence={'source':value,'kind':kind}
    if kind=='sg':
        mapped=sg_map.get(value)
        return mapped,('sg_id_mapping' if mapped else 'unmapped_sg_reference'),evidence
    if kind=='prefix':
        mapped=prefix_map.get(value)
        return mapped,('prefix_list_mapping' if mapped else 'unmapped_prefix_list'),evidence
    n=network(value)
    evidence['subnets']=cidr_evidence(value,all_inv)
    evidence['routes']=route_evidence(value,all_inv)
    evidence['source_workloads']=workloads(value,src)
    overrides=config.get('approved_cidr_mappings',{})
    if value in overrides or str(n) in overrides:
        entry=overrides.get(value, overrides.get(str(n)))
        if not isinstance(entry,dict) or not entry.get('approved_by') or not entry.get('reason') or not entry.get('ticket') or not entry.get('target'):
            return None,'override_missing_approval_metadata',evidence
        try:
            target=network(entry['target'])
            if target.version!=n.version:return None,'override_address_family_mismatch',evidence
        except ValueError:return None,'invalid_override_target',evidence
        evidence['approval']={'by':entry['approved_by'],'reason':entry['reason'],'ticket':entry.get('ticket')}
        # Even approved mappings must not accidentally widen source scope unless specifically approved.
        if target.prefixlen < n.prefixlen and not entry.get('approve_broader_scope',False):
            return None,'mapping_widens_access_without_explicit_approval',evidence
        return str(target),'approved_explicit_mapping',evidence
    if str(n) in ('0.0.0.0/0','::/0'):
        if config.get('policy',{}).get('preserve_universal_cidrs',False):return str(n),'policy_preserve_universal',evidence
        return None,'universal_cidr_requires_policy_approval',evidence
    # Whole-subnet translation is safe to PROPOSE only when uniquely mapped and workload-equivalent.
    # Names are candidate evidence, not sufficient to authorize a rule. Approved mapping above is required.
    candidate=[]
    for match in evidence['subnets']:
        if match['account']!=src.account or match['region']!=src.region or match['vpc']!=src.vpc:continue
        if str(network(match['subnet_cidr']))!=str(n):continue
        target_id=subnet_map.get(match['subnet_id'],{}).get('target')
        if target_id:
            dest=tgt.subnet_by_id()[target_id]
            destcidr=dest.get('CidrBlock') if n.version==4 else next((x['Ipv6CidrBlock'] for x in dest.get('Ipv6CidrBlockAssociationSet',[]) if x.get('Ipv6CidrBlock')),None)
            if destcidr:candidate.append({'target':destcidr,'target_subnet':target_id,'method':'same_name_subnet_candidate'})
    evidence['candidate_dr_cidrs']=candidate
    if candidate:return None,'subnet_candidate_requires_workload_approval',evidence
    if evidence['subnets']:return None,'source_network_not_verified_for_dr',evidence
    return None,'external_or_unowned_source_requires_approval',evidence


def validate_config(config):
    for key in ('source','target'):
        c=config.get(key,{})
        for field in ('account_id','region','vpc_id'):
            if not c.get(field):raise ValueError(f'{key}.{field} required')
        if not re.fullmatch(r'\d{12}',str(c['account_id'])):raise ValueError(f'{key}.account_id must be a 12-digit account ID')
    p=config.get('policy',{})
    if p.get('reconciliation_mode','source-required-only')!='source-required-only':raise ValueError('Only source-required-only supported')
    if p.get('preserve_target_extra_rules',True) is not True:raise ValueError('Target extra rules must be preserved')
    if p.get('allow_unresolved_dependencies',False):raise ValueError('Unsafe allow_unresolved_dependencies not supported')
    # Legacy policy flags are accepted for backward compatibility but never authorize
    # automatic CIDR rewriting or external CIDR preservation.
    # Explicit approved_cidr_mappings entries remain mandatory.
    if p.get('minimum_apply_confidence','HIGH')!='HIGH':raise ValueError('minimum_apply_confidence must be HIGH')
    if p.get('block_ambiguous_matches',True) is not True or p.get('block_unresolved_dependencies',True) is not True:raise ValueError('Fail-closed matching/dependency policy is required')
    if p.get('require_post_apply_validation',True) is not True:raise ValueError('Post-apply validation cannot be disabled')
    if config['source']['account_id']==config['target']['account_id'] and config['source']['region']==config['target']['region'] and config['source']['vpc_id']==config['target']['vpc_id']:
        raise ValueError('Source and target must differ')


def build_plan(src,tgt,config,extra=None):
    extra=extra or []
    ov=config.get('mapping_overrides',{})
    smap,sissues=unique_pair(src.sgs,tgt.sgs,ov.get('security_groups',{}),'sg')
    subnet_map,subissues=unique_pair(src.subnets,tgt.subnets,ov.get('subnets',{}),'subnet')
    pmap,pissues=prefix_mapping(src,tgt,ov.get('prefix_lists',{}))
    srcids=src.sg_by_id();tgtids=tgt.sg_by_id()
    unresolved=[]; proposed=[]; mappings=[]; create=[]
    # Missing SGs can be safely created as empty shells only after all dependencies resolve.
    used={m['target'] for m in smap.values()}
    for s in src.sgs:
        sid=s['GroupId']
        if sid not in smap:
            if any(x['source']==sid for x in sissues):
                reason=next(x['reason'] for x in sissues if x['source']==sid)
                if reason=='no unique target name/identity match' and not any(normalized(t.get('GroupName'))==normalized(s.get('GroupName')) for t in tgt.sgs) and normalized(s.get('GroupName')):
                    if config.get('policy',{}).get('create_missing_security_groups',False):
                        create.append({'source':sid,'name':s['GroupName'],'description':s.get('Description','Reconciled SG')})
                        continue
            unresolved.append({'sg':sid,'reason':'missing_or_ambiguous_target_sg','evidence':[x for x in sissues if x.get('source')==sid]})
    # Unresolved dependencies remain blocked until a second planning pass after shell creation.
    for s in src.sgs:
        sid=s['GroupId'];target_id=smap.get(sid,{}).get('target')
        if not target_id:continue
        t=tgtids[target_id]
        for direction,field in (('ingress','IpPermissions'),('egress','IpPermissionsEgress')):
            actual=atom_map(t.get(field,[]));expected={}
            for key,entry in [pair for r in s.get(field,[]) for pair in atomic(r)]:
                proto,fp,tp,kind,value=key
                mapped,reason,evidence=resolve_source(kind,value,src,tgt,[src,tgt]+extra,subnet_map,pmap,{k:v['target'] for k,v in smap.items()},config)
                mappings.append({'sg':sid,'target_sg':target_id,'direction':direction,'rule':serialize_key(key),'source_type':kind,'source_value':value,'target_value':mapped,'resolution':reason,'evidence':evidence})
                if not mapped:
                    unresolved.append({'sg':sid,'direction':direction,'rule':serialize_key(key),'reason':reason});continue
                nk=(proto,fp,tp,kind,mapped)
                expected[nk]=permission(nk,entry.get('Description'))
            for key,perm in expected.items():
                if key not in actual:
                    proposed.append({'source_sg':sid,'target_sg':target_id,'direction':direction,'rule':serialize_key(key),'permission':perm})
    # All ambiguous mappings are visible, but only SG mapping issues block globally. Unused subnets may be legitimately unmatched.
    return {'source':{'account':src.account,'region':src.region,'vpc':src.vpc},'target':{'account':tgt.account,'region':tgt.region,'vpc':tgt.vpc},'summary':{'source_sgs':len(src.sgs),'target_sgs':len(tgt.sgs),'matched_sgs':len(smap),'create_sgs':len(create),'missing_rules':len(proposed),'unresolved':len(unresolved)},'sg_matches':smap,'subnet_matches':subnet_map,'subnet_issues':subissues,'prefix_issues':pissues,'sg_issues':sissues,'create':create,'proposed':proposed,'resolutions':mappings,'unresolved':unresolved,'apply_eligible':not unresolved and not create}


def plan_fingerprint(plan):
    relevant={'create':plan['create'],'proposed':plan['proposed'],'unresolved':plan['unresolved'],
              'sg_matches':plan['sg_matches'],'resolutions':[(r['sg'],r['direction'],r['rule'],r['target_value']) for r in plan['resolutions']]}
    return hashlib.sha256(json.dumps(relevant,sort_keys=True,default=str).encode()).hexdigest()


def write_journal(path,actions,failures=None):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps({'warning':'Recovery aid only; inspect before manual rollback. SG deletion may fail when referenced.',
                               'actions':list(reversed(actions)),'failures':failures or []},indent=2,default=str))
    tmp.replace(path)


def apply_complete(plan,src,tgt,config,folder,approval,extra):
    if approval!=f'{tgt.account}:{tgt.region}:{tgt.vpc}':
        raise RuntimeError('Explicit --approve-target must equal authenticated account:region:vpc')
    if extra:raise RuntimeError('Additional discovery accounts are audit-only until external dependencies are approved')
    planned_ids={x['source'] for x in plan['create']}
    pending=[x for x in plan['unresolved'] if x.get('reason')=='unmapped_sg_reference' and x.get('rule','').split('|')[-1] in planned_ids]
    blockers=[x for x in plan['unresolved'] if x not in pending]
    if blockers:raise RuntimeError('Unresolved SG/CIDR dependencies; no writes performed. See report.')
    if plan['create'] and not config.get('policy',{}).get('create_missing_security_groups',False):
        raise RuntimeError('Missing SGs but create_missing_security_groups=false')
    if plan['create'] and len({x['name'] for x in plan['create']})!=len(plan['create']):
        raise RuntimeError('Duplicate missing SG names; cannot safely create')
    _,client=aws_client(config['target'])
    fresh_source=collect(config['source'],'source-preflight')
    fresh=collect(config['target'],'target-preflight')
    preflight=build_plan(fresh_source,fresh,config)
    if plan_fingerprint(plan)!=plan_fingerprint(preflight):
        raise RuntimeError('Source or target state changed after audit; aborting without writes')
    journal=folder/'rollback_actions.json'; actions=[]; failures=[]
    write_journal(journal,actions)
    try:
        for entry in plan['create']:
            original=src.sg_by_id()[entry['source']]
            response=client.create_security_group(GroupName=entry['name'],
                Description=(entry['description'] or 'DR security group')[:255],VpcId=tgt.vpc)
            sgid=response['GroupId']
            actions.append({'operation':'delete_security_group','params':{'GroupId':sgid},'source':entry['source']})
            write_journal(journal,actions)
        if plan['create']:
            fresh=collect(config['target'],'target-after-shells')
            plan=build_plan(src,fresh,config)
            report(plan,folder/'after_shell_creation')
            if plan['unresolved'] or plan['create']:
                raise RuntimeError('New SG shells did not resolve dependencies; rules not applied')
        # Every SG rule is an atomic permission, preventing grouping/order false drift.
        for change in plan['proposed']:
            operation='authorize_security_group_ingress' if change['direction']=='ingress' else 'authorize_security_group_egress'
            inverse='revoke_security_group_ingress' if change['direction']=='ingress' else 'revoke_security_group_egress'
            params={'GroupId':change['target_sg'],'IpPermissions':[change['permission']]}
            try:
                getattr(client,operation)(**params)
            except ClientError as exc:
                if exc.response.get('Error',{}).get('Code')=='InvalidPermission.Duplicate':
                    # Another writer may have added it. Verification will determine parity.
                    continue
                raise
            actions.append({'operation':inverse,'params':params,'source':change['source_sg']})
            write_journal(journal,actions)
        # Tags are additive/upsert only; no target-only tags are removed.
        if config.get('policy',{}).get('sync_tags',False):
            for sid,m in plan['sg_matches'].items():
                source=src.sg_by_id()[sid]
                desired={k:v for k,v in tags(source).items() if not k.startswith('aws:')}
                targetsg=fresh.sg_by_id().get(m['target'],{})
                current_tags=tags(targetsg)
                changes=[{'Key':k,'Value':v} for k,v in desired.items() if current_tags.get(k)!=v]
                if changes:
                    # Record previous values before changing; absent tags need delete_tags on rollback.
                    before={k:current_tags.get(k) for k in desired if current_tags.get(k)!=desired[k]}
                    client.create_tags(Resources=[m['target']],Tags=changes)
                    actions.append({'operation':'restore_tags_manually','target_sg':m['target'],'previous':before})
                    write_journal(journal,actions)
    except (ClientError,RuntimeError) as exc:
        failures.append(str(exc));write_journal(journal,actions,failures)
    refreshed=collect(config['target'],'target-post-apply')
    after=build_plan(src,refreshed,config)
    report(after,folder/'post_apply')
    # Missing rules, missing SGs and unresolved mappings must all be zero.
    tag_mismatches=[]
    if config.get('policy',{}).get('sync_tags',False):
        for sid,m in after['sg_matches'].items():
            desired={k:v for k,v in tags(src.sg_by_id()[sid]).items() if not k.startswith('aws:')}
            actual_tags=tags(refreshed.sg_by_id()[m['target']])
            if any(actual_tags.get(k)!=v for k,v in desired.items()):tag_mismatches.append(sid)
    verified=not failures and not after['unresolved'] and not after['create'] and not after['proposed'] and not tag_mismatches
    result={'post_apply_validation':{'enabled':True,'status':'PASSED' if verified else 'FAILED',
        'passed':verified,'summary':{'missing':len(after['create']),'drifted':len(after['proposed']),
        'unresolved_dependencies':len(after['unresolved']),'create':len(after['create']),
        'update':len(after['proposed']),'tag_mismatches':len(tag_mismatches)}},'applied_actions':len(actions),
        'errors':failures,'rollback_journal':str(journal)}
    (folder/'apply_result.json').write_text(json.dumps(result,indent=2))
    return result


def report(plan,folder):
    folder.mkdir(parents=True,exist_ok=True)
    (folder/'plan.json').write_text(json.dumps(plan,indent=2,default=str))
    lines=['# Workload-aware SG reconciliation','',f"Source: `{plan['source']}`",f"Target: `{plan['target']}`",'', '## Summary','']
    for k,v in plan['summary'].items():lines.append(f'- {k}: {v}')
    lines+=['',f"Apply eligible: **{plan['apply_eligible']}**",'','## Unresolved rules','']
    for x in plan['unresolved']:lines.append(f"- `{x.get('sg')}` {x.get('direction','')}: {x['reason']} — `{x.get('rule','')}`")
    lines+=['','## Proposed additions','']
    for x in plan['proposed']:lines.append(f"- `{x['target_sg']}` {x['direction']}: `{x['rule']}`")
    (folder/'report.md').write_text('\n'.join(lines)+'\n')
    with (folder/'source_mapping.csv').open('w',newline='') as f:
        import csv
        fields=['sg','target_sg','direction','rule','source_type','source_value','target_value','resolution']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in plan['resolutions']:w.writerow({k:r.get(k) for k in fields})


def main(argv=None):
    parser=argparse.ArgumentParser(description='AWS SG source-required-only live reconciliation with workload-aware CIDR approvals')
    parser.add_argument('--info-file','--config',dest='config',required=True)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--report-only',action='store_true',help='Read-only inventory and drift report')
    mode.add_argument('--dry-run',action='store_true',help='Read-only execution plan (default)')
    mode.add_argument('--yes',action='store_true',help='Apply approved changes and validate')
    parser.add_argument('--approve-target',help='Required with --yes: account:region:vpc-id')
    parser.add_argument('--output',help='Optional report root directory')
    args=parser.parse_args(argv)
    config=json.loads(Path(args.config).read_text(encoding='utf-8'))
    validate_config(config)
    if args.yes and not args.approve_target:parser.error('--yes requires --approve-target')
    out=Path(args.output or config.get('reporting',{}).get('report_directory','sg_reports')) / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    src=collect(config['source'],'source');tgt=collect(config['target'],'target')
    extra=[collect(conf,f'discovery-{i}') for i,conf in enumerate(config.get('discovery_accounts',[]))]
    plan=build_plan(src,tgt,config,extra)
    report(plan,out)
    (out/'plan_sha256.txt').write_text(plan_fingerprint(plan)+'\n')
    LOG.info('Report: %s',out)
    LOG.info('SG matches=%s missing_rules=%s unresolved=%s missing_SGs=%s',
        plan['summary']['matched_sgs'],len(plan['proposed']),len(plan['unresolved']),len(plan['create']))
    if not args.yes:return 0 if not plan['unresolved'] else 2
    result=apply_complete(plan,src,tgt,config,out,args.approve_target,extra)
    return 0 if result['post_apply_validation']['passed'] else 3


if __name__=='__main__':
    logging.basicConfig(level=logging.INFO,format='[%(levelname)s] %(message)s')
    try:sys.exit(main())
    except (RuntimeError,ValueError,ClientError,FileNotFoundError) as exc:
        LOG.error('%s',exc);sys.exit(1)
