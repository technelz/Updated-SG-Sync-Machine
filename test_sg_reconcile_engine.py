import importlib.util
import sys
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('sg',Path(__file__).with_name('sg_reconcile_engine.py'))
sg=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=sg
spec.loader.exec_module(sg)

class Tests(unittest.TestCase):
    def setUp(self):
        self.src=sg.Inventory('source','111111111111','us-west-2','vpc-a',
            sgs=[{'GroupId':'sg-a','GroupName':'app','IpPermissions':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'IpRanges':[{'CidrIp':'10.10.1.0/24'}]}],'IpPermissionsEgress':[]}],
            subnets=[{'SubnetId':'subnet-a','CidrBlock':'10.10.1.0/24','Tags':[{'Key':'Name','Value':'app-private'}]}])
        self.tgt=sg.Inventory('target','222222222222','us-east-1','vpc-b',
            sgs=[{'GroupId':'sg-b','GroupName':'app','IpPermissions':[],'IpPermissionsEgress':[]}],
            subnets=[{'SubnetId':'subnet-b','CidrBlock':'10.20.1.0/24','Tags':[{'Key':'Name','Value':'app-private'}]}])
        self.cfg={'source':{'account_id':self.src.account,'region':self.src.region,'vpc_id':self.src.vpc},
            'target':{'account_id':self.tgt.account,'region':self.tgt.region,'vpc_id':self.tgt.vpc},
            'policy':{'reconciliation_mode':'source-required-only','minimum_apply_confidence':'HIGH',
            'preserve_target_extra_rules':True,'block_ambiguous_matches':True,'block_unresolved_dependencies':True,
            'require_post_apply_validation':True},'mapping_overrides':{},'approved_cidr_mappings':{}}
    def test_unapproved_cidr_blocked(self):
        plan=sg.build_plan(self.src,self.tgt,self.cfg)
        self.assertEqual(len(plan['unresolved']),1)
        self.assertEqual(len(plan['proposed']),0)
    def test_approved_cidr_proposed(self):
        self.cfg['approved_cidr_mappings']['10.10.1.0/24']={'target':'10.20.1.0/24','approved_by':'netops','ticket':'CHG-123','reason':'verified DR app'}
        plan=sg.build_plan(self.src,self.tgt,self.cfg)
        self.assertEqual(len(plan['unresolved']),0)
        self.assertEqual(len(plan['proposed']),1)
        self.assertEqual(plan['proposed'][0]['permission']['IpRanges'][0]['CidrIp'],'10.20.1.0/24')
    def test_widening_blocked(self):
        self.cfg['approved_cidr_mappings']['10.10.1.0/24']={'target':'10.20.0.0/16','approved_by':'netops','ticket':'CHG-123','reason':'bad'}
        self.assertEqual(len(sg.build_plan(self.src,self.tgt,self.cfg)['unresolved']),1)
    def test_preserves_extra_target_rule(self):
        self.tgt.sgs[0]['IpPermissions']=[{'IpProtocol':'tcp','FromPort':22,'ToPort':22,'IpRanges':[{'CidrIp':'192.0.2.0/24'}]}]
        self.assertEqual(len(sg.build_plan(self.src,self.tgt,self.cfg)['proposed']),0)
    def test_sg_reference_translation(self):
        self.src.sgs[0]['IpPermissions'][0].pop('IpRanges')
        self.src.sgs[0]['IpPermissions'][0]['UserIdGroupPairs']=[{'GroupId':'sg-a'}]
        plan=sg.build_plan(self.src,self.tgt,self.cfg)
        self.assertEqual(plan['proposed'][0]['permission']['UserIdGroupPairs'][0]['GroupId'],'sg-b')
    def test_ambiguous_names_blocked(self):
        self.tgt.sgs.append({'GroupId':'sg-c','GroupName':'dr-app','IpPermissions':[],'IpPermissionsEgress':[]})
        self.assertTrue(sg.build_plan(self.src,self.tgt,self.cfg)['unresolved'])
    def test_original_config_legacy_flags_accepted(self):
        self.cfg['policy']['allow_relative_cidr_translation']=True
        sg.validate_config(self.cfg)
        self.assertTrue(sg.build_plan(self.src,self.tgt,self.cfg)['unresolved'])

if __name__=='__main__':unittest.main()
