# AWS Security Group Live Sync — workload-aware v4

## Deliverables

**One executable Python file:** `sg_reconcile_engine.py`. The accompanying `sg_config_ready.json` is the existing config schema with safe policy defaults and empty mapping sections. No package installation beyond `boto3` is required. `test_sg_reconcile_engine.py` contains offline unit tests.

This version follows the team's v3 operating runbook: source-required-only parity, live source/target discovery, atomic traffic-behavior comparison, SG shell creation before SG reference remapping, target-extra-rule preservation, report/dry-run/apply modes, post-apply validation, and recovery journal. It adds subnet, ENI, EC2, and VPC-route evidence for CIDR investigation.

**Critical limitation:** AWS subnet names and route destinations are *candidate evidence*, not proof of DR workload equivalence. The script cannot independently discover authoritative source-to-DR workload intent in an isolated DR bubble, or traverse all external TGW accounts and on-prem networks. CIDRs require a reviewed `approved_cidr_mappings` entry, or explicit `preserve_universal_cidrs` policy for `0.0.0.0/0` and `::/0`. It does not infer host-to-host IP translations.

## Prepare configuration

Your original `sg_config.json` was used as the baseline. The account IDs (`123prd`, `456dr`) and VPC IDs (`vpc-11111prd`, `vpc-2222dr`) are illustrative and **must be replaced with real values** before execution. Account IDs must be 12 digits and are validated against STS. The source and target profiles may use AWS SSO.

`sg_config_ready.json` retains your keys (`source`, `target`, `policy`, `reporting`) and adds:

```json
"mapping_overrides": {
  "security_groups": {"sg-PROD-ID": "sg-DR-ID"},
  "subnets": {"subnet-PROD-ID": "subnet-DR-ID"},
  "prefix_lists": {"pl-PROD-ID": "pl-DR-ID"}
},
"approved_cidr_mappings": {
  "10.10.1.0/24": {
    "target": "10.20.1.0/24",
    "approved_by": "Network team",
    "ticket": "CHG-12345",
    "reason": "Verified corresponding application subnet in DR bubble"
  },
  "10.137.0.0/16": {
    "target": "10.137.0.0/16",
    "approved_by": "Network team",
    "ticket": "CHG-12346",
    "reason": "Confirmed same shared-services source permitted in DR"
  }
}
```

These are **examples only**. Do not copy them into your real configuration without confirming ownership and authorization. CIDR mappings can preserve a CIDR when justified; widening the prefix requires `approve_broader_scope: true` on that mapping. Matching SG names are preferred; explicit SG mappings resolve exceptions. The script never blindly trusts a CIDR's offset within a subnet or similar route tables.

Legacy flags `allow_relative_cidr_translation` and `allow_external_cidr_preservation` are accepted for config compatibility but **do not authorize automatic translation/preservation**. The supplied ready config sets them to false. `preserve_target_extra_rules` must remain true; there is no revocation of extra target rules.

## Install and run

```bash
python -m pip install boto3
python -m py_compile sg_reconcile_engine.py
python -m unittest -v test_sg_reconcile_engine.py
aws sso login --profile default
aws sso login --profile dr-ida
aws sts get-caller-identity --profile default
aws sts get-caller-identity --profile dr-ida

# Inventory and report, no writes
python sg_reconcile_engine.py --info-file sg_config_ready.json --report-only

# Planned changes, no writes (default is dry-run)
python sg_reconcile_engine.py --info-file sg_config_ready.json --dry-run

# Only after reviewing and approving every unresolved mapping:
python sg_reconcile_engine.py --info-file sg_config_ready.json --yes \
  --approve-target 222222222222:us-east-1:vpc-REPLACE
```

**Use your real DR account/region/VPC in the approval string.** `--yes` is the only mode that writes AWS changes. It creates unambiguous missing SG shells first, recollects the target, maps SG references, adds source-required atomic rules, optionally syncs tags, and re-reads the target for post-apply verification. It never removes target-only rules. An unresolved CIDR blocks apply; missing SG references can be resolved by shell creation only if no other blockers exist.

## Report interpretation

The script creates a UTC-stamped directory under `sg_reports/` containing `plan.json`, `report.md`, `source_mapping.csv`, and `plan_sha256.txt`. Apply mode additionally produces `apply_result.json`, `rollback_actions.json`, `post_apply/`, and optionally `after_shell_creation/`. A clean apply reports `post_apply_validation.status=PASSED`, `passed=true`, and zero missing, drifted, unresolved, and update counts. Reports include candidate subnet matches, discovered ENIs/instances, and route destinations. A route does not establish authorization or source ownership.

**Recovery:** rollback journals record reverse actions, but are **not** an automatic transaction or rollback script. An interrupted process can leave partial changes. Inspect the report, journal, and actual AWS state before manual recovery; do not blindly replay rollback entries.

## Required AWS permissions

Source and target: `sts:GetCallerIdentity`, `ec2:DescribeVpcs`, `ec2:DescribeSecurityGroups`, `ec2:DescribeSubnets`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeInstances`, `ec2:DescribeRouteTables`, `ec2:DescribeManagedPrefixLists`.

Target apply: `ec2:CreateSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:AuthorizeSecurityGroupEgress`; optionally `ec2:CreateTags`. Access to discovery accounts is read-only and currently audit-only. IAM permission boundaries, SCPs, and cross-account reference restrictions may impose further limits.

## Known limits and release gate

- No live AWS tests have been run here; offline unit tests are not a substitute for DR sandbox integration tests.
- External/shared CIDRs, TGW paths, on-prem networks, and cross-VPC SG references require authoritative evidence and often explicit mappings. Prefix-list matching is restricted to explicit mappings or unique AWS-owned matching lists; customer-managed lists should be explicitly mapped and validated.
- The tool does not revoke extra rules, delete SGs, or perform automatic rollback. Tags are upserted, not pruned.
- For a large fleet, ENI/workload discovery is best-effort; CIDRs containing many ENIs have truncated evidence lists, which must not be interpreted as complete inventory.
- Before production apply, validate against an isolated non-production pair, confirm IAM permissions and source-to-DR mapping approvals, and inspect proposed changes and post-apply reports.

## Safety

Keep actual config files, generated reports, credentials, and rollback journals out of public repositories. Protect `approved_cidr_mappings` as change-controlled configuration.
