# backend/cloud_scanner.py
"""
Simple cloud scanner demo.
- If AWS keys look fake, frontend will call backend /scan -> this module not used.
- If real keys are provided, this will attempt minimal boto3 calls (S3, EC2 describe_security_groups, CloudTrail/logs).
This code is defensive: errors are caught and returned as part of the report.
"""

import time
try:
    import boto3
    from botocore.config import Config
except Exception:
    boto3 = None

def sample_mock_report():
    # A simple sample report used by demo/fake mode
    return {
        "summary": {
            "s3_public_buckets": 1,
            "sg_open_to_world": 1,
            "cloudtrail_log_groups": 1
        },
        "s3_results": [
            {"bucket": "company-public-assets", "public": True},
            {"bucket": "internal-backups", "public": False}
        ],
        "sg_results": [
            {"security_group": "sg-0123456789abcdef0", "open_to_world": False, "port": 0},
            {"security_group": "sg-0fedcba9876543210", "open_to_world": True, "port": 22}
        ],
        "cloudtrail_results": [
            {"trail": "default-trail", "status": "OK", "log_group": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/cloudtrail"}
        ]
    }

def scan_with_credentials(access_key, secret_key, region="us-east-1", timeout_seconds=30):
    """
    Perform read-only checks. If boto3 is not installed or credentials invalid, raise an Exception
    or return partial results. This function is intentionally simple for demo/hackathon.
    """
    # If boto3 not available, raise
    if boto3 is None:
        raise RuntimeError("boto3 not installed in this environment (install boto3 to run real scans).")

    # Time limitation can be implemented per-call via botocore config
    boto_cfg = Config(region_name=region, retries={"max_attempts": 2, "mode": "standard"}, connect_timeout=5, read_timeout=5)

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

    s3 = session.client("s3", config=boto_cfg)
    ec2 = session.client("ec2", config=boto_cfg)
    logs = session.client("logs", config=boto_cfg)

    report = {"summary": {}, "s3_results": [], "sg_results": [], "cloudtrail_results": []}

    # S3: list buckets + check ACL grants for public access
    try:
        resp = s3.list_buckets()
        buckets = resp.get("Buckets", [])
        for b in buckets:
            name = b.get("Name")
            public = False
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI", "") == "http://acs.amazonaws.com/groups/global/AllUsers":
                        public = True
                report["s3_results"].append({"bucket": name, "public": public})
            except Exception as e:
                report["s3_results"].append({"bucket": name, "error": str(e)})
        report["summary"]["s3_public_buckets"] = sum(1 for b in report["s3_results"] if b.get("public"))
    except Exception as e:
        report["s3_results"].append({"error": "s3_list_error: " + str(e)})

    # Security Groups
    try:
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in groups:
            sg_id = sg.get("GroupId")
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        report["sg_results"].append({"security_group": sg_id, "port": rule.get("FromPort"), "open_to_world": True})
        report["summary"]["sg_open_to_world"] = len(report["sg_results"])
    except Exception as e:
        report["sg_results"].append({"error": "sg_error: " + str(e)})

    # CloudTrail / Log groups (simple)
    try:
        lg = logs.describe_log_groups().get("logGroups", [])
        report["cloudtrail_results"].append({"log_groups_found": len(lg)})
        report["summary"]["cloudtrail_log_groups"] = len(lg)
    except Exception as e:
        report["cloudtrail_results"].append({"error": "logs_error: " + str(e)})

    return report


