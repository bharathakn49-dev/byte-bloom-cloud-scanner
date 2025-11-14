import boto3

def scan_with_credentials(ak, sk, region):
    session = boto3.Session(
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        region_name=region,
    )

    s3 = session.client("s3")
    ec2 = session.client("ec2")
    logs = session.client("logs")

    report = {
        "summary": {},
        "s3_results": [],
        "sg_results": [],
        "cloudtrail_results": []
    }

    # S3
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            acl = s3.get_bucket_acl(Bucket=name)

            public = any(
                g.get("Grantee", {}).get("URI") ==
                "http://acs.amazonaws.com/groups/global/AllUsers"
                for g in acl.get("Grants", [])
            )

            report["s3_results"].append({
                "bucket": name,
                "public": public
            })
    except Exception as e:
        report["s3_results"].append({"error": str(e)})

    # Security Groups
    try:
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in groups:
            for rule in sg.get("IpPermissions", []):
                for r in rule.get("IpRanges", []):
                    if r.get("CidrIp") == "0.0.0.0/0":
                        report["sg_results"].append({
                            "security_group": sg["GroupId"],
                            "port": rule.get("FromPort"),
                            "open_to_world": True
                        })
    except Exception as e:
        report["sg_results"].append({"error": str(e)})

    # CloudTrail
    try:
        lg = logs.describe_log_groups()
        report["cloudtrail_results"].append({
            "log_groups_found": len(lg.get("logGroups", []))
        })
    except Exception as e:
        report["cloudtrail_results"].append({"error": str(e)})

    return report

