import boto3

def scan_with_credentials(access_key, secret_key, region="us-east-1"):
    """
    Main function that performs all cloud checks using provided AWS credentials.
    Returns a report dictionary.
    """

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
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

    # --------------------------
    # S3 CHECK
    # --------------------------
    try:
        buckets = s3.list_buckets()["Buckets"]

        for b in buckets:
            name = b["Name"]
            acl = s3.get_bucket_acl(Bucket=name)

            public = False
            for grant in acl["Grants"]:
                grantee = grant.get("Grantee", {})
                permission = grant.get("Permission", "")

                if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    public = True

            report["s3_results"].append({
                "bucket": name,
                "public": public
            })

        report["summary"]["s3_public_buckets"] = sum(1 for b in report["s3_results"] if b["public"])
    except Exception as e:
        report["s3_results"].append({"error": str(e)})

    # --------------------------
    # SECURITY GROUP CHECK
    # --------------------------
    try:
        groups = ec2.describe_security_groups()["SecurityGroups"]
        for sg in groups:
            sg_id = sg["GroupId"]
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        report["sg_results"].append({
                            "security_group": sg_id,
                            "port": rule.get("FromPort"),
                            "open_to_world": True
                        })
        report["summary"]["open_security_groups"] = len(report["sg_results"])
    except Exception as e:
        report["sg_results"].append({"error": str(e)})

    # --------------------------
    # CLOUDTRAIL CHECK (Basic)
    # --------------------------
    try:
        trails = logs.describe_log_groups()
        report["cloudtrail_results"].append({
            "log_groups_found": len(trails.get("logGroups", []))
        })
        report["summary"]["cloudtrail_log_groups"] = len(trails.get("logGroups", []))
    except Exception as e:
        report["cloudtrail_results"].append({"error": str(e)})

    return report
