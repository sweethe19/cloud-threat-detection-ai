import pandas as pd

BASE = pd.Timestamp("2020-10-08 10:00:00", tz="UTC")


def user(name):
    return {"type": "IAMUser", "userName": name,
            "arn": f"arn:aws:iam::111111111111:user/{name}", "principalId": name}


def root():
    return {"type": "Root", "arn": "arn:aws:iam::111111111111:root",
            "principalId": "111111111111"}


def ev(ts, name, source, ip, who, err=None, **extra):
    row = {"eventTime": ts, "eventName": name, "eventSource": source,
           "sourceIPAddress": ip, "userIdentity": who, "errorCode": err,
           "userAgent": "aws-cli/2.0", "awsRegion": "us-east-1"}
    row.update(extra)
    return row


def build():
    events, scenarios = [], []

    def add(sid, name, ip, evs):
        scenarios.append({"id": sid, "name": name, "ip": ip})
        events.extend(evs)

    # --- Scenarios the current rules SHOULD catch ---
    ip = "203.0.113.1"
    add("S01", "Cryptomining: 300 RunInstances in under an hour", ip,
        [ev(BASE + pd.Timedelta(seconds=10 * i), "RunInstances",
            "ec2.amazonaws.com", ip, user("svc-build")) for i in range(300)])

    ip = "203.0.113.2"
    names = ["GetAccountSummary", "ListAccessKeys", "ListBuckets",
             "ListUsers", "DescribeInstances"]
    add("S02", "Root account used for 5 actions", ip,
        [ev(BASE + pd.Timedelta(minutes=i), n, "iam.amazonaws.com", ip, root())
         for i, n in enumerate(names)])

    ip = "203.0.113.3"
    add("S03", "Attacker stops and deletes CloudTrail", ip,
        [ev(BASE, "StopLogging", "cloudtrail.amazonaws.com", ip, user("dev-temp")),
         ev(BASE + pd.Timedelta(minutes=1), "DeleteTrail",
            "cloudtrail.amazonaws.com", ip, user("dev-temp"))])

    ip = "203.0.113.4"
    add("S04", "80 AccessDenied errors in one hour", ip,
        [ev(BASE + pd.Timedelta(seconds=30 * i), "GetObject", "s3.amazonaws.com",
            ip, user("contractor"), err="AccessDenied") for i in range(80)])

    ip = "203.0.113.5"
    recon = ["ListUsers", "ListRoles", "ListBuckets", "ListFunctions",
             "DescribeInstances", "DescribeVpcs", "DescribeSecurityGroups",
             "DescribeSnapshots", "DescribeVolumes", "DescribeKeyPairs",
             "GetAccountSummary", "GetAccountAuthorizationDetails",
             "ListPolicies", "ListGroups", "ListAccessKeys", "DescribeDBInstances",
             "ListTopics", "ListQueues", "DescribeLoadBalancers", "DescribeRegions",
             "DescribeImages", "ListAttachedUserPolicies", "GetCallerIdentity",
             "DescribeAddresses", "DescribeSubnets"]
    add("S05", "25 different recon calls in one hour", ip,
        [ev(BASE + pd.Timedelta(minutes=i), n, "iam.amazonaws.com", ip, user("stolen-key"))
         for i, n in enumerate(recon)])

    # --- Scenarios the current rules will probably MISS ---
    ip = "203.0.113.6"
    add("S06", "Low-and-slow cryptomining (20 launches over 10 hours)", ip,
        [ev(BASE + pd.Timedelta(minutes=30 * i), "RunInstances",
            "ec2.amazonaws.com", ip, user("svc-build")) for i in range(20)])

    ip = "203.0.113.7"
    add("S07", "Persistence: new user and access key created", ip,
        [ev(BASE, "CreateUser", "iam.amazonaws.com", ip, user("alice")),
         ev(BASE + pd.Timedelta(minutes=1), "CreateAccessKey",
            "iam.amazonaws.com", ip, user("alice"))])

    ip = "203.0.113.8"
    add("S08", "EBS snapshot shared publicly", ip,
        [ev(BASE, "ModifySnapshotAttribute", "ec2.amazonaws.com", ip, user("bob"),
            requestParameters={"snapshotId": "snap-0123456789abcdef0",
                               "createVolumePermission": {"add": {"items": [{"group": "all"}]}}})])

    ip = "203.0.113.9"
    add("S09", "Privilege escalation: AdministratorAccess attached", ip,
        [ev(BASE, "AttachUserPolicy", "iam.amazonaws.com", ip, user("bob"),
            requestParameters={"userName": "bob",
                               "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})])

    ip = "203.0.113.10"
    add("S10", "Console login without MFA", ip,
        [ev(BASE, "ConsoleLogin", "signin.amazonaws.com", ip, user("carol"),
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"})])

    return events, scenarios