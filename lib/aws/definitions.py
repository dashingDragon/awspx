from __future__ import annotations

definitions = {
    "CreatePolicyVersion": {
        "Description": "Overwrite the default version of the target managed policy:",
        "Commands": [
            "aws create-policy-version"
            "   --policy-arn ${AWS::Iam::Policy.Arn}"
            "   --set-as-default"
            "   --policy-document file://<(cat <<EOF\n"
            "{\n"
            '    "Version": "2012-10-17",\n'
            '    "Statement": [\n'
            "        {\n"
            '            "Sid": "Admin",\n'
            '            "Effect": "Allow",\n'
            '            "Action": "*",\n'
            '            "Resource": "*"\n'
            "        }]\n"
            "}\n"
            "EOF\n"
            ")"
        ],
        "Attack": {
            "Depends": "AWS::Iam::Policy",
            "Requires": ["iam:CreatePolicyVersion"],
            "Affects": "AWS::Iam::Policy",
            "Grants": "Admin",
        },
    },
    "AssociateInstanceProfile": {
        "Description": "Associate the specified EC2 instance with the target instance profile: ",
        "Commands": [
            "aws ec2 associate-iam-instance-profile"
            "   --instance-id ${AWS::Ec2::Instance}"
            "   --iam-instance-profile Name=${AWS::Iam::InstanceProfile}"
        ],
        "Attack": {
            "Depends": "AWS::Ec2::Instance",
            "Requires": ["ec2:AssociateIamInstanceProfile"],
            "Affects": "AWS::Ec2::Instance",
            "Grants": "AWS::Iam::InstanceProfile",
            "Cypher": [
                # The instance profile doesnt exist or it can be deleted indirectly
                "(NOT EXISTS((${AWS::Ec2::Instance})-[:TRANSITIVE]->(:`AWS::Iam::InstanceProfile`))",
                "   OR EXISTS((${})-[:I|ACTION{Name:'ec2:DisassociateIamInstanceProfile'}]->(${AWS::Ec2::Instance}))",
                # The instance profile has no role or iam:Pass role can be performed
                ") AND (NOT EXISTS((${AWS::Iam::InstanceProfile})-[:TRANSITIVE]->(:`AWS::Iam::Role`))",
                "OR EXISTS((${})-[:D|ACTION{Name:'iam:PassRole'}]->(:`AWS::Iam::Role`)<-[:TRANSITIVE]-(${AWS::Iam::InstanceProfile})))",
            ],
        },
    },
    "AssumeRole": {
        "Description": "Retrieve a set of temporary security credentials from assuming the target role:",
        "Commands": [
            "aws sts assume-role"
            "   --role-arn ${AWS::Iam::Role.Arn}"
            "   --role-session-name AssumeRole"
        ],
        "Attack": {
            "Requires": ["sts:AssumeRole"],
            "Affects": "AWS::Iam::Role",
            "Cypher": [
                "(${})<-[:TRUSTS{Name:'sts:AssumeRole'}]-(${AWS::Iam::Role})"
            ],
        },
    },
    "AddRoleToInstanceProfile": {
        "Description": "Add the target role to the specified instance profile:",
        "Commands": [
            "aws iam add-role-to-instance-profile"
            "   --instance-profile-name ${AWS::Iam::InstanceProfile}"
            "   --role-name ${AWS::Iam::Role}"
        ],
        "Attack": {
            "Depends": "AWS::Iam::InstanceProfile",
            "Requires": ["iam:AddRoleToInstanceProfile"],
            "Affects": "AWS::Iam::InstanceProfile",
            "Grants": "AWS::Iam::Role",
            "Cypher": [
                # EC2 is trusted by the role
                "(EXISTS((${AWS::Iam::Role})-[:TRUSTS]->({Name:'ec2.amazonaws.com'}))",
                # The instance profile has no role or it can be detached
                "AND EXISTS((${})-[:I|ACTION{Name:'iam:RemoveRoleFromInstanceProfile'}]->(${AWS::Iam::InstanceProfile}))",
                "   OR NOT EXISTS((${AWS::Iam::InstanceProfile})-[:TRANSITIVE]->(${AWS::Iam::Role})))",
            ],
        },
    },
    "AddUserToGroup": {
        "Description": "Add the specified user to the target group:",
        "Commands": [
            "aws iam add-user-to-group"
            "   --group-name ${AWS::Iam::Group}"
            "   --user-name ${AWS::Iam::User}"
        ],
        "Attack": {
            "Depends": "AWS::Iam::User",
            "Requires": ["iam:AddUserToGroup"],
            "Affects": "AWS::Iam::Group",
        },
    },
    "AttachGroupPolicy": {
        "Description": "Attach the target managed policy to the specified group:",
        "Commands": [
            "aws iam attach-group-policy"
            "   --group-name ${AWS::Iam::Group}"
            "   --policy-arn ${AWS::Iam::Policy.Arn}"
        ],
        "Attack": {
            "Depends": "AWS::Iam::Group",
            "Requires": [
                "iam:AttachGroupPolicy",
            ],
            "Affects": "AWS::Iam::Group",
            "Grants": "AWS::Iam::Policy",
        },
    },
    "AttachRolePolicy": {
        "Description": "Attach the target managed policy to the specified role:",
        "Commands": [
            "aws iam attach-role-policy"
            "   --role-name ${AWS::Iam::Role}"
            "   --policy-arn ${AWS::Iam::Policy.Arn}"
        ],
        "Attack": {
            "Depends": "AWS::Iam::Role",
            "Requires": ["iam:AttachRolePolicy"],
            "Affects": "AWS::Iam::Role",
            "Grants": "AWS::Iam::Policy",
        },
    },
    "AttachUserPolicy": {
        "Description": "Attach the target managed policy to the specified user:",
        "Commands": [
            "aws iam attach-user-policy"
            "   --user-name ${AWS::Iam::User}"
            "   --policy-arn ${AWS::Iam::Policy.Arn}"
        ],
        "Attack": {
            "Depends": "AWS::Iam::User",
            "Requires": [
                "iam:AttachUserPolicy",
            ],
            "Affects": "AWS::Iam::User",
            "Grants": "AWS::Iam::Policy",
        },
    },
    "CreateGroup": {
        "Description": "Create a new group and add the specified user to it:",
        "Options": {"CreateAction": True, "Transitive": False},
        "Commands": ["aws iam create-group --group-name ${AWS::Iam::Group}"],
        "Attack": {
            "Requires": ["iam:CreateGroup"],
            "Affects": "AWS::Iam::Group",
        },
    },
    "CreateInstance": {
        "Description": "Launch a new EC2 instance:",
        "Options": {"CreateAction": True, "Transitive": True},
        "Commands": [
            "aws ec2 run-instances"
            "   --count 1"
            "   --instance-type t2.micro"
            "   --image-id $AmiId",
        ],
        "Attack": {
            "Requires": ["ec2:RunInstances"],
            "Affects": "AWS::Ec2::Instance",
        },
    },
    "CreateInstanceProfile": {
        "Description": "Create a new instance profile:",
        "Options": {"CreateAction": True, "Transitive": False},
        "Commands": [
            "aws iam create-instance-profile"
            "   --instance-profile-name ${AWS::Iam::InstanceProfile}"
        ],
        "Attack": {
            "Requires": ["iam:CreateInstanceProfile"],
            "Affects": "AWS::Iam::InstanceProfile",
        },
    },
    "CreatePolicy": {
        "Description": "Create a new managed policy:",
        "Options": {"CreateAction": True, "Transitive": False},
        "Commands": [
            "aws iam create-policy"
            "   --policy-name ${AWS::Iam::Policy}"
            "   --policy-document file://<(cat <<EOF\n"
            "{\n"
            '    "Version": "2012-10-17",\n'
            '    "Statement": [\n'
            "        {\n"
            '            "Sid": "Admin",\n'
            '            "Effect": "Allow",\n'
            '            "Action": "*",\n'
            '            "Resource": "*"\n'
            "        }]\n"
            "}\n"
            "EOF\n"
            ")"
        ],
        "Attack": {
            "Requires": [
                "iam:CreatePolicy",
            ],
            "Affects": "AWS::Iam::Policy",
            "Grants": "Admin",
        },
    },
    "CreateRole": {
        "Description": [
            "Create a new role to assume:",
            "Retrieve a set of temporary security credentials from assuming the target role:",
        ],
        "Options": {"CreateAction": True, "Transitive": True},
        "Commands": [
            "aws iam create-role"
            "   --role-name ${AWS::Iam::Role} "
            "   --assume-role-policy-document file://<(cat <<EOF\n"
            "{\n"
            '  "Version": "2012-10-17",\n'
            '  "Statement": [\n'
            "    {\n"
            '      "Effect": "Allow",\n'
            '      "Action": "sts:AssumeRole",\n'
            '      "Principal": {\n'
            '        "AWS": "*"\n'
            "      }\n"
            "    }\n"
            "  ]\n"
            "}\n"
            "EOF\n"
            ")",
            "aws sts assume-role"
            "   --role-arn ${AWS::Iam::Role.Arn}"
            "   --role-session-name AssumeRole",
        ],
        "Attack": {
            "Requires": [
                "iam:CreateRole",
            ],
            "Affects": "AWS::Iam::Role",
        },
    },
    "CreateUser": {
        "Description": "Create a new user:",
        "Options": {"CreateAction": True, "Transitive": False},
        "Commands": [
            "aws iam create-user --user-name ${AWS::Iam::User}",
        ],
        "Attack": {
            "Requires": ["iam:CreateUser"],
            "Affects": "AWS::Iam::User",
        },
    },
    "PutGroupPolicy": {
        "Description": "Add a new administrative inline policy document to the target group:",
        "Commands": [
            "aws iam put-group-policy"
            "   --group-name ${AWS::Iam::Group}"
            "   --policy-name Admin"
            "   --policy-document file://<(cat <<EOF\n"
            "{\n"
            '    "Version": "2012-10-17",\n'
            '    "Statement": [\n'
            "        {\n"
            '            "Sid": "Admin",\n'
            '            "Effect": "Allow",\n'
            '            "Action": "*",\n'
            '            "Resource": "*"\n'
            "        }]\n"
            "}\n"
            "EOF\n"
            ")"
        ],
        "Attack": {
            "Depends": "AWS::Iam::Group",
            "Requires": ["iam:PutGroupPolicy"],
            "Affects": "AWS::Iam::Group",
            "Grants": "Admin",
        },
    },
    "PutRolePolicy": {
        "Description": "Add a new administrative inline policy document to the target role:",
        "Commands": [
            "aws iam put-role-policy"
            "   --role-name ${AWS::Iam::Role}"
            "   --policy-name Admin"
            "   --policy-document file://<(cat <<EOF\n"
            "{\n"
            '    "Version": "2012-10-17",\n'
            '    "Statement": [\n'
            "        {\n"
            '            "Sid": "Admin",\n'
            '            "Effect": "Allow",\n'
            '            "Action": "*",\n'
            '            "Resource": "*"\n'
            "        }]\n"
            "}\n"
            "EOF\n"
            ")"
        ],
        "Attack": {
            "Depends": "AWS::Iam::Role",
            "Requires": ["iam:PutRolePolicy"],
            "Affects": "AWS::Iam::Role",
            "Grants": "Admin",
        },
    },
    "PutUserPolicy": {
        "Description": "Add a new administrative inline policy document to the target user:",
        "Commands": [
            "aws iam put-user-policy"
            "   --user-name ${AWS::Iam::User}"
            "   --policy-name Admin "
            "   --policy-document file://<(cat <<EOF\n"
            "{\n"
            '    "Version": "2012-10-17",\n'
            '    "Statement": [\n'
            "        {\n"
            '            "Sid": "Admin",\n'
            '            "Effect": "Allow",\n'
            '            "Action": "*",\n'
            '            "Resource": "*"\n'
            "        }]\n"
            "}\n"
            "EOF\n"
            ")"
        ],
        "Attack": {
            "Depends": "AWS::Iam::User",
            "Requires": ["iam:PutUserPolicy"],
            "Affects": "AWS::Iam::User",
            "Grants": "Admin",
        },
    },
    "UpdateRole": {
        "Description": [
            "Update the assume-role policy document of the target role and assume it thereafter:",
            "Retrieve a set of temporary security credentials from assuming the target role:",
        ],
        "Commands": [
            "aws iam update-assume-role-policy"
            "   --role-name ${AWS::Iam::Role}"
            "   --policy-document file://<(cat <<EOF\n"
            "{\n"
            '  "Version": "2012-10-17",\n'
            '  "Statement": [\n'
            "    {\n"
            '      "Effect": "Allow",\n'
            '      "Action": "sts:AssumeRole",\n'
            '      "Principal": {\n'
            '        "AWS": "*"\n'
            "      }\n"
            "    }\n"
            "  ]\n"
            "}\n"
            "EOF\n"
            ")",
            "aws sts assume-role"
            "   --role-arn ${AWS::Iam::Role.Arn}"
            "   --role-session-name AssumeRole",
        ],
        "Attack": {
            "Requires": ["iam:UpdateAssumeRolePolicy"],
            "Affects": "AWS::Iam::Role",
        },
    },
    "UpdateLoginProfile": {
        "Description": "Reset the target user's console password and login as them:",
        "Commands": [
            "aws iam update-login-profile"
            "   --user-name ${AWS::Iam::User}"
            "   --password $Password"
        ],
        "Attack": {
            "Requires": ["iam:UpdateLoginProfile"],
            "Affects": "AWS::Iam::User",
        },
    },
    "CreateLoginProfile": {
        "Description": "Set a console password for the target user and login as them, nothing has been set before:",
        "Commands": [
            "aws iam create-login-profile"
            "   --user-name ${AWS::Iam::User}"
            "   --password $Password"
        ],
        "Attack": {
            "Requires": ["iam:CreateLoginProfile"],
            "Affects": "AWS::Iam::User",
            "Cypher": [
                "(${AWS::Iam::User.LoginProfile} IS NULL",
                "OR EXISTS((${})-[:I|ACTION{Name:'iam:DeleteLoginProfile'}]->(${AWS::Iam::User})))",
            ],
        },
    },
    "CreateAccessKey": {
        "Description": "Create an access key for the target user and authenticate as them using the API:",
        "Commands": [
            "aws iam create-access-key --user-name ${AWS::Iam::User}"
        ],
        "Attack": {
            "Requires": ["iam:CreateAccessKey"],
            "Affects": "AWS::Iam::User",
            "Cypher": [
                "((COALESCE(SIZE(SPLIT(${AWS::Iam::User.AccessKeys},'Status')), 1) - 1) < 2",
                "OR EXISTS((${})-[:I|ACTION{Name:'iam:DeleteAccessKey'}]->(${AWS::Iam::User})))",
            ],
        },
    },
}
