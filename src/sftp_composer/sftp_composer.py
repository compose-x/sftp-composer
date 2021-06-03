#!/usr/bin/env python
#  -*- coding: utf-8 -*-
# SPDX-License-Identifier: MPL-2.0
# Copyright 2020-2021 John Mille<john@compose-x.io>


"""Main module."""

import re
from copy import deepcopy
from json import dumps
from os import path

import yaml
from troposphere import (
    And,
    Condition,
    Equals,
    GetAtt,
    If,
    Not,
    Output,
    Parameter,
    Ref,
    Sub,
    Template,
)
from troposphere.iam import Policy, Role
from troposphere.secretsmanager import Secret

from .model import DirectoryMapping, SftpComposer

try:
    from yaml import Loader
except ImportError:
    from yaml import CLoader as Loader


def import_file_content(file_path):
    """
    Function to read input file and return YAML parsed content
    :param file_path:
    :return:
    """
    with open(path.abspath(file_path), "r") as file_fd:
        content = file_fd.read()
    return yaml.load(content, Loader=Loader)


def render_bucket_paths(secret_directories):
    """
    Function to render the buckets and user directory mapping needed by AWS SFTP in the secret

    :param list<DirectoryMapping> secret_directories:
    :return:
    """
    sftp_list = []
    for config in secret_directories:
        sftp_list.append({"Entry": config["UserPath"], "Target": config["BucketPath"]})
    return sftp_list


def get_curated_buckets_list(secret_directories):
    """
    Function to get the list of bucket names and validate the bucket name format

    :param secret_directories:
    :return:
    """
    buckets = []
    bucketname_re = re.compile(
        r"^(?:/)([a-zA-Z0-9.-]+)(?:/)?$|^(?:/)([a-zA-Z0-9.-]+/)(?:\S+)$"
    )
    for config in secret_directories:
        b_name = config["BucketPath"]
        if not bucketname_re.match(b_name):
            raise ValueError(
                "Bucket name is malformed. Must follow", bucketname_re.pattern
            )
        curated = bucketname_re.match(b_name).groups()[0]
        buckets.append(curated)
    return buckets


def render(content_input):
    """
    Render the CFN template for the SFTP mapping for secrets manager for a given input

    :param dict content_input:
    :return: The CFN troposphere template
    """
    template = Template("Template for SFTP user")
    content = SftpComposer.parse_obj(content_input)
    secret_content = content.dict()
    secret_mappings = render_bucket_paths(secret_content["HomeDirectoryDetails"])
    curated_buckets = get_curated_buckets_list(secret_content["HomeDirectoryDetails"])
    secret_content["HomeDirectoryDetails"] = secret_mappings
    if "PublicKeys" in secret_content.keys() and not secret_content["PublicKeys"]:
        del secret_content["PublicKeys"]
    role = None
    if "Role" in secret_content.keys() and content.Role:
        iam_boundary = template.add_parameter(
            Parameter("PermissionsBoundary", Type="String", Default="none")
        )
        use_boundary = template.add_condition(
            "UsePermissionsBoundary",
            Not(Equals(Ref(iam_boundary), iam_boundary.Default)),
        )
        role = Role(
            "SFTPRoleForUser",
            PermissionsBoundary=If(
                use_boundary, Ref(iam_boundary), Ref("AWS::NoValue")
            ),
            AssumeRolePolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": ["sts:AssumeRole"],
                        "Effect": "Allow",
                        "Principal": {"Service": Sub("transfer.${AWS::URLSuffix}")},
                        "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                    }
                ],
            },
            Policies=[
                Policy(
                    PolicyName="SFTPS3Access",
                    PolicyDocument={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Action": [
                                    "s3:GetObject",
                                    "s3:PutObject",
                                    "s3:DeleteObject",
                                ],
                                "Effect": "Allow",
                                "Resource": [
                                    Sub(f"arn:${{AWS::Partition}}:s3:::{bucket_name}/*")
                                    for bucket_name in curated_buckets
                                ],
                            },
                            {
                                "Action": [
                                    "s3:ListBucket",
                                    "s3:GetBucketLocation",
                                    "s3:HeadBucket",
                                ],
                                "Effect": "Allow",
                                "Resource": [
                                    Sub(f"arn:${{AWS::Partition}}:s3:::{bucket_name}")
                                    for bucket_name in curated_buckets
                                ],
                            },
                        ],
                    },
                )
            ],
        )
        secret_content["Role"] = f"${{{role.title}.Arn}}"

    username = template.add_parameter(Parameter("Username", Type="String"))
    password = template.add_parameter(
        Parameter("Password", Type="String", NoEcho=True, Default="none")
    )
    ssh_key = template.add_parameter(
        Parameter("RsaSshKey", Type="String", NoEcho=True, Default="none")
    )
    use_password_con = template.add_condition(
        "UseUserPassword", Not(Equals(Ref(password), password.Default))
    )
    use_ssh_key_con = template.add_condition(
        "UseSshKey", Not(Equals(Ref(ssh_key), ssh_key.Default))
    )
    use_ssh_key_and_password = template.add_condition(
        "UseAllAuth", And(Condition(use_ssh_key_con), Condition(use_password_con))
    )
    if role:
        template.add_resource(role)
    with_ssh_key = deepcopy(secret_content)
    with_ssh_key["PublicKeys"] = [f"${{{ssh_key.title}}}"]
    with_password = deepcopy(secret_content)
    with_password["Password"] = f"${{{password.title}}}"
    with_both = deepcopy(secret_content)
    with_both["PublicKeys"] = [f"${{{ssh_key.title}}}"]
    with_both["Password"] = f"${{{password.title}}}"
    secret = Secret(
        "SFTPUserSecret",
        Description="SFTP User secret with directory and S3 bucket mappings",
        Name=Sub(f"SFTP/${{{username.title}}}"),
        SecretString=If(
            use_ssh_key_and_password,
            Sub(dumps(with_both)),
            If(
                use_ssh_key_con,
                Sub(dumps(with_ssh_key)),
                If(use_password_con, Sub(dumps(with_password)), Ref("AWS::NoValue")),
            ),
        ),
    )
    template.add_resource(secret)
    return template
