#!/usr/bin/env python
#  -*- coding: utf-8 -*-
# SPDX-License-Identifier: MPL-2.0
# Copyright 2020-2021 John Mille<john@compose-x.io>


"""Main module."""

import yaml
from os import path
from json import dumps
from .model import SftpComposer, DirectoryMapping
from troposphere import Template, Parameter, Output, Sub
from troposphere.secretsmanager import Secret

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


def render(content_input):
    """
    Render the CFN template for the SFTP mapping for secrets manager for a given input

    :param dict content_input:
    :return: The CFN troposphere template
    """
    content = SftpComposer.parse_obj(content_input)
    secret_content = content.dict()
    secret_mappings = render_bucket_paths(secret_content["HomeDirectoryDetails"])
    secret_content["HomeDirectoryDetails"] = secret_mappings
    if "PublicKeys" in secret_content.keys() and not secret_content["PublicKeys"]:
        del secret_content["PublicKeys"]
    template = Template("Template for SFTP user")
    username = Parameter("Username", Type="String")
    secret = Secret(
        "SFTPUserSecret",
        Description="SFTP User secret with directory and S3 bucket mappings",
        SecretString=dumps(secret_content),
        Name=Sub(f"SFTP/${{{username.title}}}"),
    )
    template.add_parameter(username)
    template.add_resource(secret)
    return template
