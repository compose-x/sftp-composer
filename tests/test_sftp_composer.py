#!/usr/bin/env python

"""Tests for `sftp_composer` package."""

import pytest

from sftp_composer.sftp_composer import render


@pytest.fixture()
def valid_content():
    return {
        "HomeDirectoryDetails": [
            {"UserPath": "/ingest-crac", "BucketPath": "/ingest-crac"},
            {"UserPath": "/ingest-disposals", "BucketPath": "/ingest-disposals"},
            {"UserPath": "/ingest-recon", "BucketPath": "/ingest-recon"},
            {"UserPath": "/ingest-movements", "BucketPath": "/ingest-movements"},
            {"UserPath": "/ingest-issues", "BucketPath": "/ingest-issues"},
            {"UserPath": "/ingest-shrinkage", "BucketPath": "/ingest-shrinkage"},
        ],
        "PublicKeys": [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDq",
            "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwAQJ",
        ],
        "Role": "arn:aws:iam::012345567890:role/sftp-user",
    }


def test_main(valid_content):
    template = render(valid_content)
    print(template.to_json())
