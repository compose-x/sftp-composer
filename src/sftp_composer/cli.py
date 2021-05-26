#!/usr/bin/env python
#  -*- coding: utf-8 -*-
# SPDX-License-Identifier: MPL-2.0
# Copyright 2020-2021 John Mille<john@compose-x.io>


"""Console script for sftp_composer."""
import argparse
import sys


from src.sftp_composer.sftp_composer import render, import_file_content


def main():
    """Console script for sftp_composer."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file-path", type=str, required=True)
    parser.add_argument("_", nargs="*")
    args = parser.parse_args()

    print("Arguments: " + str(args._))
    print("Replace this message by putting your code into " "sftp_composer.cli.main")
    content = import_file_content(args.file_path)
    template = render(content)
    print(template.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
