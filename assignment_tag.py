#!/usr/bin/env python3

import argparse
import base64
import csv
import os
import re
import secrets
import smtplib
import string
import sys

import requests
import urllib3

urllib3.disable_warnings()

parser = argparse.ArgumentParser(
    description='Rapid7 Insight VM API Tools - tag')

parser.add_argument('assets_csv_file',
                    action='store',
                    nargs=None,
                    const=None,
                    default=None,
                    type=str,
                    choices=None,
                    help='filename',
                    metavar=None)

parser.add_argument('--host',
                    action='store',
                    nargs='?',
                    const=None,
                    default='localhost',
                    type=str,
                    choices=None,
                    help='Rapid7 Insight VM Host',
                    metavar=None)

parser.add_argument('--port',
                    action='store',
                    nargs='?',
                    const=None,
                    default=443,
                    type=int,
                    choices=None,
                    help='Rapid7 Insight VM Port (default:443)',
                    metavar=None)

parser.add_argument('-k', '--no-verify-certificate',
                    action='store_false',
                    default=True,
                    help='Verify cetificate action')

parser.add_argument('--api-version',
                    action='store',
                    nargs='?',
                    const=None,
                    default=3,
                    type=int,
                    choices=None,
                    help='API Version',
                    metavar=None)

args = parser.parse_args()

def main(args: dict):
    api_login_id: str  = os.environ.get('RAPID7_IVM_LOGIN', None)
    api_password: str = os.environ.get('RAPID7_IVM_PASSWORD', None)

    if any([api_login_id is None, api_password is None]):
        print("[ERROR]", "os.environ RAPID7_IVM_LOGIN or RAPID7_IVM_PASSWORD is not defined")
        sys.exit(1)

    api_authorization: str = base64.b64encode("{:s}:{:s}".format(api_login_id, api_password).encode()).decode()

    url_rapid7_ivm: str = "https://{:s}".format(args.host)
    if args.port != 443:
        url_rapid7_ivm += ":{:d}".format(args.port)
    url_rapid7_ivm_api = url_rapid7_ivm + "/api/{:d}/".format(args.api_version)

    headers: dict = {
        "User-Agent"      : "Rapid7 Insight VM API Tools",
        "Authorization"   : "Basic {:s}".format(api_authorization),
        "Accept"          : "application/json",
        "Accept-Language" : "ja, en;",
        "Accept-Encoding" : "gzip, deflate"
    }

    if args.assets_csv_file is None or os.path.isfile(args.assets_csv_file) == False:
        sys.exit(1)

    assets: list = []
    with open(args.assets_csv_file, "r", encoding="utf-8") as fp:
        csvp = csv.reader(fp, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)

        for asset in csvp:
            if re.match("^#", asset[0]):
                continue

            # login
            if re.match("^\s*$", asset[0]):
                print("[WARNING]", "asset is None", str(asset))
                continue

            assets.append(asset)

    if len(assets) == 0:
        sys.exit(0)

    for asset in assets:
        if len(asset) < 2:
            continue

        asset_id: int = get_asset_id(asset[0], url_rapid7_ivm_api + "assets", headers)
        if asset_id is None:
            print("[WARNING]", "Undefined asset:", asset[0])
            continue

        tags: list = str(asset[1]).split("|")
        for tag in tags:
            value: list = tag.split(":")
            if len(value) == 1:
                tag_data: dict = {
                    "type" : "custom",
                    "name" : value[0],
                    "color" : "default",
                }
                tag_id: int = get_tag_id(tag_data["name"], tag_data["type"], url_rapid7_ivm_api + "tags", headers)
                if tag_id is None:
                    tag_id = create_tag(tag_data["name"], tag_data["type"], tag_data["color"], url_rapid7_ivm_api, headers)
                    print("[INFO]", "Create tag:", tag_data["name"], ", id:", tag_id)

                if assing_asset_tag(asset_id, tag_id, url_rapid7_ivm_api, headers) == True:
                    print("[INFO]", "Assing tag:", tag_data["name"], ", asset name:", asset[0])
                else:
                    print("[WARNING]", "Failed assing tag:", tag_data["name"], ", asset name:", asset[0])

            elif all([len(value) == 2, value[0] in ("custom","owner","location")]):
                tag_data : dict = {
                    "type" : value[0],
                    "name" : value[1],
                    "color" : "default"
                }
                tag_id: int = get_tag_id(tag_data["name"], tag_data["type"], url_rapid7_ivm_api + "tags", headers)
                if tag_id is None:
                    tag_id = create_tag(tag_data["name"], tag_data["type"], tag_data["color"], url_rapid7_ivm_api, headers)
                    print("[INFO]", "Create tag:", tag_data["name"], ", id:", tag_id)

                if assing_asset_tag(asset_id, tag_id, url_rapid7_ivm_api, headers) == True:
                    print("[INFO]", "Assing tag:", tag_data["name"], ", asset name:", asset[0])
                else:
                    print("[WARNING]", "Failed assing tag:", tag_data["name"], ", asset name:", asset[0])

            else:
                print("[WARNING]", "Unknown tag:", asset[0], value)
                continue


def get_asset_id(asset_name: str, url: str, headers: dict) -> int:
    asset_id = None

    response = requests.get(url, verify=args.no_verify_certificate, headers=headers)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        raise SystemError("[ERROR]", "{:d} {:s}".format(response_json["status"], response_json["message"]))

    if "resources" in response_json:
        for assets in response_json["resources"]:
            if assets["ip"] == asset_name:
                asset_id = assets["id"]
                break
            elif assets["hostName"] == asset_name:
                asset_id = assets["id"]
                break

    if asset_id is None and "links" in response_json:
        for link in response_json["links"]:
            if link["rel"] == "next":
                asset_id = get_asset_id(asset_name, link["href"], headers)
                break

    return asset_id


def get_asset(asset_id: int, url: str, headers: dict) -> dict:
    url += "assets/{:d}".format(asset_id)

    response = requests.get(url, verify=args.no_verify_certificate, headers=headers)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        print(response_json)
        raise Exception("[WARNING]", "{:d} {:s}".format(response_json["status"], response_json["message"]))

    return response_json


def get_asset_tags(asset_id: int, url: str, headers: dict) -> dict:
    url += "assets/{:d}/tags".format(asset_id)

    response = requests.get(url, verify=args.no_verify_certificate, headers=headers)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        print(response_json)
        raise Exception("[WARNING]", "{:d} {:s}".format(response_json["status"], response_json["message"]))

    return response_json


def get_tag_id(tag_name: str, tag_type: str, url: str, headers: dict) -> int:
    tag_id = None

    response = requests.get(url, verify=args.no_verify_certificate, headers=headers)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        raise SystemError("[ERROR]", "{:d} {:s}".format(response_json["status"], response_json["message"]))

    if "resources" in response_json:
        for tag in response_json["resources"]:
            if all([tag["name"] == tag_name, tag["type"] == tag_type]):
                tag_id = tag["id"]
                break

    if tag_id is None and "links" in response_json:
        for link in response_json["links"]:
            if link["rel"] == "next":
                tag_id = get_tag_id(tag_name, tag_type, link["href"], headers)
                break

    return tag_id


def create_tag(tag_name: str, tag_type: str, tag_color: str, url: str, headers: dict) -> int:
    tag_id: int = None

    payload: dict = {
        "name" : tag_name,
        "type" : tag_type,
        "color": tag_color
    }

    response = requests.post(url + "tags", verify=args.no_verify_certificate, headers=headers, json=payload)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 201:
        raise Exception("[WARNING] {:d} {:s}".format(response_json["status"], response_json["message"]))

    if "id" in response_json:
        tag_id = response_json["id"]

    return tag_id


def assing_asset_tag(asset_id: int, tag_id: int, url: str, headers: dict) -> bool:
    url += "assets/{:d}/tags/{:d}".format(asset_id, tag_id)

    response = requests.put(url, verify=args.no_verify_certificate, headers=headers)
    response_json = response.json()

    if "status" in response_json:
        #raise Exception("[WARNING] {:d} {:s}".format(response_json["status"], response_json["message"]))
        print("[WARNING] {:d} {:s}".format(response_json["status"], response_json["message"]))
        return False

    return True


if __name__ == "__main__":
    main(args)
