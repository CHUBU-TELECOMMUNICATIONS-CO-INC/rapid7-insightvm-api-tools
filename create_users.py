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
from email.mime import multipart, text

import requests
import urllib3

urllib3.disable_warnings()

parser = argparse.ArgumentParser(
    description='Rapid7 Insight VM API Tools - create users')

parser.add_argument('userslist_csv_file',
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

parser.add_argument('--smtp-host',
                    action='store',
                    nargs='?',
                    const=None,
                    default='localhost',
                    type=str,
                    choices=None,
                    help='SMTP Host',
                    metavar=None)

parser.add_argument('--smtp-port',
                    action='store',
                    nargs='?',
                    const=None,
                    default=25,
                    type=int,
                    choices=None,
                    help='SMTP port(default: 25)',
                    metavar=None)

parser.add_argument('--mail-from',
                    action='store',
                    nargs='?',
                    const=None,
                    default='root@localhost',
                    type=str,
                    choices=None,
                    help='Mail from',
                    metavar=None)

parser.add_argument('--generate-password-length',
                    action='store',
                    nargs='?',
                    const=None,
                    default=10,
                    type=int,
                    choices=None,
                    help='generate random password length(default: 10)',
                    metavar=None)

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

    mail_subject: str = "[Rapid7 Insight VM] Create user successful"
    mail_body_original: str = """
こちらは脆弱性管理システム(Rapid7 Insight VM)のユーザ登録完了メールとなります

[[name]] さんのUsernameおよびPasswordは下記となります

----------------------------------
Username : [[login]]
Password : [[password]]
Password Rest : [[reset_password]]
Enabled  : [[enabled]]
----------------------------------

*1. Password Rest = True の場合は初回ログイン時にパスワード再設定を行ってください
*2. Enabled = False の場合は管理者(CSIRT)へログイン有効化申請を行ってください

URL : [[url_rapid7_ivm]]
    """

    if args.userslist_csv_file is None or os.path.isfile(args.userslist_csv_file) == False:
        sys.exit(1)

    users: list = []
    with open(args.userslist_csv_file, "r", encoding="utf-8") as fp:
        csvp = csv.reader(fp, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)

        for user in csvp:
            if re.match("^#", user[0]):
                continue

            # login
            if re.match("^\s*$", user[0]):
                print("[WARNING]", "login is None", str(user))
                continue

            users.append(user)

    if len(users) == 0:
        print("[INFO]", "create user is None")
        sys.exit(0)

    for user in users:
        user_data: dict = {
            "login": user[0],
            "name" :  user[1],
            "email": user[2],
            "password":  user[3],
            "role": user[4],
            "sites":  user[5],
            "enabled":  convert_bool(user[6]),
            "reset_password": convert_bool(user[7]),
            "send_email": convert_bool(user[8])
        }

        login_id: int = None
        role_id: str  = None
        site_id_list: list = []

        try:
            login_id = get_user_id(user_data["login"], url_rapid7_ivm_api + "users", headers)
        except SystemError as ex:
            print(ex)
            break

        if login_id is not None:
            print("[WARNING]", "User {:s} is found id:{:d}".format(user_data["login"], login_id))
            continue

        if any([user_data["role"] != ""]):
            try:
                role_id = get_role_id(user_data["role"], url_rapid7_ivm_api + "roles", headers)
            except SystemError as ex:
                print(ex)
                break

        if role_id is None:
            print("[WARNING]", "User {:s} role {:s} is not found".format(user_data["login"], user_data["role"]))
            continue

        if user_data["sites"] != "":
            site_list = user_data["sites"].split("|")
            for site_name in site_list:
                site_id = get_site_id(site_name, url_rapid7_ivm_api + "sites", headers)
                if site_id is not None:
                    site_id_list.append(site_id)
                else:
                    print("[WARNING]", "Site {:s} is not found".format(site_name))

        if any([user_data["password"] == "NULL", user_data["password"] == "None"]):
            user_data["password"] = get_random_password_string(args.generate_password_length)

        try:
            login_id = create_user(user_data, role_id, url_rapid7_ivm_api, headers)
        except Exception as ex:
            print(ex)
            continue
        print("[SUCCESS]", "User {:s} is id:{:d}".format(user_data["login"], login_id))

        if len(site_id_list) > 0:
            try:
                update_site_access(login_id, site_id_list, url_rapid7_ivm_api, headers)
            except Exception as ex:
                print(ex)
                continue

        if user_data["send_email"] == True:
            send_mail(user_data, url_rapid7_ivm, mail_subject, mail_body_original)


def convert_bool(value: str):
    if any([value == "", value == "FALSE", value == "False", value == "false", value == "0"]):
        return False
    return True


def get_random_password_string(length):
    pass_chars = string.ascii_letters
    password = ''.join(secrets.choice(pass_chars) for x in range(length))

    pass_chars = string.digits
    password += secrets.choice(pass_chars)

    pass_chars = string.punctuation
    password += secrets.choice(pass_chars)

    return password


def send_mail(user_data: str, url_rapid7_ivm: str, mail_subject: str, mail_body_original: str):
    try:
        smtp_server = smtplib.SMTP(args.smtp_host, args.smtp_port, timeout=5)

        msg = multipart.MIMEMultipart()
        # マクロ置換
        mail_body = mail_body_original
        for key, value in user_data.items():
            mail_body = mail_body.replace("[[{:s}]]".format(key), str(value))

        if "name" in user_data["name"]:
            # 苗字(LAST NAME)分離
            matches = re.search("^([^\s]+)\s+(.+)$", user_data["name"])
            if matches:
                mail_body = mail_body.replace("[[last_name]]", matches[1])
                mail_body = mail_body.replace("[[first_name]]", matches[2])

        mail_body = mail_body.replace("[[url_rapid7_ivm]]", url_rapid7_ivm)

        msg["Subject"] = mail_subject
        msg["From"] = args.mail_from
        msg["to"] = user_data["email"]
        msg.attach(text.MIMEText(mail_body, "plain", "utf-8"))

        smtp_server.send_message(msg)

        smtp_server.quit()
    except Exception as ex:
        print(ex)


def get_user_id(login: str, url: str, headers: dict):
    login_id = None

    response = requests.get(url, verify=args.no_verify_certificate, headers=headers)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        raise SystemError("[ERROR] {:d} {:s}".format(response_json["status"], response_json["message"]))

    if "resources" in response_json:
        for authentication in response_json["resources"]:
            if authentication["login"] == login:
                login_id = authentication["id"]
                break

    if login_id is None and "links" in response_json:
        for link in response_json["links"]:
            if link["rel"] == "next":
                login_id = get_user_id(login, link["href"], headers)
                break

    return login_id


def get_role_id(role_name: str, url: str, headers: dict):
    role_id = None

    response = requests.get(url, verify=args.no_verify_certificate, headers=headers)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        raise SystemError("[ERROR] {:d} {:s}".format(response_json["status"], response_json["message"]))

    if "resources" in response_json:
        for role in response_json["resources"]:
            if role["name"] == role_name:
                role_id = role["id"]
                break

    if role_id is None and "links" in response_json:
        for link in response_json["links"]:
            if link["rel"] == "next":
                role_id = get_role_id(role_name, link["href"], headers)
                break

    return role_id


def get_site_id(site_name: str, url: str, headers: dict):
    site_id = None

    response = requests.get(url, verify=args.no_verify_certificate, headers=headers)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        raise SystemError("[ERROR] {:d} {:s}".format(response_json["status"], response_json["message"]))

    if "resources" in response_json:
        for site in response_json["resources"]:
            if site["name"] == site_name:
                site_id = site["id"]
                break

    if site_id is None and "links" in response_json:
        for link in response_json["links"]:
            if link["rel"] == "next":
                site_id = get_site_id(site_name, link["href"], headers)
                break

    return site_id


def create_user(user_data: dict, role_id: str, url: str, headers: dict):
    login_id = None

    payload: dict = {
        "email"                : user_data["email"],
        "enabled"              : user_data["enabled"],
        "login"                : user_data["login"],
        "name"                 : user_data["name"],
        "password"             : user_data["password"],
        "passwordResetOnLogin" : user_data["reset_password"],
        "role" : {
            "allAssetGroups" : False,
            "allSites"       : False,
            "id"             : role_id,
            "superuser"      : False
        }
    }

    if user_data["role"] == "global-admin":
        payload["role"]["allAssetGroups"] = True
        payload["role"]["allSites"] = True
        payload["role"]["superuser"] = True

    response = requests.post(url + "users", verify=args.no_verify_certificate, headers=headers, json=payload)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        print(response_json)
        raise Exception("[WARNING] {:d} {:s}".format(response_json["status"], response_json["message"]))

    if "id" in response_json:
        login_id = response_json["id"]

    return login_id


def update_site_access(login_id: int, site_id_list: list, url: str, headers: dict):
    url += "users/{:d}/sites".format(login_id)

    response = requests.put(url, verify=args.no_verify_certificate, headers=headers, json=site_id_list)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        print(response_json)
        raise Exception("[WARNING] {:d} {:s}".format(response_json["status"], response_json["message"]))


if __name__ == "__main__":
    main(args)
