#!/usr/bin/env python3

import argparse
import base64
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
    description='Rapid7 Insight VM API Tools - reset password')

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

    mail_subject: str = "[Rapid7 Insight VM] Password reset"
    mail_body_original: str = """
こちらは脆弱性管理システム(Rapid7 Insight VM)のPasswordリセットメールとなります

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

    user: list = []

    while True:
        login: str = input("Input user login:")

        user_data: dict = {
            "login": login,
            "name" :  None,
            "email": None,
            "password": None,
            "enabled": True,
            "reset_password": True,
            "send_email": True
        }

        login_id: int = None

        try:
            login_id = get_user_id(login, url_rapid7_ivm_api + "users", headers)
        except SystemError as ex:
            print(ex)
            continue

        if login_id is None:
            print("[WARNING]", "User {:s} is not found".format(login))
            continue

        try:
            data = get_user(login_id, url_rapid7_ivm_api, headers)
        except SystemError as ex:
            print(ex)
            continue

        user_data["name"] = data["name"]
        user_data["email"] = data["email"]
        user_data["password"] = get_random_password_string(args.generate_password_length)
        user_data["enabled"] = data["enabled"]

        print("[INFO]", "User {:s} is found".format(login))
        check: str = input("Can I really reset password? (y/Y):")
        if not any([check == "y", check == "Y"]):
            print("[WARNING]", "break")
            continue

        try:
            password_reset(login_id, user_data["password"], url_rapid7_ivm_api, headers)
        except Exception as ex:
            print(ex)
            continue
        print("[SUCCESS]", "User {:s} is password reset".format(login))

        if user_data["send_email"] == True:
            send_mail(user_data, url_rapid7_ivm, mail_subject, mail_body_original)


def convert_bool(value: str) -> bool:
    if any([value == "", value == "FALSE", value == "False", value == "false", value == "0"]):
        return False
    return True


def get_random_password_string(length) -> str:
    pass_chars = string.ascii_letters
    password = ''.join(secrets.choice(pass_chars) for x in range(length))

    pass_chars = string.digits
    password += secrets.choice(pass_chars)

    pass_chars = string.punctuation
    password += secrets.choice(pass_chars)

    return password


def send_mail(user_data: str, url_rapid7_ivm: str, mail_subject: str, mail_body_original: str) -> None:
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


def get_user_id(login: str, url: str, headers: dict) -> int:
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

def get_user(login_id: int, url: str, headers: dict) -> dict:
    url += "users/{:d}".format(login_id)

    response = requests.get(url, verify=args.no_verify_certificate, headers=headers)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        print(response_json)
        raise Exception("[WARNING] {:d} {:s}".format(response_json["status"], response_json["message"]))

    return response_json


def password_reset(login_id: int, password: str, url: str, headers: dict) -> None:
    url += "users/{:d}/password".format(login_id)

    payload: dict = {
        "password" : password
    }

    response = requests.put(url, verify=args.no_verify_certificate, headers=headers, json=payload)
    response_json = response.json()

    if "status" in response_json and response_json["status"] != 200:
        print(response_json)
        raise Exception("[WARNING] {:d} {:s}".format(response_json["status"], response_json["message"]))


if __name__ == "__main__":
    main(args)
