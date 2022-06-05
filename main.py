import base64
import os
import threading
import requests
from lxml import etree
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pksc1_v1_5
from Crypto.PublicKey import RSA


# from apscheduler.schedulers.blocking import BlockingScheduler


def login_token():
    url = "http://210.40.176.165/"
    payload = {}
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Host': '210.40.176.165',
        'Pragma': 'no-cache',
        'Referer': 'http://210.40.176.165/login/enterMain/',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.36'
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    res = etree.HTML(response.text)
    data_public_key = res.xpath('//*[@id="password"]/@data-public-key')[0]
    token = response.cookies['JSESSIONID']
    # print(token)
    return data_public_key, token, response.cookies


def encrpt(password, public_key):
    public_key = '-----BEGIN PUBLIC KEY-----\n' + public_key + '\n-----END PUBLIC KEY-----'
    rsakey = RSA.importKey(public_key)
    cipher = Cipher_pksc1_v1_5.new(rsakey)
    password = str(password)  # 密码为int类型时需要转化为str类型
    cipher_text = base64.b64encode(cipher.encrypt(password.encode()))
    return cipher_text.decode()


def login(loginId, pwd, token, pub_key, cookies):
    password = encrpt(pwd, pub_key)
    url = "http://210.40.176.165/login/signin"
    info = '{"loginId":"' + loginId + '", "password":"' + password + '", "verifyCode": null, "isWeekPassword": false}'
    # info = parse.urlencode(info)
    payload = {
        'loginForm': info,
        'token': token
    }
    headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        # 'Content-Length': '348',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Host': '210.40.176.165',
        'Origin': 'http://210.40.176.165',
        'Pragma': 'no-cache',
        'Referer': 'http://210.40.176.165/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.36',
        'X-Requested-With': 'XMLHttpRequest',
        'screenHeight': '1080',
        'screenWidth': '1920',
        'Cookie': f'JSESSIONID={token}'
    }
    # form_data =  parse.urlencode(form_data)
    # form_data = json.dumps(payload)
    response = requests.request("POST", url, headers=headers, data=payload, cookies=cookies)
    print(response.text)


def login_enterMain(c):
    url = "http://210.40.176.165/login/enterMain"
    # payload = {}
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Host': '210.40.176.165',
        'Pragma': 'no-cache',
        'Referer': 'http://210.40.176.165/',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.36'
    }
    response = requests.request("GET", url, headers=headers, cookies=c)
    # print(response.text)
    res = etree.HTML(response.text)
    username = res.xpath('//*[@id="ez-adm-header-user"]/span[4]/text()')[0]
    print(username, '登录成功！')


def twdk(tbxx, token, cookie):
    url = "http://210.40.176.165/xg/twgl/submitTbxx4Xs"
    payload = {
        'tbxx': tbxx,
        'token': token
    }
    headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Content-Length': '1182',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Host': '210.40.176.165',
        'Origin': 'http://210.40.176.165',
        'Pragma': 'no-cache',
        'Referer': 'http://210.40.176.165/login/enterMain/xg/twgl/enterTbTwxxcj4Xs',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.39',
        'X-Requested-With': 'XMLHttpRequest'
    }
    response = requests.request("POST", url, headers=headers, data=payload, cookies=cookie)
    print(response.text)


def getContextData(token, cookies):
    url = "http://210.40.176.165/sysCommon/getContextData"
    payload = 'key=tbxx&token=' + token
    headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Content-Length': '47',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Host': '210.40.176.165',
        'Origin': 'http://210.40.176.165',
        'Pragma': 'no-cache',
        'Referer': 'http://210.40.176.165/login/enterMain/xg/twgl/enterTbTwxxcj4Xs',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.39',
        'X-Requested-With': 'XMLHttpRequest'
    }
    response = requests.request("POST", url, headers=headers, data=payload, cookies=cookies)
    if response.text == 'false':
        print('今天已经打卡！')
        print(enterTbTwxxcj4Xs(cookies))  # 增加一个检测功能
    else:
        tbxx = response.text
        twdk(tbxx, token, cookies)
        print(enterTbTwxxcj4Xs(cookies))


def enterTbTwxxcj4Xs(cookies):
    '''
    :param cookies: cookie
    :return: 签到的信息返回值
    '''
    url = "http://210.40.176.165/xg/twgl/enterTbTwxxcj4Xs"
    payload = {}
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Host': '210.40.176.165',
        'Pragma': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.39'
    }
    response = requests.request("GET", url, headers=headers, data=payload, cookies=cookies)
    res = etree.HTML(response.text)
    resp = res.xpath('/html/body/div/ol/li[2]/text()')[0]
    return resp


def total(loginId, pwd):
    data_public_key, token, cookies = login_token()
    login(loginId, pwd, token, data_public_key, cookies)
    login_enterMain(cookies)
    resp = enterTbTwxxcj4Xs(cookies)
    if '未提交' in str(resp):
        tbxx = getContextData(token, cookies)
        twdk(tbxx, token, cookies)
    else:
        print(resp)


def main():
    if os.path.exists('./config.txt'):
        configs = open('./config.txt', 'r', encoding='utf-8').read()
        username_list = configs.split('\n')
        a = []
        b = []
        for i in username_list:
            for item in i.split(', '):
                a.append(item)
            b.append(a)
        for i in username_list:  # 使用循环来执行多个账号
            for item in i.split(', '):
                loginId = item[0]
                pwd = item[1]
                # total(loginId, pwd)
                # print('执行完成')
                my_threading = threading.Thread(target=total, args=(loginId, pwd))
                my_threading.start()



if __name__ == "__main__":
    # print("⏲ 请输入定时时间（默认每天7:05）")
    # hour = input("\thour: ") or 7
    # minute = input("\tminute: ") or 5
    # scheduler = BlockingScheduler(timezone='Asia/Shanghai')
    # scheduler.add_job(main, 'cron', hour=hour, minute=minute)  # args=[],  这里使用的是个人账号
    # print('⏰ 已启动定时程序，每天 %02d:%02d 为您打卡' % (int(hour), int(minute)))
    # print('Press Ctrl+{0} to exit'.format('Break' if os.name == 'nt' else 'C'))
    # try:
    #     scheduler.start()
    # except (KeyboardInterrupt, SystemExit):
    #     pass
    main()


def main_handler(event, context):
    # print(__js_engine.call('get_jqParam', '2028378636.25636375', '2021/10/1 9:39:03', '104551951'))
    return main()
