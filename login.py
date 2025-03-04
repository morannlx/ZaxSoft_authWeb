import requests
#终端类型
user_agents = {
    '1': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
    '2': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36 Edg/133.0.0.0'
}

def make_post_request(user_id, password, user_agent):
    # 请求的 URL
    url = "http://10.9.9.9/webauth.do?wlanacip=10.9.9.7&wlanacname=GXVNU-BRAS"

    # 请求头
    headers = {
        'User-Agent': user_agent
    }

    # POST 数据
    data = {
        'scheme': 'http',
        'serverIp': 'tomcat_server%3A80',
        'hostIp': 'http%3A%2F%2F127.0.0.1%3A8081%2F',
        'loginType': '',
        'auth_type': '0',
        'isBindMac1': '1',
        'pageid': '1',
        'templatetype': '1',
        'listbindmac': '1',
        'recordmac': '0',
        'isRemind': '1',
        'loginTimes': '',
        'groupId': '',
        'distoken': '',
        'echostr': '',
        'url': '',
        'isautoauth': '',
        'userId': user_id,
        'passwd': password,
        'remInfo': 'on'
    }

    try:
        print("正在认证，请稍等……")
        response = requests.post(url, headers=headers, data=data)

        if response.status_code == 200:
            if "密码错误" in response.text:
                # 返回账号密码填写
                print("账号或密码错误，请重新登录")
                return False

            elif "auth_success" in response.text:
                print("成功上线，开始网上冲浪")
                return True
        else:
            print("网络错误，请检查是否连接校园网")
            return True

    except requests.exceptions.RequestException as e:

        print(f"Request Error: 网络错误，请检查是否连接校园网")
        return True


# 脚本入口
if __name__ == "__main__":
    while True:
        user_id = input("输入你的校园网账号: ")
        password = input("输入你的密码: ")
        ua_choose = input("模拟设备登录，1为电脑端，2为手机端: ")

        selected_ua = user_agents.get(ua_choose, user_agents['1'])  # 默认为电脑端

        if make_post_request(user_id, password, selected_ua):
            break