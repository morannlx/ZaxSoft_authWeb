import requests
import json
import re
import hashlib
# 终端类型
user_agents = {
    '1': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
    '2': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36 Edg/133.0.0.0'
}
# 校园网主地址
host = 'http://10.9.9.9'
# 校园网wlanc名称
wlanacname = "GXVNU-BRAS"


class CampusNetworkAuthLogic:
    def __init__(self):
        self.config = self.load_config()
        self.captcha_image = None
        self.x = None
        self.headers = None
        self.cookies_login = None  # 用于存储登录后的cookies
        self.online_devices = []

    def load_config(self):
        try:
            with open("../saved_config.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def save_config(self, config):
        with open("../saved_config.json", "w") as f:
            json.dump(config, f)

    def make_post_request(self, user_id, password, user_agent):
        url = f"{host}/webauth.do?wlanacip=10.9.9.7&wlanacname={wlanacname}"
        headers = {'User-Agent': user_agent}
        data = {
            'scheme': 'http',
            'serverIp': 'tomcat_server%3A80',
            'hostIp': 'http%3A%2F%2F127.0.0.1%3A8081%2F',
            'pageid': '1',
            'userId': user_id,
            'passwd': password,
        }

        try:
            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                if "密码错误" in response.text:
                    return False, None, None
                elif "auth_success" in response.text:
                    distoken = re.search(r'<input id="distoken" name="distoken" type="hidden" value="([^"]+)"',
                                         response.text)
                    wlanuserip = re.search(r'<input id="wlanuserip" name="wlanuserip" type="hidden" value="([^"]+)"',
                                           response.text)
                    if distoken and wlanuserip:
                        self.cookies_login = response.cookies.get_dict()  # 获取登录后的cookies
                        return True, distoken.group(1), wlanuserip.group(1)
            return False, None, None
        except requests.exceptions.RequestException:
            return False, None, None

    def login(self, user_id, password, selected_ua):
        user_agent = user_agents.get(selected_ua, user_agents['1'])

        login_success, distoken, wlanuserip = self.make_post_request(user_id, password, user_agent)

        if login_success and distoken and wlanuserip:
            self.distoken = distoken
            self.wlanuserip = wlanuserip
            self.user_id = user_id
            self.password = password
            return True
        return False

    def make_logout_request(self, user_id, password, distoken, wlanuserip):
        url = f"{host}/httpservice/appoffline.do?wlanacip=&wlanacname={wlanacname}&userId={user_id}&passwd={password}&mac=&wlanuserip={wlanuserip}&distoken={distoken}"
        try:
            response = requests.post(url)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def logout(self):
        if hasattr(self, 'distoken') and hasattr(self, 'wlanuserip'):
            logout_success = self.make_logout_request(
                self.user_id,
                self.password,
                self.distoken,
                self.wlanuserip
            )
            return logout_success
        return False


    def get_md5(self, v):
        md5 = hashlib.md5()
        md5.update(v.encode('utf-8'))
        return md5.hexdigest()