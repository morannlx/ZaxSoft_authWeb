import os
import sys
import base64
import ttkbootstrap as ttk
from ttkbootstrap.dialogs import Messagebox
from ttkbootstrap.constants import *
import requests
import json
import re
from PIL import Image, ImageTk
import io
from code import CampusNetworkAuthLogic  # 导入功能逻辑类


# 终端类型
user_agents = {
    '1': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
    '2': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36 Edg/133.0.0.0'
}
# 校园网主地址
host = "http://10.9.9.9"
# 校园网wlanc名称
wlanacname = "GXVNU-BRAS"


class CampusNetworkAuthGUI(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=(20, 10))
        self.pack(fill=BOTH, expand=YES)
        self.master = master
        self.logic = CampusNetworkAuthLogic()  # 实例化功能逻辑类
        self.captcha_image = None
        self.x = None
        self.headers = None
        self.cookies_login = None  # 用于存储登录后的cookies


        # 标题
        hdr = ttk.Label(master=self, text="校园网认证", font=("Arial", 16, "bold"), bootstyle=PRIMARY)
        hdr.pack(fill=X, pady=10)

        # 账号输入
        self.user_id_entry = self.create_form_entry("校园网账号", "")

        # 密码输入
        self.password_entry = self.create_form_entry("密码", "", show="*")

        # 设备类型选择
        self.ua_var = ttk.StringVar(value='1')
        ua_frame = ttk.Frame(self)
        ua_frame.pack(fill=X, pady=5)
        ttk.Radiobutton(ua_frame, text="电脑端", variable=self.ua_var, value='1', bootstyle=PRIMARY).pack(side=LEFT,
                                                                                                          padx=10)
        ttk.Radiobutton(ua_frame, text="手机端", variable=self.ua_var, value='2', bootstyle=PRIMARY).pack(side=LEFT,
                                                                                                          padx=10)

        # 记住密码复选框
        self.remember_var = ttk.BooleanVar()
        ttk.Checkbutton(self, text="记住账号和密码", variable=self.remember_var, bootstyle=PRIMARY).pack(pady=5)

        # 状态显示
        self.status_label = ttk.Label(self, text="", font=("Arial", 10), bootstyle=INFO)
        self.status_label.pack(pady=5)

        # 按钮
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=X, pady=10)
        self.login_button = ttk.Button(button_frame, text="登录", command=self.login, bootstyle=SUCCESS)
        self.login_button.pack(side=LEFT, padx=10)
        self.logout_button = ttk.Button(button_frame, text="下线", command=self.logout, bootstyle=WARNING,state=DISABLED)
        self.logout_button.pack(side=LEFT, padx=10)
        self.get_list_button = ttk.Button(button_frame, text="获取在线设备", command=self.get_online_devices,bootstyle=INFO, state=DISABLED)
        self.get_list_button.pack(side=LEFT, padx=10)
        self.clear_mac_button = ttk.Button(button_frame, text="清除MAC绑定", command=self.clear_mac_binding,bootstyle=DANGER, state=DISABLED)
        self.clear_mac_button.pack(side=LEFT, padx=10)

        # 加载配置
        config = self.logic.load_config()
        if config:
            self.user_id_entry.insert(0, config.get("user_id", ""))
            self.password_entry.insert(0, config.get("password", ""))
            self.ua_var.set(config.get("ua_choose", "1"))

    def create_form_entry(self, label, default_value, show=None):
        """创建表单输入框"""
        container = ttk.Frame(self)
        container.pack(fill=X, pady=5)

        lbl = ttk.Label(master=container, text=label, width=10, bootstyle=SECONDARY)
        lbl.pack(side=LEFT, padx=5)

        entry = ttk.Entry(master=container, show=show)
        entry.insert(0, default_value)
        entry.pack(side=LEFT, padx=5, fill=X, expand=YES)
        return entry

    def login(self):
        user_id = self.user_id_entry.get()
        password = self.password_entry.get()
        selected_ua = self.ua_var.get()

        if not user_id or not password:
            Messagebox.show_warning("请输入账号和密码", "警告")
            return

        self.status_label.config(text="正在认证，请稍等...")
        login_success = self.logic.login(user_id, password, selected_ua)

        if login_success:
            self.status_label.config(text="认证成功，开始网上冲浪")
            self.save_config()
            self.logout_button.config(state=NORMAL)
            self.get_list_button.config(state=NORMAL)
            self.clear_mac_button.config(state=NORMAL)  # 登录成功后启用清除MAC绑定按钮
        else:
            self.status_label.config(text="认证失败")
            Messagebox.show_warning("认证失败，请检查账号、密码或网络连接", "错误")

    def save_config(self):
        if self.remember_var.get():
            config = {
                "user_id": self.user_id_entry.get(),
                "password": self.password_entry.get(),
                "ua_choose": self.ua_var.get()
            }
            self.logic.save_config(config)

    def logout(self):
        """执行下线操作"""
        if hasattr(self.logic, 'distoken') and hasattr(self.logic, 'wlanuserip'):
            logout_success = self.logic.logout()

            if logout_success:
                self.status_label.config(text="下线成功")
                Messagebox.show_info("提示:3秒后可再次登录", "成功下线")
                # 更新按钮状态
                self.logout_button.config(state=DISABLED)
                self.get_list_button.config(state=DISABLED)
                self.clear_mac_button.config(state=DISABLED)
                self.login_button.config(state=DISABLED)
                # 3秒后恢复登录按钮
                self.after(3000, lambda: self.login_button.config(state=NORMAL))
            else:
                Messagebox.show_warning("下线失败，请检查网络连接", "错误")
        else:
            Messagebox.show_warning("请先登录再执行下线操作", "错误")

    def get_online_devices(self):
        try:
            self.x = requests.session()
            r = self.x.post(f'{host}/self/tologin.do')
            response_data = json.loads(r.text)
            verifyCode = response_data.get("data", {}).get("verifyCode", "")

            if verifyCode:
                self.show_captcha_dialog(verifyCode)
            else:
                Messagebox.show_warning("验证码获取失败", "错误")
        except Exception as e:
            Messagebox.show_warning(f"连接失败: {str(e)}", "错误")

    def show_captcha_dialog(self, base64_data):
        """显示验证码输入弹窗"""
        self.captcha_window = ttk.Toplevel(self)
        self.captcha_window.title("输入验证码")
        self.captcha_window.geometry("300x180")

        try:
            img_data = base64.b64decode(base64_data)
            img = Image.open(io.BytesIO(img_data))
            self.captcha_image = ImageTk.PhotoImage(img)
            img = img.resize((200, 100), Image.LANCZOS)

            img_label = ttk.Label(self.captcha_window, image=self.captcha_image)
            img_label.pack(pady=5)
        except Exception as e:
            Messagebox.show_error("验证码加载失败", "错误")
            self.captcha_window.destroy()
            return

        self.captcha_entry = ttk.Entry(self.captcha_window, width=10)
        self.captcha_entry.pack(pady=5)
        self.captcha_entry.focus_set()

        ttk.Button(
            self.captcha_window,
            text="确认",
            command=self.on_captcha_submit,
            bootstyle=PRIMARY
        ).pack(pady=5)

    def on_captcha_submit(self):
        self.loginCode = self.captcha_entry.get()
        self.captcha_window.destroy()
        self.login_backend()

    def login_backend(self):
        login_data = {
            "accountId": self.user_id_entry.get(),
            "password": self.logic.get_md5(self.password_entry.get()),
            "verifyCode": self.loginCode
        }

        headers = {
            'Connection': 'keep-alive',
            'Content-Type': 'application/json;charset=UTF-8',
            'Referer': f'{host}/self/index.html'
        }

        try:
            response = self.x.post(
                f'{host}/self/login.do',
                headers=headers,
                data=json.dumps(login_data)
            )
            if json.loads(response.text).get("errmsg") == "操作成功":
                self.fetch_online_devices()
            else:
                Messagebox.show_warning("验证码错误", "登录失败")
        except Exception as e:
            Messagebox.show_warning(f"登录失败: {str(e)}", "错误")

    def fetch_online_devices(self):
        if hasattr(self, 'user_id_entry') and hasattr(self, 'x'):
            user_id = self.user_id_entry.get()
            headers = {
                'Connection': 'keep-alive',
                'Content-Type': 'application/json;charset=UTF-8',
                'Referer': f'{host}/self/index.html'
            }
            self.headers = headers
            data2 = {"accountId": user_id}
            try:
                r3 = self.x.post(f'{host}/self/getonline.do', headers=headers, data=json.dumps(data2))
                online_data = json.loads(r3.text)
                if online_data.get("success") and online_data.get("rows"):
                    self.online_devices = online_data["rows"]
                    self.show_online_devices()
                else:
                    Messagebox.show_info("当前没有在线设备", "提示")
            except Exception as e:
                Messagebox.show_warning(f"获取在线设备失败: {str(e)}", "错误")
        else:
            Messagebox.show_warning("请先登录再获取在线设备", "错误")

    def show_online_devices(self):
        # 单例模式管理弹窗
        if hasattr(self, 'device_window') and self.device_window.winfo_exists():
            self.device_window.lift()  # 置顶已有窗口
            return

        # 创建新弹窗
        self.device_window = ttk.Toplevel(self)
        self.device_window.title("在线设备")
        self.device_window.geometry("1000x500")  # 扩大窗口尺寸以容纳上线时间列
        self.device_window.resizable(False, False)

        # 创建表格容器
        table_frame = ttk.Frame(self.device_window)
        table_frame.pack(fill=BOTH, expand=YES, padx=10, pady=10)

        # 创建 Treeview 表格
        columns = ("设备ID", "系统信息", "IP地址", "MAC地址", "上线时间")  # 添加上线时间列
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", bootstyle=PRIMARY)
        tree.pack(fill=BOTH, expand=YES)

        # 设置列标题
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)

        # 添加数据行
        for device in self.online_devices:
            billingId = device.get("billingId", "N/A")
            osInfo = device.get("osInfo", "未知系统")
            accountIp = device.get("accountIp", "0.0.0.0")
            accountMac = device.get("accountMac", "未知MAC")
            onlineTime = device.get("onlineTime", "未知时间")  # 获取上线时间

            # 插入行数据
            tree.insert("", "end", values=(billingId, osInfo, accountIp, accountMac, onlineTime))

        # 将表格组件绑定到副窗口对象
        self.device_window.tree = tree

        # 添加按钮容器
        button_frame = ttk.Frame(self.device_window)
        button_frame.pack(fill=X, padx=10, pady=10, side=BOTTOM)

        # 添加下线单个设备按钮
        ttk.Button(
            button_frame,
            text="下线单个设备",
            command=lambda: self.logout_single_device_from_window(tree),
            bootstyle=DANGER
        ).pack(side=LEFT, padx=5)

        # 添加下线所有设备按钮
        ttk.Button(
            button_frame,
            text="下线所有设备",
            command=self.logout_all_devices,
            bootstyle=DANGER
        ).pack(side=LEFT, padx=5)

        # 添加刷新按钮
        ttk.Button(
            button_frame,
            text="刷新",
            command=self.refresh_online_devices,
            bootstyle=INFO
        ).pack(side=LEFT, padx=5)

    def refresh_online_devices(self):
        if hasattr(self, 'user_id_entry') and hasattr(self, 'x') and hasattr(self, 'headers'):
            user_id = self.user_id_entry.get()
            headers = self.headers
            data2 = {"accountId": user_id}
            try:
                r3 = self.x.post(f'{host}/self/getonline.do', headers=headers, data=json.dumps(data2))
                online_data = json.loads(r3.text)
                if online_data.get("success") and online_data.get("rows"):
                    self.online_devices = online_data["rows"]
                    if hasattr(self, 'device_window') and self.device_window.winfo_exists():
                        # 更新副窗口中的表格
                        self.update_device_table(self.device_window.tree, self.online_devices)
                else:
                    Messagebox.show_info("当前没有在线设备", "提示")
            except Exception as e:
                Messagebox.show_warning(f"获取在线设备失败: {str(e)}", "错误")
        else:
            Messagebox.show_warning("请先登录再获取在线设备", "错误")

    def update_device_table(self, tree, devices):
        # 清空现有表格数据
        for item in tree.get_children():
            tree.delete(item)

        # 重新插入新数据
        for device in devices:
            billingId = device.get("billingId", "N/A")
            osInfo = device.get("osInfo", "未知系统")
            accountIp = device.get("accountIp", "0.0.0.0")
            accountMac = device.get("accountMac", "未知MAC")
            onlineTime = device.get("onlineTime", "未知时间")  # 获取上线时间

            # 插入行数据
            tree.insert("", "end", values=(billingId, osInfo, accountIp, accountMac, onlineTime))

    def logout_single_device_from_window(self, tree):
        # 获取选中的设备
        selected_item = tree.focus()
        if selected_item:
            values = tree.item(selected_item, 'values')
            billingId = values[0]
            osInfo = values[1]
            accountIp = values[2]

            # 查找对应的设备数据
            for device in self.online_devices:
                if device.get("billingId") == billingId and device.get("osInfo") == osInfo and device.get("accountIp") == accountIp:
                    self.logout_single_device(device)
                    break
            # 刷新设备列表
            self.refresh_online_devices()
        else:
            Messagebox.show_warning("请选择要下线的设备", "提示")

    def logout_single_device(self, device):
        """下线单个设备"""
        billingId = device.get("billingId")
        accountIp = device.get("accountIp")
        serverIp = device.get("serverIp")

        loginout_data = {
            "accountId": self.user_id_entry.get(),
            "accountIp": accountIp,
            "billingId": billingId,
            "serverIp": serverIp
        }

        try:
            out = self.x.post(f'{host}/self/kickonline.do',headers=self.headers,data=json.dumps(loginout_data))
            if json.loads(out.text).get("success"):
                Messagebox.show_info(f"设备 {billingId} 下线成功", "操作成功")
                # 刷新设备列表
                self.refresh_online_devices()
        except Exception as e:
            print(f"下线设备 {billingId} ({accountIp}) 失败: {e}")

    def logout_all_devices(self):
        if hasattr(self, 'online_devices') and hasattr(self, 'x') and hasattr(self, 'headers'):
            headers = self.headers
            logout_count = 0
            for device in self.online_devices:
                billingId = device.get("billingId", "")
                accountIp = device.get("accountIp", "")
                serverIp = device.get("serverIp", "")
                if not billingId or not accountIp or not serverIp:
                    continue

                loginout_data = {
                    "accountId": self.user_id_entry.get(),
                    "accountIp": accountIp,
                    "billingId": billingId,
                    "serverIp": serverIp
                }

                try:
                    out = self.x.post(f'{host}/self/kickonline.do', headers=headers, data=json.dumps(loginout_data))
                    response_data = json.loads(out.text)
                    if response_data.get("success"):
                        logout_count += 1
                except Exception as e:
                    print(f"下线设备 {billingId} ({accountIp}) 失败: {e}")

            Messagebox.show_info(f"成功下线 {logout_count} 个设备", "提示")
            # 刷新设备列表
            self.refresh_online_devices()
        else:
            Messagebox.show_warning("请先获取在线设备", "错误")

    def clear_mac_binding(self):
        """清除MAC绑定"""
        if not hasattr(self.logic, 'cookies_login') or not self.logic.cookies_login:
            Messagebox.show_warning("请先登录再进行操作", "提示")
            return

        try:
            # 获取MAC1和MAC2的值
            url = f'{host}/self/toRemoveMac.do?userId={self.user_id_entry.get()}'
            headers = {
                'User-Agent': user_agents.get(self.ua_var.get(), user_agents['1'])
            }
            r = requests.get(url, headers=headers, cookies=self.logic.cookies_login)
            mac1_match = re.search(r'id="accountMac1" value="([^"]+)"', r.text)
            mac2_match = re.search(r'id="accountMac2" value="([^"]+)"', r.text)
            mac1 = mac1_match.group(1) if mac1_match else "未找到 MAC1"
            mac2 = mac2_match.group(1) if mac2_match else "未找到 MAC2"

            # 显示MAC地址并选择要清除的MAC
            mac_window = ttk.Toplevel(self)
            mac_window.title("MAC地址")
            mac_window.geometry("400x250")  # 增大窗口宽度
            mac_window.resizable(False, False)

            # 使用Frame容器来更好地组织布局
            content_frame = ttk.Frame(mac_window, padding=20)
            content_frame.pack(fill=BOTH, expand=YES)

            # MAC地址显示区域
            ttk.Label(content_frame, text="MAC1:", font=("Arial", 10, "bold"), bootstyle=PRIMARY).grid(row=0, column=0,sticky=W, pady=5)
            mac1_label = ttk.Label(content_frame, text=mac1, font=("Arial", 10), bootstyle=PRIMARY)
            mac1_label.grid(row=0, column=1, sticky=W, pady=5)
            mac1_label.configure(wraplength=200)  # 设置文本换行

            ttk.Label(content_frame, text="MAC2:", font=("Arial", 10, "bold"), bootstyle=PRIMARY).grid(row=1, column=0,sticky=W, pady=5)
            mac2_label = ttk.Label(content_frame, text=mac2, font=("Arial", 10), bootstyle=PRIMARY)
            mac2_label.grid(row=1, column=1, sticky=W, pady=5)
            mac2_label.configure(wraplength=200)  # 设置文本换行

            # 按钮区域
            button_frame = ttk.Frame(content_frame)
            button_frame.grid(row=2, column=0, columnspan=2, pady=20)

            ttk.Button(
                button_frame,
                text="清除MAC1",
                command=lambda: [self.do_clear_mac('1'), mac_window.destroy()],
                bootstyle=DANGER
            ).pack(side=LEFT, padx=5)

            ttk.Button(
                button_frame,
                text="清除MAC2",
                command=lambda: [self.do_clear_mac('2'), mac_window.destroy()],
                bootstyle=DANGER
            ).pack(side=LEFT, padx=5)

            ttk.Button(
                button_frame,
                text="清除所有",
                command=lambda: [self.do_clear_mac('1'), self.do_clear_mac('2'), mac_window.destroy()],
                bootstyle=DANGER
            ).pack(side=LEFT, padx=5)

        except Exception as e:
            Messagebox.show_warning(f"获取MAC地址失败: {str(e)}", "错误")

    def do_clear_mac(self, clear_type):
        """执行清除MAC操作"""
        if not hasattr(self.logic, 'cookies_login') or not self.logic.cookies_login:
            Messagebox.show_warning("请先登录再进行操作", "提示")
            return

        try:
            url = f'{host}/self/clearusermac.do'
            headers = {
                'User-Agent': user_agents.get(self.ua_var.get(), user_agents['1'])
            }
            data = {
                'accountId': self.user_id_entry.get(),
                'clearType': clear_type
            }
            response = requests.post(url, headers=headers, cookies=self.logic.cookies_login, json=data, verify=False)

            if "操作成功" in response.text:
                Messagebox.show_info(f"清除MAC{clear_type}成功", "操作成功")
            else:
                Messagebox.show_warning(f"清除MAC{clear_type}失败", "操作失败")
        except Exception as e:
            Messagebox.show_warning(f"清除MAC失败: {str(e)}", "错误")


if __name__ == "__main__":
           #设置窗口图标
        app = ttk.Window("校园网认证", "superhero", resizable=(False, False))
        try:
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))

            icon_path = os.path.join(base_path, "favicon.ico")
            app.iconbitmap(icon_path)
        except Exception as e:
            print(f"设置图标时出错: {e}")

        CampusNetworkAuthGUI(app)
        app.mainloop()