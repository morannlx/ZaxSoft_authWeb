# GVVNU-CONNECT
广西职业师范学院校园网小助手

# 如何使用？
## Windows10/11
**Windows系统已打包成exe程序，可直接下载运行，下载请前往Release**

**脚本运行方法：**
安装python(3.5以上版本)，打开cmd导入库，
```
pip install requests
```
随后在文件目录下运行
```
python login-v2.py
```
## Linux/openwrt
## 登录
打开`login.sh`，填入你的账号密码，`User-agent`为自定义登录设备，此处填入浏览器ua即可，默认为`塞班ua`（占用Windows端），完成填写后，直接用Linux终端运行sh即可，**注意：需要系统支持curl**

## 登出
首先进行一次正常网络认证，拨号成功后，按`f12`进入`开发者工具`，查看页面源码，滑到第100行：
```
<input id="distoken" name="distoken" type="hidden" value="bee09bc484f71fc826cdf5f541d244bf" />
```
将value值复制，把它填入`loginout.sh`脚本的distoken，随后运行脚本即可退出

# 此脚本的作用？
可以在没有gui的系统上进行web认证，也可以设置开机自动进行网络认证
