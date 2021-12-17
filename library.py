from bs4 import BeautifulSoup
from random import randrange
import base64
import random
import requests
import pandas as pd
import datetime
import time
import re
import requests
import AES
from config import *


class CSULoginHelper:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.key = None
        self.aes_crypt = None
        self.base_url = 'http://libzw.csu.edu.cn/cas/index.php?callback=http://libzw.csu.edu.cn/home/web/f_second'
        self.login_url = 'https://ca.csu.edu.cn/authserver/login?service=http%3A%2F%2Flibzw.csu.edu.cn%2Fcas%2Findex.php%3Fcallback%3Dhttp%3A%2F%2Flibzw.csu.edu.cn%2Fhome%2Fweb%2Ff_second'
        self.save_url = "https://wxxy.csu.edu.cn/ncov/wap/default/save"
        self.info = None
        self.sess = requests.Session()

    def login(self):
        def __login_passwd_aes(mode=AES.MODE_CBC):
            def __random_str(num):
                chars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
                return ''.join([chars[randrange(len(chars))] for i in range(num)])

            passwd_with_salt, iv = __random_str(
                64) + self.password, __random_str(16)
            self.aes_crypt = AESCrypt(self.key, mode, iv, passwd_with_salt)
            return self.aes_crypt.encrypt()

        # try:
        login_res = self.sess.get(self.base_url, allow_redirects=True)
        # print(login_res.text)
        login_html = login_res.content.decode()
        login_soup = BeautifulSoup(login_html, "html.parser")
        login_form = login_soup.find("form", id="pwdFromId")
        self.key = login_form.find("input", id="pwdEncryptSalt")['value']
        pwd = __login_passwd_aes()
        # print(pwd)
        login_data = {
            "username": self.username,
            "password": pwd,
            "captcha": '',
            "rememberMe": login_form.find("input", id="rememberMe")['value'],
            "_eventId": login_form.find("input", id="_eventId")['value'],
            "cllt": login_form.find("input", id="cllt")['value'],
            "dllt": login_form.find("input", id="dllt")['value'],
            "lt": login_form.find("input", id="lt")['value'],
            "execution": login_form.find("input", id="execution")['value']
        }
        # session中cookies单点登录相关的key改变
        r = self.sess.post(self.login_url, data=login_data,
                           allow_redirects=True)
        # print(r.headers)
        try:
            access_token = r.cookies['access_token']
            return access_token
        except:
            print('也许密码输错了？')
            return "what's wrong?"
        # except Exception as e:
        # print("中南大学统一登录过程出错")
        # exit(1)


class AESCrypt:
    """
    csu encrypt.js实现过程如下：
    function getAesString(data, key0, iv0) {
        key0 = key0.replace(/(^\s+)|(\s+$)/g, "");
        var key = CryptoJS.enc.Utf8.parse(key0);
        var iv = CryptoJS.enc.Utf8.parse(iv0);
        var encrypted = CryptoJS.AES.encrypt(data, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        return encrypted.toString();
    }
    function encryptAES(data, aesKey) {
        if (!aesKey) {
            return data;
        }
        var encrypted = getAesString(randomString(64) + data, aesKey, randomString(16));
        return encrypted;
    }
    var $aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
    var aes_chars_len = $aes_chars.length;
    function randomString(len) {
        var retStr = '';
        for (i = 0; i < len; i++) {
            retStr += $aes_chars.charAt(Math.floor(Math.random() * aes_chars_len));
        }
        return retStr;
    }
    """

    def __init__(self, key, mode, iv, data):
        self.key = key.encode('utf-8')
        self.mode = mode
        self.iv = iv.encode('utf-8')
        self.data = self.pkcs7(data)
        self.cipher = AES.new(self.key, self.mode, self.iv)
        self.encryptedStr = None

    def encrypt(self):
        self.encryptedStr = base64.b64encode(self.cipher.encrypt(self.data))
        return self.encryptedStr

    def pkcs7(self, data, block_num=16):
        """
        填充规则：如果长度不是block_num的倍数，余数使用余数进行补齐
        :return:
        """
        pad = block_num - len(data.encode('utf-8')) % block_num
        data = data + pad * chr(pad)
        return data.encode('utf-8')


def get_header():
    user_agents = [
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36 OPR/26.0.1656.60',
        'Opera/8.0 (Windows NT 5.1; U; en)',
        'Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.50',
        'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 9.50',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        'Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
        'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.133 ',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36'
    ]
    headers = {
        "Host": "libzw.csu.edu.cn",
        "Connection": "keep-alive",
        # "Content-Length": "86",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": user_agents[random.randint(0, 10)],
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "http://libzw.csu.edu.cn",
        "Referer": "www.baidu.com",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    }
    return headers


def get_map_areaNumber2areaTureID(save=False):
    def fix_BenBu_areaName(area):
        area_name = area['nameMerge']
        if area_name is None:
            area_name = area['name']
            if area_name[0] == 'C':
                area_name = '本部-二楼-二楼C区'
            elif area_name[0] == 'D':
                area_name = '本部-二楼-三楼D区'
        areaABCD = r.findall(area_name)[0]
        area_name = area_name[:6] + areaABCD
        return area_name
    tree = {'X': {}, 'B': {}}
    url = 'http://libzw.csu.edu.cn/api.php/areas/20/tree/1'
    r = requests.get(url=url, headers=get_header())
    librarys = pd.DataFrame(r.json()['data']['list'])
    BENBU = 2
    XINXIAO = 0
    mapping1 = {}
    mapping2 = {}
    f = {
        '新校区': 'X',
        '本部': 'B',
        '二楼': 'F2',
        '三楼': 'F3',
        '四楼': 'F4',
        '五楼': 'F5',
        '六楼': 'F6',
        '七楼': 'F7',
    }
    r = re.compile(r'\w区')
    for school_idx in [XINXIAO, BENBU]:
        library = librarys.loc[school_idx]
        SCHOOL_XTB = ['X', 'T', 'B'][school_idx]
        floors = pd.DataFrame(library['_child'])
        floor_count = 1
        for floor in floors['_child']:
            floor_count += 1
            tree[SCHOOL_XTB]['F'+str(floor_count)] = {}
            areas = pd.DataFrame(floor)
            for i in range(areas.shape[0]):
                area = areas.loc[i]
                area_id = area['id']
                area_name = area['nameMerge']
                if school_idx == BENBU:
                    area_name = fix_BenBu_areaName(area)
                schoolArea, floor, area = area_name.split('-')
                if school_idx == XINXIAO and len(area) != 2:
                    continue
                schoolArea, floor, area = f[schoolArea], f[floor], area[0]
                area_ture_id = schoolArea+floor+area
                mapping1[area_ture_id] = str(area_id)
                mapping2[str(area_id)] = area_ture_id
                tree[schoolArea][floor][area] = {
                    'area_info': (str(area_id), area_ture_id)}
    if save:
        data_list = []
        keys = list(mapping1.keys())
        values = list(mapping1.values())
        for i in range(len(mapping1)):
            data = {'true_id': keys[i], 'area_id': values[i]}
            data_list.append(data)
            df = pd.DataFrame(data_list)
            df.to_csv('area_map.csv')
    return mapping1, mapping2, tree


def get_segment(area, today):
    r = requests.get(url='http://libzw.csu.edu.cn/api.php/areadays/'+str(area),
                     headers=get_header()
                     )
    data_dicts = r.json()['data']['list']
    available_segment = []
    for data in data_dicts:
        available_segment.append(data['id'])
    # print(available_segment)
    if today:
        return str(min(available_segment))
    else:
        return str(max(available_segment))


def get_token1(user, password):
    try:
        # r = requests.get('http://libzw.csu.edu.cn/api.php/login/', headers=get_header(),
        #                  params={
        #     'username': user,
        #     'password': password,
        #     # 'callback':'http://libzw.csu.edu.cn/web/seat3?area=79'
        #     'from': 'mobile'
        # })
        r = requests.get('http://libzw.csu.edu.cn/Api/auto_user_check/', headers=get_header(),
                         params={
            'user': user,
            'p': password,
            'callback': 'www.baidu.com'
        })
        # print(r.headers['Set-Cookie'])
        token = r.headers['Set-Cookie'].split('token=')[1][:32]
        # s = r.json()['data']['_hash_']
        # userid = s['userid']
        # access_token = s['access_token']
        return True, token

    except:
        print('登录失败', r.json())
        return False, ''


def get_token2(user, password):
    try:
        # r = requests.get('http://libzw.csu.edu.cn/api.php/login/', headers=get_header(),
        #                  params={
        #     'username': user,
        #     'password': password,
        #     # 'callback':'http://libzw.csu.edu.cn/web/seat3?area=79'
        #     'from': 'mobile'
        # })
        r = requests.get('http://libzw.csu.edu.cn/api.php/login/', headers=get_header(),
                         params={
            'username': user,
            'p': password,
            'callback': 'http://libzw.csu.edu.cn/web/seat3?area=79'
        })
        print(r.json())
        s = r.json()['data']['_hash_']
        userid = s['userid']
        access_token = s['access_token']
        return True, access_token

    except:
        print('登录失败', r.json())
        return False, ''


def get_token3(user, password):
    helper = CSULoginHelper(user, password)
    token = helper.login()
    return token


def area_TrueID2char(s):
    a = {'X': '新校', 'B': '本部'}
    b = {
        'F2': '二楼',
        'F3': '三楼',
        'F4': '四楼',
        'F5': '五楼',
        'F6': '六楼',
        'F7': '七楼',
    }
    output = a[s[0]]+'-'+b[s[1:3]]+'-'+s[-1]+'区'
    return output


def get_single_area_info(area_id, today=True):

    segment = get_segment(area_id, today)
    ts = datetime.datetime.now()
    date = ts.date()
    time = ts.time().strftime('%H:%M')
    response = requests.get(
        headers=get_header(),
        url='http://libzw.csu.edu.cn/api.php/spaces_old'        # url='http://libzw.csu.edu.cn//api.php/spaces_old?\
        #     area='+str(area) +\
        #     '&segment='+str(segment)+\
        #     '&day='+date+\
        #     '&startTime='+time+'\
            #     &endTime=22:00',
        , params={
            'area': str(area_id),
            'segment': str(segment),
            'day': date.isoformat() if today else date+datetime.timedelta(days=1),
            'startTime': time if today else "7:30",
            'endTime': '22:00',
        }
    )
    # response.encoding = 'utf-8-sig'
    df_area = pd.DataFrame(response.json()['data']['list'], columns=[
        'id', 'status_name', 'name'])
    df_area = df_area[df_area['status_name'] != STATUS['lock']]
    area_true_id = AREA_MAP_ID2TRUE[area_id]
    return {'ch': area_TrueID2char(area_true_id), 'segment': segment, 'area_true_id': area_true_id, 'area_id': area_id, 'df': df_area}


def dfs_TREE(tree, function=lambda x: x):
    res = []
    d1 = list(tree.values()) if type(tree) == dict else tree
    for i in range(len(d1)):
        d2 = list(d1[i].values())if type(d1[i]) == dict else d1[i]
        res.append([])
        for j in range(len(d2)):
            d3 = list(d2[j].values())if type(d2[j]) == dict else d2[j]
            res[i].append([])
            for k in range(len(d3)):
                value = d3[k]
                # print(value)
                f_value = function(value)
                # print(f_value)
                res[i][j].append(f_value)
    return res


def get_all_seat_info(today=True):
    return dfs_TREE(tree=TREE, function=lambda x: get_single_area_info(x['area_info'][0], today))


def get_seat_info(areas, today=True):
    depth = 0
    current = areas.copy()
    while type(current) != list:
        depth += 1
        current = current[0]
    while depth > 0:
        pass
    res = []
    for area in areas:
        single_area_info = get_single_area_info(area, today)
        # df_area = pd.DataFrame(response.json()['data']['list'])
        res.append(single_area_info)
    return res


def regular_search_area(s, output_TrueID=True):
    res = []
    s_length = len(s)
    if s_length <= 2:
        key_msg = [s[0]]
    elif s_length <= 3:
        key_msg = [s[0], 'F'+s[2]]
    else:
        key_msg = [s[0], 'F'+s[2], s[3]]
    cur_tree = TREE.copy()
    for i in range(len(key_msg)):
        try:
            cur_tree = cur_tree[key_msg[i]]
        except:
            print('输入有误')
            break
    stack = [cur_tree]
    while len(stack) > 0:
        # print(stack)
        p = stack.pop(0)
        for key, value in p.items():
            if key == 'area_info':
                if output_TrueID:
                    res.append(value[1])
                else:
                    res.append(value[0])

            else:
                stack.append(value)
    return res


def book_seat(seat_id, segment):
    token = get_token3(USERNAME, PASSWORD)
    response = requests.post(
        headers=get_header(),
        url='http://libzw.csu.edu.cn/api.php/spaces/'+str(seat_id)+'/book',
        data={
            'userid': USERNAME,
            'access_token': token,
            'segment': str(segment),
            'type': 1
        },
        cookies=''
    )
    return response


def get_profile(username, token):
    r = requests.get(url='http://libzw.csu.edu.cn/api.php/profile/books',
                     headers=get_header(),
                     params={
                         'userid': username,
                         'access_token': token
                     })
    return pd.DataFrame(r.json()['data']['list'])


def find_free_seat(seat_info):
    free_seatID = []
    for i in range(len(seat_info)):
        info = seat_info[i]
        df = info['df']
        segment = info['segment']
        df_free = df[df['status_name'] == STATUS['free']]
        if df_free.shape[0] == 0:
            print('> %s 区座位已满' % area_TrueID2char(info['area_true_id']))
        else:
            free_id = df_free['id'].tolist()
            true_id = df_free['name'].tolist()
            free_seatID.append(
                {'free_id': free_id, 'segment': segment, 'area': df_free['id'],
                 'true_id': true_id})
            # ======== 输出
            # for i in range(len(free_id)):
            # free_id[i] = AREA_MAP_ID2TRUE[free_id[i]]
            print('> %s 区座位空闲座位号' % area_TrueID2char(
                info['area_true_id']), true_id)
    if len(free_seatID) == 0:
        # print('> 所选所有区域座位已满')
        return False, []
    else:
        # print('> 空闲座位信息:', free_seatID)
        return True, free_seatID


def output_all_seat_info(all_info_tree):
    def f(x):
        df = x['df']
        segment = x['segment']
        area_ture_id = x['area_true_id']
        ch = x['ch']
        area_id = x['area_id']
        df_free = df[df['status_name'] == STATUS['free']]
        df_busy = df[df['status_name'] == STATUS['busy']]
        df_occ = df[df['status_name'] == STATUS['occ']]
        print('{:s} 空闲座位:{:d} 使用座位:{:d} 已预约:{:d}'.format(
            ch, df_free.shape[0], df_busy.shape[0], df_occ.shape[0]))
    dfs_TREE(all_info_tree, lambda x: f(x))


def process_input(s):
    res = None
    if len(s) <= 4:
        res = regular_search_area(s)
    else:
        res = s.split(' ')
    return res


def main(s, today=True):
    chosen_areas = process_input(s)
    for i in range(len(chosen_areas)):
        print('> 已选区域:', area_TrueID2char(chosen_areas[i]))
        chosen_areas[i] = AREA_MAP_TRUE2ID[chosen_areas[i]]
    print()
    success = False
    # todo
    # segment = get_segment(chosen_areas[0], today=True)
    ret1 = True
    while not success:
        time.sleep(2)
        if ret1:
            seat_info = get_seat_info(chosen_areas, today)

            ret2, ids = find_free_seat(seat_info)
            if ret2:
                idx = random.randint(0, len(ids[0]['free_id'])-1)
                seat_id = ids[0]['free_id'][idx]
                seat_true_id = ids[0]['true_id'][idx]
                segment = ids[0]['segment']
                print('> 拟预定座位ID:', (seat_true_id, seat_id))
                r = book_seat(seat_id, segment)
                print('> 服务器反馈:', r.json()['msg'])
                success = True
            else:
                print('> 所选所有区域座位已满')
                success = False

        else:
            print('> 获取token失败 :）')
            break


STATUS = {'free': '空闲', 'busy': '使用中', 'lock': '锁定', 'occ': '已预约'}
AREA_MAP_TRUE2ID, AREA_MAP_ID2TRUE, TREE = get_map_areaNumber2areaTureID()
