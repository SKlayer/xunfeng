# coding:utf-8
from ctypes import *
import _ctypes
import json
import platform
import os
import requests
import time

import zipfile

import logging
logging.basicConfig(level = logging.INFO)
logger = logging.getLogger("KunPeng")
logger.setLevel(logging.DEBUG)
logger.info("KUNPENG")

class kunpeng:
    def __init__(self):
        self.kunpeng = None
        self.system = platform.system().lower()
        self.pwd = os.path.split(os.path.realpath(__file__))[0]
        self.suf_map = {
            'windows': '.dll',
            'darwin': '.dylib',
            'linux': '.so'
        }
        self._load_kunpeng()

    def do_upgrade(self):
        logger.info('Starting check KUNPENG Version')
        current_version = self.get_version().decode()
        release_version = self._get_release_latest()
        version = release_version["tag_name"]
        logger.info('Current=%s, Latest=%s . %s' % (current_version, version, "do upgrade" if current_version != version else "doesn't need upgrade"))
        if version != current_version:
            path = self._down_release(release_version['tag_name'])
            self.close()
            z_file = zipfile.ZipFile(path, 'r')
            dat = z_file.read('kunpeng_c' + self.suf_map[self.system])
            new_lib = self.pwd + '/kunpeng_v' + version + self.suf_map[self.system]
            lib_f = open(new_lib, 'wb')
            lib_f.write(dat)
            lib_f.close()
            z_file.close()

            os.remove(self.pwd + '/' + self._get_lib_path())
            print('update success', version)
            self._load_kunpeng()
        else:
            return





    def _get_lib_path(self):
        file_list = os.listdir(self.pwd)
        for v in file_list:
            if 'kunpeng' in v and os.path.splitext(v)[1] == self.suf_map[self.system]:
                return v

    def close(self):
        if self.system == 'windows':
            _ctypes.FreeLibrary(self.kunpeng._handle)
        else:
            handle = self.kunpeng._handle
            del self.kunpeng
            _ctypes.dlclose(handle)

    def _down_release(self, version):

        save_path = self.pwd + \
                    '/kunpeng_{}_v{}.zip'.format(self.system, version)
        down_url = 'https://github.com/opensec-cn/kunpeng/releases/download/{}/kunpeng_{}_v{}.zip'.format(
            version, self.system.lower(), version)
        logger.info('kunpeng update %s, url=%s starting downloading' % (version, down_url))
        if os.path.exists(save_path):
            return save_path

        def downloadFile(name, url):
            headers = {'Proxy-Connection': 'keep-alive'}
            r = requests.get(url, stream=True, headers=headers)
            length = float(r.headers['content-length'])
            f = open(name, 'wb')
            count = 0
            count_tmp = 0
            time1 = time.time()
            for chunk in r.iter_content(chunk_size=512):
                if chunk:
                    f.write(chunk)
                    count += len(chunk)
                    if time.time() - time1 > 2:
                        p = count / length * 100
                        speed = (count - count_tmp) / 1024 / 1024 / 2
                        count_tmp = count
                        print(name + ': ' + formatFloat(p) + '%' + ' Speed: ' + formatFloat(speed) + 'M/S')
                        time1 = time.time()
            f.close()

        def formatFloat(num):
            return '{:.2f}'.format(num)

        downloadFile(save_path,down_url)
        return save_path


    def _get_release_latest(self):
        req = requests.get('https://api.github.com/repos/opensec-cn/kunpeng/releases/latest')
        return req.json()

    def get_version(self):
        return self.kunpeng.GetVersion()

    def _load_kunpeng(self):
        lib_path = self._get_lib_path()
        # 加载动态连接库
        self.kunpeng = cdll.LoadLibrary(
            self.pwd + '/' + lib_path)

        # 定义出入参变量类型
        self.kunpeng.GetPlugins.restype = c_char_p
        self.kunpeng.Check.argtypes = [c_char_p]
        self.kunpeng.Check.restype = c_char_p
        self.kunpeng.SetConfig.argtypes = [c_char_p]
        self.kunpeng.GetVersion.restype = c_char_p
        print(self.get_version())

    def get_plugin_list(self):
        result = self.kunpeng.GetPlugins()
        return json.loads(result)

    def set_config(self, timeout, pass_list):
        config = {
            'timeout': timeout,
            'pass_list': pass_list
        }
        self.kunpeng.SetConfig(json.dumps(config))

    def check(self, t, netloc, kpid):
        task_dic = {
            'type': t,
            'netloc': netloc,
            'target': kpid
        }
        r = json.loads(self.kunpeng.Check(json.dumps(task_dic)))
        result = ''
        if not r:
            return ''
        for v in r:
            result += v['remarks'] + ','
        return result


if __name__ == '__main__':
    kp = kunpeng()
    kp.do_upgrade()
