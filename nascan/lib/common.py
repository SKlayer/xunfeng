# coding:utf-8
import pymongo
import socket
import lib.log as log
import datetime
import time
import base64
import traceback
import lib.db as db



def format_config(config_name, config_info):
    mark_list = []
    try:
        config_file = config_info.split('\n')
        if config_name == 'Discern_server':
            for mark in config_file:
                name, port, mode, reg = mark.strip().split("|", 3)
                mark_list.append([name, port, mode, reg])
        else:
            for mark in config_file:
                name, location, key, value = mark.strip().split("|", 3)
                mark_list.append([name.lower(), location, key, value])
    except Exception as e:
        print(e)
    return mark_list


def get_config():
    config = {}
    config_info = db.na_db.Config.find_one({"type": "nascan"})
    for name in config_info['config']:
        if name in ['Discern_cms', 'Discern_con', 'Discern_lang', 'Discern_server']:
            config[name] = format_config(name, config_info['config'][name]['value'])
        else:
            config[name] = config_info['config'][name]['value']
    return config

def monitor(CONFIG_INI, STATISTICS, NACHANGE):
    while True:
        try:
            time_ = datetime.datetime.now()
            date_ = time_.strftime('%Y-%m-%d')
            db.na_db.Heartbeat.update({"name": "heartbeat"}, {"$set": {"up_time": time_}})
            if date_ not in STATISTICS: STATISTICS[date_] = {"add": 0, "update": 0, "delete": 0}
            db.na_db.Statistics.update({"date": date_}, {"$set": {"info": STATISTICS[date_]}}, upsert=True)
            new_config = get_config()
            if str(CONFIG_INI["Scan_list"]) != str(new_config["Scan_list"]):
                NACHANGE[0] = 1
            CONFIG_INI.clear()
            CONFIG_INI.update(new_config)
        except Exception as e:
            traceback.print_exc()
            print(e)
        time.sleep(30)


def get_statistics():
    date_ = datetime.datetime.now().strftime('%Y-%m-%d')
    now_stati = db.na_db.Statistics.find_one({"date": date_})
    if not now_stati:
        now_stati = {date_: {"add": 0, "update": 0, "delete": 0}}
        return now_stati
    else:
        return {date_: now_stati['info']}

def cruise(STATISTICS,MASSCAN_AC):
    while True:
        now_str = datetime.datetime.now()
        week = int(now_str.weekday())
        hour = int(now_str.hour)
        if week >= 1 and week <= 5 and hour >= 9 and hour <= 18:  # 非工作时间不删除
            try:
                data = db.NA_INFO.find().sort("time", 1)
                for history_info in data:
                    while True:
                        if MASSCAN_AC[0]:  # 如果masscan正在扫描即不进行清理
                            time.sleep(10)
                        else:
                            break
                    ip = history_info['ip']
                    port = history_info['port']
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect((ip, int(port)))
                        sock.close()
                    except Exception as e:
                        time_ = datetime.datetime.now()
                        date_ = time_.strftime('%Y-%m-%d')
                        db.NA_INFO.remove({"ip": ip, "port": port})
                        log.write('info', None, 0, '%s:%s delete' % (ip, port))
                        STATISTICS[date_]['delete'] += 1
                        del history_info["_id"]
                        history_info['del_time'] = time_
                        history_info['type'] = 'delete'
                        db.NA_HISTORY.insert(history_info)
            except:
                pass
        time.sleep(3600)
