import webview
import securityReader as reader
import random as rnd

class Api:
    def __init__(self):
        self.cancel_heavy_stuff_flag = False

    # 读取无源标签温度
    def read_wy(self,keya,keyb):
        card_service = reader.init()
        uid = reader.read_uid(card_service)
        Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
        info_json = reader.COS_Read_Tempture(card_service,Des3_Cipher)
        result = {
            "info" :info_json
        }
        return result

    # 读取有源标签温度
    def read_yy(self,keya,keyb):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
        info_json = reader.COS_Analysis(card_service,Des3_Cipher,56,False)
        result = {
            "info" :info_json
        }
        return result

    # 激活有源标签
    def active_yy(self,keya,keyb):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
        result = reader.COS_Write_Config(card_service,Des3_Cipher,49162,8,[0xF0, 0x03, 0x00, 0x0F, 0x20, 0x00, 0xF6, 0x00],8)
        if result:
            return '芯片激活成功'
        else:
            return '芯片激活失败'

    # 检查有源标签状态
    def check_yy_status(self,keya,keyb):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
        result = reader.COS_Read_Config(card_service,Des3_Cipher,49162,8,8)
        if result[0] == 240:
            return'芯片已激活'
        else:
            return '芯片未激活'

    # 读取标签uid
    def read_uid(self):
        card_service = reader.init()
        uid = reader.read_uid(card_service)
        return uid

    # 写入自定义信息
    def write_data(self,keya,keyb,write_str):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service, keya, keyb)
        write_bytes = bytes(write_str, encoding="utf8")
        write_bytes_len = len(write_bytes)
        if write_bytes_len >= 4031:
            return '写入数据太大啦'
        add = [0xff for i in range(8-(write_bytes_len % 8))]
        add = b''.join(map(lambda d: int.to_bytes(d, 1, 'little'), add))
        write_bytes+=add
        result = reader.write_data(card_service,Des3_Cipher,write_bytes)
        return result

    # 读取自定义信息
    def read_data(self,keya,keyb):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service, keya, keyb)
        result = reader.read_data(card_service,Des3_Cipher)
        return result

if __name__ == '__main__':
    api = Api()
    window = webview.create_window('中义NFC读写器', url='helloworld.html', js_api=api,resizable=True,width=800,height=800)
    webview.start(debug = True)