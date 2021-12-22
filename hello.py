import webview
import securityReader as reader

class Api:
    def __init__(self):
        self.cancel_heavy_stuff_flag = False

    def read_wy(self,keya,keyb):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
        info_json = reader.COS_Read_Tempture(card_service,Des3_Cipher)
        result = {
            "keya":keya,
            "keyb":keyb,
            "info" :info_json
        }
        return result

    def read_yy(self,keya,keyb):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
        info_json = reader.COS_Analysis(card_service,Des3_Cipher,60,False)
        result = {
            "keya":keya,
            "keyb":keyb,
            "info" :info_json
        }
        return result

    def active_yy(self,keya,keyb):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
        result = reader.COS_Write_Config(card_service,Des3_Cipher,49162,8,[0xF0, 0x03, 0x00, 0x0F, 0x20, 0x00, 0xF6, 0x00],8)
        if result:
            return '芯片激活成功'
        else:
            return '芯片激活失败'

    def check_yy_status(self,keya,keyb):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
        result = reader.COS_Read_Config(card_service,Des3_Cipher,49162,8,8)
        if result[0] == 240:
            return'芯片已激活'
        else:
            return '芯片未激活'

    def read_uid(self):
        card_service = reader.init()
        uid = reader.read_uid(card_service)
        return uid

    def write_data(self,keya,keyb,write_str):
        card_service = reader.init()
        Des3_Cipher = reader.COS_Access(card_service, keya, keyb)
        write_bytes = bytes(write_str, encoding="utf8")

        if len(write_bytes) >= 4031:
            return '写入数据太大啦'
        result = reader.write_data(card_service,Des3_Cipher,write_bytes)
        return result


if __name__ == '__main__':
    api = Api()
    window = webview.create_window('中义NFC读写器', url='helloworld.html', js_api=api,resizable=False,width=800,height=800)
    webview.start(debug = True)