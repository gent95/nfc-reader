from typing import Tuple
import RC003 as PL51NF001


RF_PACKAGE_SIZE = 56                                                                                                                            # 控制数据包大小

result, Device = PL51NF001.device_connect("COM4", "125000")
print(Device)
result = PL51NF001.Device_CloseField(Device)                                                                                                          # 关闭场
# PL51NF001.delay(0.1)
result = PL51NF001.Device_OpenField(Device)                                                                                                           # 打开场
# PL51NF001.delay(0.1)
# result = PL51NF001.data_rate_set(Device, 0)                                                                                                     # 设置RF数据速率 106kbps
result = PL51NF001.Active_Card(Device)                                                                                                          # 激活卡片
result = PL51NF001.RATS(Device)                                                                                                                 # rats指令，进入COS
# result = PL51NF001.pps(Device, 1)                                                                                                             # PPS指令，设置数据速率 212kbps
result, Des3_Cipher = PL51NF001.COS_Access(Device, "A0 A1 A2 A3 A4 A5 A6 A7", "A8 A9 AA AB AC AD AE AF")                                        # 验证权限
PL51NF001.COS_Analysis(Device, Des3_Cipher, RF_PACKAGE_SIZE, "False")                                                                        # 数据解析
result = PL51NF001.Device_CloseField(Device)
