import RC003 as PL51NF001


RF_PACKAGE_SIZE = 56                                                                                                                            # 控制数据包大小

result, Device = PL51NF001.device_connect("COM3", "125000")

print(Device)
result = PL51NF001.Device_CloseField(Device)                                                                                                          # 关闭场
# PL51NF001.delay(0.1)
result = PL51NF001.Device_OpenField(Device)                                                                                                           # 打开场
# PL51NF001.delay(0.1)
# result = PL51NF001.data_rate_set(Device, 0)                                                                                                     # 设置RF数据速率 106kbps
result = PL51NF001.Active_Card(Device)                                                                                                          # 激活卡片
result = PL51NF001.RATS(Device)

result, Des3_Cipher = PL51NF001.cos_access(Device, "A0 A1 A2 A3 A4 A5 A6 A7", "A8 A9 AA AB AC AD AE AF")

# NDEF卡
# result = PL51NF001.cos_write_config(Device, Des3_Cipher, 0xC000, 64, "C0407FFF0578338000ACF003000F2000F600F6040600010FC0000000112233445566778899AABBCCDDEEFFA0A1A2A3A4A5A6A7A8A9AAABACADAEAF0052002200", RF_PACKAGE_SIZE)
# 无源调试模式
result = PL51NF001.cos_write_config(Device, Des3_Cipher, 0xC000, 64, "C0407FFF0578338000ACF003000F2000F600F6040600010FC000FF00112233445566778899AABBCCDDEEFFA0A1A2A3A4A5A6A7A8A9AAABACADAEAF0052002200", RF_PACKAGE_SIZE)
# 有源调试模式
# result = PL51NF001.cos_write_config(Device, Des3_Cipher, 0xC000, 64, "C0407FFF0578338000ACFC03000F2000F600F6040600010FC000FF00112233445566778899AABBCCDDEEFFA0A1A2A3A4A5A6A7A8A9AAABACADAEAFAC52022200", RF_PACKAGE_SIZE)

result, data_bytes = PL51NF001.cos_read_config(Device, Des3_Cipher, 0xC000, 64, RF_PACKAGE_SIZE)

result = PL51NF001.close_field(Device)
