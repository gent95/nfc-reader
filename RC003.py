# -*- coding: utf-8 -*-
import serial as ser  # pip install pyserial
import serial.tools.list_ports as ser_list
import time as tm
from Crypto.Cipher import DES3 as des3  # pip install pycryptodome
import random as rnd
import math
import matplotlib.pyplot as plt
import numpy as np


def Delay(time_float):
    tm.sleep(time_float)


# 测试项目打印（蓝色）
def item_print(item_str):
    item_str = "\033[44m" + item_str + "\033[0m"
    print(item_str)


# 结果打印（正确：绿色  不正确：红色）
def result_print(result_out_str, result):
    if result == True:
        result_out_str = "\033[32m" + result_out_str + "\033[0m"
    else:
        result_out_str = "\033[31m" + result_out_str + "\033[0m"
    print(result_out_str)


def int2bytes(data_int):
    return bytes([data_int])


def hexstr2int_list(data_str):
    data_str = data_str.replace('0x', '')
    data_str = data_str.replace(' ', '')
    data_str = data_str.replace('\r', '')
    data_str = data_str.replace('\n', '')
    data_number_int = int(len(data_str) / 2)
    data_bytes_list = list(range(data_number_int))
    data_int_list = list(range(data_number_int))
    for i in range(0, data_number_int):
        data_bytes_list[i] = bytes.fromhex(data_str[i * 2:i * 2 + 2])
        data_int_list[i] = int.from_bytes(data_bytes_list[i], 'big')
    return data_int_list


def bytes2int(data_bytes):
    data_number = len(data_bytes)
    data_int = 0
    for i in range(0, data_number):
        data_int = data_int + data_bytes[data_number - i - 1] * math.pow(2, i * 8)
    return int(data_int)


def bytes2int_list(data_bytes):
    data_number = len(data_bytes)
    data_int_list = list(range(data_number))
    for i in range(0, data_number):
        data_int_list[i] = int(str(data_bytes[i]))
    return data_int_list


def bytes2hexstr(data_bytes):
    data_number = len(data_bytes)
    data_hex_str = ''
    for i in range(0, data_number):
        data_int = int(str(data_bytes[i]))
        data_hex_str += "{:02X} ".format(data_int)
    return data_hex_str


def int_list2bytes(data_int_list):
    data_bytes = b''.join(map(lambda d: int.to_bytes(d, 1, 'little'), data_int_list))
    return data_bytes


def hexstr2bytes(hex_str):
    hex_int_list = hexstr2int_list(hex_str)
    hex_bytes = int_list2bytes(hex_int_list)
    return hex_bytes


# 计算ISO14443a CRC16
def iso14443a_crc16(data_bytes):
    length_int = len(data_bytes)
    wCrc = 0x6363
    data_int_list = bytes2int_list(data_bytes)
    for i in range(0, length_int):
        bt = data_int_list[i]
        bt = bt ^ (wCrc & 0x00FF)
        bt &= 0xFF
        bt = bt ^ ((bt << 4) & 0xFF)
        wCrc = ((wCrc >> 8) & 0xFFFF) ^ (((bt << 8) & 0xFFFF) ^ ((bt << 3)) & 0xFFFF) ^ ((bt >> 4) & 0xFFFF)
        wCrc &= 0xFFFF
    crc_int_list = [0 for i in range(2)]
    crc_int_list[0] = wCrc & 0xFF
    crc_int_list[1] = (wCrc >> 8) & 0xFF
    crc_bytes = int_list2bytes(crc_int_list)
    return crc_bytes


# 添加CRC16
def iso14443a_add_crc16(data_bytes):
    data_bytes += iso14443a_crc16(data_bytes)
    return data_bytes


# 添加指令包长度字节
def command_add_package_length(data_bytes):
    data_length = len(data_bytes)
    data_bytes = data_bytes[0:1] + bytes([(data_length >> 8) & 0xFF]) + bytes([data_length & 0xFF]) + data_bytes[3:]
    return data_bytes


# 构建串口指令
def build_com_command(rf_command_bytes):
    rf_command_length_bytes = int2bytes(len(rf_command_bytes))
    command_bytes = b'\xAA\x00\x00\xFF' + rf_command_length_bytes + b'\x80' + rf_command_bytes
    command_bytes = command_add_package_length(command_bytes)
    return command_bytes


# 连接串口
def device_connect(serial_port, buad_rate):
    result = False
    try:
        sscom = ser.Serial(serial_port, buad_rate, timeout=600)
        sscomIsOpen = sscom.isOpen()
        if sscomIsOpen == False:
            result_print("串口被占用", result)
        else:
            result = True
            result_print("串口打开成功", result)
    except:
        sscom = -1
    return result, sscom


# 串口写入、读取返回数据
# sscom：串口
# write_data_str：写入数据
# 返回：串口返回数据（bytes）
def sscom_transceive_bytes(sscom, write_data_bytes):
    sscom.write(write_data_bytes)
    data_length_int = 0
    for i in range(0, 1000):
        tm.sleep(0.001)
        data_length_int = sscom.in_waiting
        if data_length_int != 0:
            break
    if i == 999:
        data_bytes = b''
    else:  # 接收到数据
        for i in range(0, 1000):  # 1s超时
            tm.sleep(0.001)  # 2ms没收到新数据，则判断接收完成
            if data_length_int != sscom.in_waiting:
                data_length_int = sscom.in_waiting
            else:
                break
    if data_length_int > 0:
        data_bytes = sscom.read(data_length_int)
    else:
        data_bytes = b''
    print('>>' + bytes2hexstr(write_data_bytes))
    print('<<' + bytes2hexstr(data_bytes))
    return data_bytes, data_length_int


# 读数据
# ISO14443-4A更新数据
# sscom：串口
# cla_bytes：CLA （PL私有为b'\xA0'，ISO14443-4A标准为b'\x00'）
# address_start_int：数据起始位置
# length_int：更新数据长度
# 返回：正确：卡片返回数据  错误：b''
def ISO14443_4A_ReadBinary(sscom, cla_bytes, address_start_int, length_int, RF_PACKAGE_SIZE):
    data_read_bytes = b''
    des3_key_int_list = [0 for i in range(2)]
    package_size_int = RF_PACKAGE_SIZE
    package_number_int = int(length_int / package_size_int)
    package_bytes_left_int = length_int % package_size_int
    i = 0
    # 读取整包数据
    for i in range(0, package_number_int):
        for retry_cnt_int in range(0, 10):
            data_address_int = address_start_int + i * package_size_int
            des3_key_int_list[0] = int(data_address_int / 256)
            des3_key_int_list[1] = int(data_address_int % 256)
            data_address_bytes = int_list2bytes(des3_key_int_list)
            rf_command_bytes = iso14443a_add_crc16(
                b'\x02' + cla_bytes + b'\xB0' + data_address_bytes + bytes([package_size_int]))
            command_bytes = build_com_command(rf_command_bytes)
            data_bytes, length = sscom_transceive_bytes(sscom, command_bytes)
            if data_bytes[-4:-2] != b'\x90\x00':
                continue
            else:
                data_read_bytes = data_read_bytes + data_bytes[1:1 + package_size_int]
                break
        if retry_cnt_int == 9:
            return b''
    # 读取剩余数据
    if package_bytes_left_int != 0:
        if package_number_int != 0:
            i = i + 1
        for retry_cnt_int in range(0, 10):
            data_address_int = address_start_int + i * package_size_int
            des3_key_int_list[0] = int(data_address_int / 256)
            des3_key_int_list[1] = int(data_address_int % 256)
            data_address_bytes = int_list2bytes(des3_key_int_list)
            rf_command_bytes = iso14443a_add_crc16(
                b'\x02' + cla_bytes + b'\xB0' + data_address_bytes + bytes([package_bytes_left_int]))
            command_bytes = build_com_command(rf_command_bytes)
            data_bytes, length = sscom_transceive_bytes(sscom, command_bytes)
            if data_bytes[-4:-2] != b'\x90\x00':
                continue
            else:
                data_read_bytes = data_read_bytes + data_bytes[1:1 + package_bytes_left_int]
                break
        if retry_cnt_int == 9:
            return b''
    return data_read_bytes


# ISO14443-4A更新数据
# sscom：串口
# cla_bytes：CLA （PL私有为b'\xA0'，ISO14443-4A标准为b'\x00'）
# address_start_int：数据起始位置
# length_int：更新数据长度
# data_write_bytes：更新数据
# 返回：正确：卡片最后一次返回数据 错误：b''
def ISO14443_4A_UpdateBinary(sscom, cla_bytes, address_start_int, length_int, data_write_bytes, RF_PACKAGE_SIZE):
    des3_key_int_list = [0 for i in range(2)]
    package_size_int = RF_PACKAGE_SIZE
    package_number_int = int(length_int / package_size_int)
    package_bytes_left_int = length_int % package_size_int
    i = 0
    # 写整包数据
    for i in range(0, package_number_int):
        for retry_cnt_int in range(0, 10):
            # tm.sleep(0.01)
            data_address_int = address_start_int + i * package_size_int
            des3_key_int_list[0] = int(data_address_int / 256)
            des3_key_int_list[1] = int(data_address_int % 256)
            data_address_bytes = int_list2bytes(des3_key_int_list)
            rf_command_bytes = iso14443a_add_crc16(
                b'\x02' + cla_bytes + b'\xD6' + data_address_bytes + bytes([package_size_int]) +
                data_write_bytes[i * package_size_int: (i + 1) * package_size_int])
            command_bytes = build_com_command(rf_command_bytes)
            data_bytes, length = sscom_transceive_bytes(sscom, command_bytes)
            if data_bytes[0:1] == b'\xF2':
                command_bytes = b'\xAA\x00\x00\xFF\x04\x80' + iso14443a_add_crc16(data_bytes[0:2])
                command_bytes = command_add_package_length(command_bytes)
                data_bytes, length = sscom_transceive_bytes(sscom, command_bytes)
            if data_bytes[-4:-2] != b'\x90\x00':
                continue
            else:
                break
        if retry_cnt_int == 9:
            return b''
    # 写剩余数据
    if package_bytes_left_int != 0:
        # tm.sleep(0.01)
        if package_number_int != 0:
            i = i + 1
        for retry_cnt_int in range(0, 10):
            data_address_int = address_start_int + i * package_size_int
            des3_key_int_list[0] = int(data_address_int / 256)
            des3_key_int_list[1] = int(data_address_int % 256)
            data_address_bytes = int_list2bytes(des3_key_int_list)

            rf_command_bytes = iso14443a_add_crc16(b'\x02' + cla_bytes + b'\xD6' + data_address_bytes + \
                                                   bytes([package_bytes_left_int]) + \
                                                   data_write_bytes[
                                                   i * package_size_int:i * package_size_int + package_bytes_left_int])
            command_bytes = build_com_command(rf_command_bytes)
            data_bytes, length = sscom_transceive_bytes(sscom, command_bytes)
            if data_bytes[0:1] == b'\xF2':
                command_bytes = b'\xAA\x00\x00\xFF\x04\x80' + iso14443a_add_crc16(data_bytes[0:2])
                command_bytes = command_add_package_length(command_bytes)
                data_bytes, length = sscom_transceive_bytes(sscom, command_bytes)
            if data_bytes[-4:-2] != b'\x90\x00':
                continue
            else:
                break
        if retry_cnt_int == 9:
            return b''
    return data_bytes


# 十六进制字符串分段换行
# hex_str：十六进制字符串
# break_size_int：换行尺寸大小
def hex_str_break(hex_str, break_size_int):
    hex_temp_str = hex_str.replace(' ', '')
    data_size_int = int(len(hex_temp_str) / 2)
    data_break_size_int = int(data_size_int / break_size_int)
    data_break_lfet_int = int(data_size_int % break_size_int)
    data_temp_str = ""
    i = 0
    for i in range(0, data_break_size_int):
        data_temp_str = data_temp_str + hex_str[i * break_size_int * 3:(i + 1) * break_size_int * 3] + "\n"
    if data_break_lfet_int != 0:
        if data_break_size_int != 0:
            i = i + 1
        data_temp_str = data_temp_str + hex_str[i * break_size_int * 3:i * break_size_int * 3 + data_break_lfet_int * 3]
    return data_temp_str


# RF关场
def Device_CloseField(SeialCom):
    item_print("RF关闭")
    result = False
    print(SeialCom)
    if SeialCom.isOpen() == True:
        # 选中CONFIG
        command_bytes = b'\xAA\x00\x00\xF0'
        command_bytes = command_add_package_length(command_bytes)
        data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
        if data_bytes[0] != 0xFF:
            result = True
            result_print("成功", result)
        else:
            result = False
            result_print("失败", result)
    return result


# RF开场
def Device_OpenField(SeialCom):
    item_print("RF开启")
    result = False
    if SeialCom.isOpen() == True:
        # 选中CONFIG
        command_bytes = b'\xAA\x00\x00\xF1'
        command_bytes = command_add_package_length(command_bytes)
        data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
        if data_bytes[0] != 0xFF:
            result = True
            result_print("成功", result)
        else:
            result = False
            result_print("失败", result)
    return result


# 激活卡片
# def Active_Card(SeialCom):
#   item_print("卡片激活")
#   result = False
#   # ACTIVE
#   command_bytes = b'\xAA\x00\x00\xF2\x26\x00'
#   command_bytes = command_add_package_length(command_bytes)
#   data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
#   if data_bytes[0] != 0xFF:
#     data_str = bytes2hexstr(data_bytes)
#     data_str = "CARD ID = " + data_str[3:] + "\n" + \
#               "SAK = " + data_str[0:2]
#     result = True
#     result_print("成功", result)
#     result_print(data_str, result)
#     tm.sleep(0.01)
#   if result == False:
#     result_print("失败", result)
#   return result


# 激活卡片
def Active_Card(SeialCom):
    item_print("卡片激活")
    result = False
    # REQA
    command_bytes = b'\xAA\x00\x00\xFF\x01\x87\x26'
    command_bytes = command_add_package_length(command_bytes)
    for i in range(0, 4):
        recive_data, length = sscom_transceive_bytes(SeialCom, command_bytes)
        if recive_data != b'\xFF':
            if length != 0:
                break
    if i == 3:
        result_print("失败", result)
        return False
    ATQA_str = bytes2hexstr(recive_data)
    result_print("ATQA: " + ATQA_str, True)
    ATQA_int_list = bytes2int_list(recive_data)
    # UID size
    uid_size_flag = ATQA_int_list[0] & 0xF0
    if uid_size_flag == 0x00:
        UID_Size = 1
    elif uid_size_flag == 0x40:
        UID_Size = 2
    elif uid_size_flag == 0x80:
        UID_Size = 3
    # ANTICOLL1
    rf_command_bytes = b'\x93\x20'
    command_bytes = build_com_command(rf_command_bytes)
    uid1_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    # SELECT1
    rf_command_bytes = iso14443a_add_crc16(b'\x93\x70' + uid1_bytes)
    command_bytes = build_com_command(rf_command_bytes)
    sak_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    result_print("UID1: " + bytes2hexstr(uid1_bytes), True)
    sak_int_list = bytes2int_list(sak_bytes)
    if sak_int_list[0] & 0x04:  # UID not complete
        # ANTICOLL2
        rf_command_bytes = b'\x95\x20'
        command_bytes = build_com_command(rf_command_bytes)
        uid2_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
        # SELECT2
        rf_command_bytes = iso14443a_add_crc16(b'\x93\x70' + uid2_bytes)
        command_bytes = build_com_command(rf_command_bytes)
        sak_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
        result_print("UID2: " + bytes2hexstr(uid2_bytes), True)
        sak_int_list = bytes2int_list(sak_bytes)
        if sak_int_list[0] & 0x04:  # UID not complete
            # ANTICOLL3
            rf_command_bytes = b'\x97\x20'
            command_bytes = build_com_command(rf_command_bytes)
            uid3_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
            # SELECT3
            rf_command_bytes = iso14443a_add_crc16(b'\x97\x70' + uid3_bytes)
            command_bytes = build_com_command(rf_command_bytes)
            sak_bytes, length = sscom_transceive_bytes(SeialCom, rf_command_bytes)
            result_print("UID3: " + bytes2hexstr(uid3_bytes), True)
            sak_int_list = bytes2int_list(sak_bytes)
    result_print("SAK: " + bytes2hexstr(sak_bytes), True)
    # if sak_int_list[0] & 0x20:    # ISO/IEC 14443-4 is complianted
    #   ats_bytes, length = sscom_transceive_bytes(SeialCom, b'\xAA\xC3\x01\xFF\x02\xC0\xE0\x80')
    #   Output_str = Output_str + "ATS: " + bytes2hexstr(ats_bytes) + '\n'
    result = True
    return result


# RATS指令
# def RATS(SeialCom):
#   item_print("进入COS")
#   result = False
#   command_bytes = b'\xAA\x00\x00\xF3\x08\x00'
#   command_bytes = command_add_package_length(command_bytes)
#   data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
#   if data_bytes[0] != 0xFF:
#     data_str = bytes2hexstr(data_bytes)
#     data_str = "RATS = " + data_str
#     result = True
#     result_print("成功", result)
#     result_print(data_str, result)
#   if result == False:
#     result_print("失败", result)
#   return result

# RATS指令
def RATS(SeialCom):
    item_print("进入COS")
    result = False
    rf_command_bytes = iso14443a_add_crc16(b'\xE0\x80')
    command_bytes = build_com_command(rf_command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    if data_bytes[0] != 0xFF:
        data_str = bytes2hexstr(data_bytes)
        data_str = "RATS = " + data_str
        result = True
        result_print("成功", result)
        result_print(data_str, result)
    if result == False:
        result_print("失败", result)
    return result


# 权限获取
def COS_Access(SeialCom, KEYA_str, KEYB_str):
    item_print("COS权限验证")
    result = False
    # 选择ACC
    rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xA4\x00\x0C\x02\xAC\x01')
    command_bytes = build_com_command(rf_command_bytes)
    command_bytes = command_add_package_length(command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    if data_bytes[1] == 0x63 and data_bytes[2] == 0xc0:
        tm.sleep(20)
        rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xA4\x00\x0C\x02\xAC\x01')
        command_bytes = build_com_command(rf_command_bytes)
        command_bytes = command_add_package_length(command_bytes)
        data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)

    # 开始验证管理员权限
    rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xB0\x00\x10\x10')
    command_bytes = build_com_command(rf_command_bytes)
    command_bytes = command_add_package_length(command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    trnd_bytes = data_bytes[1:9]
    mid_bytes = data_bytes[9:17]
    # 计算KEYA* KEYB*
    random_int_list = bytes2int_list(trnd_bytes)
    mid_int_list = bytes2int_list(mid_bytes)
    keya_int_list = hexstr2int_list(KEYA_str)
    keyb_int_list = hexstr2int_list(KEYB_str)
    des3_key_list = [0 for i in range(16)]
    for i in range(0, 8):
        des3_key_list[i] = random_int_list[i] ^ keya_int_list[i]
        des3_key_list[i + 8] = mid_int_list[i] ^ keyb_int_list[i]
    des3_key_bytes = b''.join(map(lambda d: int.to_bytes(d, 1, 'little'), des3_key_list))
    Des3_Cipher = des3.new(des3_key_bytes, des3.MODE_ECB)
    # 加密随机数
    random_key_bytes = b''.join(map(lambda d: int.to_bytes(d, 1, 'little'), random_int_list))
    trnd_encrpyt_bytes = Des3_Cipher.encrypt(random_key_bytes)
    trnd_bytes = rnd.randbytes(8)
    command_bytes = b'\xAA\x00\x00\xFF\x18\x80' + iso14443a_add_crc16(
        b'\x02\xA2\xD6\x00\x10\x10' + trnd_encrpyt_bytes + trnd_bytes)
    command_bytes = command_add_package_length(command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    if data_bytes[1:3] == b'\x90\x00':
        # 验证标签
        rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xB0\x00\x10\x10')
        command_bytes = build_com_command(rf_command_bytes)
        command_bytes = command_add_package_length(command_bytes)
        data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
        trnd_encrpyt_bytes = Des3_Cipher.encrypt(trnd_bytes)
        if trnd_encrpyt_bytes == data_bytes[1:9]:
            result = True
            result_print("成功", result)
    if result == False:
        result_print("失败", result)
    return result, Des3_Cipher


# 读温度按钮点击程序
def COS_Read_Tempture(SeialCom, Des3_Cipher):
    item_print("COS读取温度")
    result = False
    tempture_int = 0
    # 选中PL DATA
    rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xA4\x00\x0C\x02\xDA\x01')
    command_bytes = build_com_command(rf_command_bytes)
    command_bytes = command_add_package_length(command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    # 读数据
    rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xB0\x00\x4E\x08')
    command_bytes = build_com_command(rf_command_bytes)
    command_bytes = command_add_package_length(command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    data_bytes = Des3_Cipher.decrypt(data_bytes[1:9])
    tempture_int = int(str(data_bytes[0])) * 256 + int(str(data_bytes[1]))
    tempture_int = tempture_int >> 5
    result = True
    result_print("温度ADC = " + str(tempture_int), result)
    if result == False:
        result_print("失败", result)
    return result, tempture_int


# 数据解析
def COS_Analysis(SeialCom, Des3_Cipher, DATA_SIZE, show_picture_str):
    item_print("COS数据解析")
    # 选中DATA
    rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xA4\x00\x0C\x02\xDA\x01')
    command_bytes = build_com_command(rf_command_bytes)
    command_bytes = command_add_package_length(command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    # 读取数据
    data_bytes = ISO14443_4A_ReadBinary(SeialCom, b'\xA2', 0, 80, DATA_SIZE)
    print('analy'+bytes2hexstr(data_bytes))
    data_bytes = Des3_Cipher.decrypt(data_bytes)
    # 解析数据
    data_bias = 12
    CID_bytes = data_bytes[data_bias + 0: data_bias + 2]
    TID_bytes = data_bytes[data_bias + 2: data_bias + 8]
    GTIN_bytes = data_bytes[data_bias + 8: data_bias + 18]
    VID_bytes = data_bytes[data_bias + 18:data_bias + 26]
    MID_bytes = data_bytes[data_bias + 26:data_bias + 34]
    MAC_bytes = data_bytes[data_bias + 34:data_bias + 42]
    TRNG_bytes = data_bytes[data_bias + 42:data_bias + 50]
    PAGE_bytes = data_bytes[data_bias + 50:data_bias + 51]
    RNUM_bytes = data_bytes[data_bias + 51:data_bias + 55]
    RES_bytes = data_bytes[data_bias + 55:data_bias + 58]
    K_bytes = data_bytes[data_bias + 58:data_bias + 62]
    B_bytes = data_bytes[data_bias + 62:data_bias + 66]
    info_str = "CID: " + bytes2hexstr(CID_bytes) + "\n" + \
               "TID: " + bytes2hexstr(TID_bytes) + "\n" + \
               "GTIN: " + bytes2hexstr(GTIN_bytes) + "\n" + \
               "VID: " + bytes2hexstr(VID_bytes) + "\n" + \
               "MID: " + bytes2hexstr(MID_bytes) + "\n" + \
               "MAC: " + bytes2hexstr(MAC_bytes) + "\n" + \
               "TRNG: " + bytes2hexstr(TRNG_bytes) + "\n" + \
               "PAGE: " + bytes2hexstr(PAGE_bytes) + "\n" + \
               "RNUM: " + bytes2hexstr(RNUM_bytes) + "\n" + \
               "RES: " + bytes2hexstr(RES_bytes) + "\n" + \
               "K: " + bytes2hexstr(K_bytes) + "\n" + \
               "B: " + bytes2hexstr(B_bytes)
    result_print(info_str, True)
    record_number_int = bytes2int(RNUM_bytes)
    record_data_size_int = int(record_number_int * 11 / 8)
    if (record_number_int * 11 % 8):
        record_data_size_int += 1
    record_data_size_mod_int = record_data_size_int % 8
    if (record_data_size_mod_int):
        record_data_size_int = record_data_size_int + (8 - record_data_size_mod_int)
    # 读取数据
    data_bytes = ISO14443_4A_ReadBinary(SeialCom, b'\xA2', 78, record_data_size_int, DATA_SIZE)
    data_bytes = Des3_Cipher.decrypt(data_bytes)
    # 解析adc
    tempture_data = [0 for i in range(record_number_int)]
    repeat_cnt = int(record_number_int / 8)
    count_residue = record_number_int % 8
    if count_residue > 0:
        repeat_cnt += 1
    decode_count = 0
    for i in range(0, repeat_cnt):
        for j in range(0, 8):
            if decode_count >= record_number_int:
                break
            else:
                decode_count += 1
            if j == 0:
                adc_data_int = data_bytes[i * 11] * 256 + data_bytes[i * 11 + 1]
                adc_data_int = (adc_data_int & 0x0000FFE0) >> 5
            elif j == 1:
                adc_data_int = data_bytes[i * 11 + 1] * 256 + data_bytes[i * 11 + 2]
                adc_data_int = (adc_data_int & 0x00001FFC) >> 2
            elif j == 2:
                adc_data_int = data_bytes[i * 11 + 2] * 65536 + data_bytes[i * 11 + 3] * 256 + data_bytes[i * 11 + 4]
                adc_data_int = (adc_data_int & 0x0003FF80) >> 7
            elif j == 3:
                adc_data_int = data_bytes[i * 11 + 4] * 256 + data_bytes[i * 11 + 5]
                adc_data_int = (adc_data_int & 0x00007FF0) >> 4
            elif j == 4:
                adc_data_int = data_bytes[i * 11 + 5] * 256 + data_bytes[i * 11 + 6]
                adc_data_int = (adc_data_int & 0x00000FFE) >> 1
            elif j == 5:
                adc_data_int = data_bytes[i * 11 + 6] * 65536 + data_bytes[i * 11 + 7] * 256 + data_bytes[i * 11 + 8]
                adc_data_int = (adc_data_int & 0x0001FFC0) >> 6
            elif j == 6:
                adc_data_int = data_bytes[i * 11 + 8] * 256 + data_bytes[i * 11 + 9]
                adc_data_int = (adc_data_int & 0x000003FF8) >> 3
            elif j == 7:
                adc_data_int = data_bytes[i * 11 + 9] * 256 + data_bytes[i * 11 + 10]
                adc_data_int = (adc_data_int & 0x000007FF) >> 0
            adc_data_int = int(adc_data_int)
            tempture_data[decode_count - 1] = adc_data_int
    result_print(str(tempture_data), True)
    # 波形显示
    if show_picture_str == "show picture":
        DATA_FILTER = 0
        x = [0 for i in range(record_number_int)]
        for i in range(0, record_number_int):
            x[i] = i
        plt.figure(figsize=(20.48, 10.24))
        plt.title('Tempture Record')
        lable_name = bytes2hexstr(VID_bytes)
        plt.plot(x, tempture_data, label=lable_name)
        plt.legend()  # 显示图例
        plt.ylim(0, 2048)
        plt.ylabel('adc value')
        plt.xlabel('time')
        plt.show()


# 读读取数据
def COS_Read_Data(SeialCom, Des3_Cipher, address_int, length_int, package_size):
    item_print("COS读取数据")
    result = False
    # 选中PL DATA
    rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xA4\x00\x0C\x02\xDA\x01')
    command_bytes = build_com_command(rf_command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    # 读数据
    data_bytes = ISO14443_4A_ReadBinary(SeialCom, b'\xA2', address_int, length_int, package_size)
    data_bytes = Des3_Cipher.decrypt(data_bytes)
    data_str = bytes2hexstr(data_bytes)
    result = True
    result_print("成功", result)
    result_print(data_str, result)
    return result, data_bytes


def COS_Read_Config(SeialCom, Des3_Cipher, address_int, length_int, package_size):
    item_print("COS读取配置数据")
    result = False
    # 选中CONFIG
    rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xA4\x00\x0C\x02\xCF\x01')
    command_bytes = build_com_command(rf_command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    # 读数据
    data_bytes = ISO14443_4A_ReadBinary(SeialCom, b'\xA2', address_int, length_int, package_size)
    data_bytes = Des3_Cipher.decrypt(data_bytes)
    data_str = bytes2hexstr(data_bytes)
    result = True
    result_print("成功", result)
    result_print(data_str, result)
    return result, data_bytes


def COS_Write_Config(SeialCom, Des3_Cipher, address_int, length_int, data_hex_str, package_size):
    item_print("COS写入配置数据")
    result = False
    # 选中CONFIG
    rf_command_bytes = iso14443a_add_crc16(b'\x02\xA2\xA4\x00\x0C\x02\xCF\x01')
    command_bytes = build_com_command(rf_command_bytes)
    data_bytes, length = sscom_transceive_bytes(SeialCom, command_bytes)
    data_write_str = data_hex_str
    data_write_bytes = hexstr2bytes(data_write_str)
    data_write_bytes = Des3_Cipher.encrypt(data_write_bytes)
    data_bytes = ISO14443_4A_UpdateBinary(SeialCom, b'\xA2', address_int, length_int, data_write_bytes, package_size)
    if data_bytes != b'':
        result = True
        result_print("成功", result)
    if result == False:
        result_print("失败", result)
    return result

