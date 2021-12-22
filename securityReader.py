#! /usr/bin/env python

"""
Smart Card Reader / Writer
"""
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString
from smartcard.ATR import ATR
from Crypto.Cipher import DES3 as des3
import random as rnd
import time as tm
import matplotlib.pyplot as plt
import math
import logging
import binascii
import struct

# 通过下面的方式进行简单配置输出方式与日志级别
logging.basicConfig(filename='logger.log', level=logging.INFO)


# 初始化读卡器
def init():
  print('初始化读卡器')
  card_type = AnyCardType()
  card_request = CardRequest(timeout=50000, cardType=card_type)
  card_service = card_request.waitforcard()
  card_service.connection.connect()
  # atr = ATR(card_service.connection.getATR())
  return card_service

def result_print(result_out_str):
  print(result_out_str)
  logging.info(result_out_str)

def trace_command(apdu):
    print('sending ', toHexString(apdu))
    logging.info('sending: '+ toHexString(apdu))

def trace_response(response, sw1, sw2):
    if response is None:
        response = []
    print(
        'serial no.: ',
        toHexString(response),
        ' status words: ',
        "%x %x" % (sw1, sw2)
    )
    logging.info( 'serial no.: '+
        toHexString(response)+
        ' status words: '+
        "%x %x" % (sw1, sw2))

def bytes2int(data_bytes):
  data_number = len(data_bytes)
  data_int = 0
  for i in range(0, data_number):
    data_int = data_int + data_bytes[data_number-i-1]*math.pow(2, i*8)
  return int(data_int)   

def int2bytes(data_int):
  return bytes([data_int])

def bytes2int_list(data_bytes):
  data_number = len(data_bytes)
  data_int_list = list(range(data_number))
  for i in range(0, data_number):
    data_int_list[i] = int(str(data_bytes[i]))
  return data_int_list

def hexstr2bytes(hex_str):
  hex_int_list = hexstr2int_list(hex_str)
  hex_bytes = int_list2bytes(hex_int_list)
  return hex_bytes

def bytes2hexstr(data_bytes):
  data_number = len(data_bytes)
  data_hex_str = ''
  for i in range(0, data_number):
    data_int = int(str(data_bytes[i]))
    data_hex_str += "{:02X} ".format(data_int)
  return data_hex_str


def hexstr2int_list(data_str):
  data_str = data_str.replace('0x', '')
  data_str = data_str.replace(' ', '')
  data_str = data_str.replace('\r', '')
  data_str = data_str.replace('\n', '')
  data_str = data_str.replace(',', '')
  data_number_int = int(len(data_str)/2)
  data_bytes_list = list(range(data_number_int))
  data_int_list = list(range(data_number_int))
  for i in range(0, data_number_int):
    data_bytes_list[i] = bytes.fromhex(data_str[i*2:i*2+2])
    data_int_list[i] = int.from_bytes(data_bytes_list[i], 'big')
  return data_int_list
  
def int_list2bytes(data_int_list):
  data_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), data_int_list))
  return data_bytes

#发送指令 
def sendCommand(card_service,command):
    trace_command(command)
    res, s1, s2 = card_service.connection.transmit(command)
    trace_response(res, s1, s2)
    return res,s1,s2

# 权限验证
def COS_Access(card_service,KEYA_str, KEYB_str):
    print('开始ACCESS验证')
    rf_command_bytes = [ 0xA2, 0xA4, 0x00, 0x0C, 0x02, 0xAC, 0x01]
    data_byres,s1,s2 = sendCommand(card_service,rf_command_bytes)
    if s1==99 and s2 == 192:
      print('解锁标签')  
      tm.sleep(20)
      rf_command_bytes = [ 0xA2, 0xA4, 0x00, 0x0C, 0x02, 0xAC, 0x01]
      data_byres,s1,s2 = sendCommand(card_service,rf_command_bytes)
      return
    rf_command_bytes = [0xA2, 0xB0, 0x00, 0x10, 0x10]
    data_bytes,s1,s2 = sendCommand(card_service,rf_command_bytes)
    trnd_bytes = data_bytes[0:8]
    mid_bytes = data_bytes[8:17]

    # 计算KEYA* KEYB*
    random_int_list = bytes2int_list(trnd_bytes)
    mid_int_list    = bytes2int_list(mid_bytes)
    keya_int_list   = hexstr2int_list(KEYA_str)
    keyb_int_list   = hexstr2int_list(KEYB_str)
    des3_key_list = [0 for i in range(16)]
    for i in range(0,8):
        des3_key_list[i]   = random_int_list[i] ^ keya_int_list[i]
        des3_key_list[i+8] = mid_int_list[i] ^ keyb_int_list[i]
    des3_key_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), des3_key_list))
    Des3_Cipher = des3.new(des3_key_bytes, des3.MODE_ECB)
    # 加密随机数
    random_key_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), random_int_list))
    trnd_encrpyt_bytes = Des3_Cipher.encrypt(random_key_bytes)
    # trnd_bytes= rnd.randbytes(8)

    trnd_bytes = [0xA2,0xD6,0x00,0x10,0x10,0x00,0x10,0x10]

    command_bytes = [0xA2,0xD6,0x00,0x10,0x10]
    command_bytes.extend(trnd_encrpyt_bytes)
    command_bytes.extend(trnd_bytes)
    res,s1,s2 = sendCommand(card_service,command_bytes)
    if s1 == 144 and s2 == 0:
      res,s1,s2 = sendCommand(card_service,[0xA2,0xB0,0x00,0x10,0x10])
      trnd_bytes = b''.join(map(lambda d: int.to_bytes(d, 1, 'little'), trnd_bytes))
      trnd_encrpyt_bytes = Des3_Cipher.encrypt(trnd_bytes)
      if bytes2hexstr(trnd_encrpyt_bytes) == bytes2hexstr(res[0:8]):
          print('验证成功')


    return Des3_Cipher

# 读读取数据
def COS_Read_Data(card_service,Des3_Cipher, address_int, length_int, package_size):
  result_print("COS读取数据")
  result = False
  # 选中PL DATA
  rf_command_bytes = [0xA2,0xA4,0x00,0x0C,0x02,0xDA,0x01]
  data_bytes,s1,s2 = sendCommand(rf_command_bytes)
  # 读数据
  data_bytes = ISO14443_4A_ReadBinary(0xA2, address_int, length_int, package_size)
  data_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), data_bytes))
  data_bytes = Des3_Cipher.decrypt(data_bytes)
  data_str = bytes2hexstr(data_bytes)
  result = True
  result_print("成功", result)
  result_print(data_str, result)
  return result, data_bytes

# 读取温度
def COS_Read_Tempture(card_service,Des3_Cipher):
  result_print("COS读取温度")
  result = False
  tempture_int = 0
  # 选中PL DATA
  command_bytes = [0xA2,0xA4,0x00,0x0C,0x02,0xDA,0x01]
  data_bytes,s1,s2 = sendCommand(card_service,command_bytes)

  # 读取数据
  data_bytes = ISO14443_4A_ReadBinary(card_service,0xA2, 0, 80, 60)
  data_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), data_bytes))
  data_bytes = Des3_Cipher.decrypt(data_bytes)
  print('report: '+bytes2hexstr(data_bytes))
  # 解析数据
  data_bias = 12
  CID_bytes  = data_bytes[data_bias+0: data_bias+2]
  TID_bytes  = data_bytes[data_bias+2: data_bias+8]
  GTIN_bytes = data_bytes[data_bias+8: data_bias+18]
  VID_bytes  = data_bytes[data_bias+18:data_bias+26]
  MID_bytes  = data_bytes[data_bias+26:data_bias+34]
  MAC_bytes  = data_bytes[data_bias+34:data_bias+42]
  TRNG_bytes = data_bytes[data_bias+42:data_bias+50]
  PAGE_bytes = data_bytes[data_bias+50:data_bias+51]
  RNUM_bytes = data_bytes[data_bias+51:data_bias+55]
  Cal_Data = [[0 for i in range(2)] for j in range(3)]
  Cal_Data[0][0] = (data_bytes[data_bias+55]*16 + (data_bytes[data_bias+56]>>4))/10
  Cal_Data[0][1] = (data_bytes[data_bias+56]&0x0F)*256 + data_bytes[data_bias+57]
  Cal_Data[1][0] = (data_bytes[data_bias+58]*16 + (data_bytes[data_bias+59]>>4))/10
  Cal_Data[1][1] = (data_bytes[data_bias+59]&0x0F)*256 + data_bytes[data_bias+60]
  Cal_Data[2][0] = (data_bytes[data_bias+61]*16 + (data_bytes[data_bias+62]>>4))/10
  Cal_Data[2][1] = (data_bytes[data_bias+62]&0x0F)*256 + data_bytes[data_bias+63]
  info_json = {
      "CID":bytes2hexstr(CID_bytes),
      "TID":bytes2hexstr(TID_bytes),
      "GTIN":bytes2hexstr(GTIN_bytes),
      "VID":bytes2hexstr(VID_bytes),
      "MID":bytes2hexstr(MID_bytes),
      "MAC":bytes2hexstr(MAC_bytes),
      "TRNG":bytes2hexstr(TRNG_bytes),
      "PAGE":bytes2hexstr(PAGE_bytes),
      "RUNM":bytes2hexstr(RNUM_bytes),
      "CAL1":{
            "TEMP":str(Cal_Data[0][0]),
            "ADC":str(Cal_Data[0][1])
        },
      "CAL2":{
            "TEMP":str(Cal_Data[1][0]),
            "ADC":str(Cal_Data[1][1])
        },
      "CAL3":{
            "TEMP":str(Cal_Data[2][0]),
            "ADC":str(Cal_Data[2][1])
        }
  }

  command_bytes = [0xA2,0xB0,0x00,0x4E,0x08]
  data_bytes,s1,s2 = sendCommand(card_service,command_bytes)
  data_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), data_bytes))
  data_bytes = Des3_Cipher.decrypt(data_bytes)
  tempture_int = int(str(data_bytes[0]))*256 + int(str(data_bytes[1]))
  adc_data_int = tempture_int >> 5
  if(adc_data_int<Cal_Data[1][1]):
    tempture1 = Cal_Data[0][0]
    adc1 = Cal_Data[0][1]
    tempture2 = Cal_Data[1][0]
    adc2 = Cal_Data[1][1]
  else:                         
    tempture1 = Cal_Data[1][0]
    adc1 = Cal_Data[1][1]
    tempture2 = Cal_Data[2][0]
    adc2 = Cal_Data[2][1]
  k = (tempture1-tempture2)/(adc1-adc2)
  b = tempture1 - (k*adc1)
  tempture_float = k*adc_data_int + b
  info_json['tempture_data'] = round(tempture_float,2)
  return info_json

# 读数据
def ISO14443_4A_ReadBinary(card_service,cla_bytes, address_start_int, length_int, RF_PACKAGE_SIZE):
  data_read_bytes = []
  des3_key_int_list = [0 for i in range(2)]
  package_size_int = RF_PACKAGE_SIZE
  package_number_int = int(length_int / package_size_int)
  package_bytes_left_int = length_int % package_size_int
  i = 0
  # 读取整包数据
  for i in range (0, package_number_int):
    data_address_int = address_start_int + i * package_size_int
    des3_key_int_list[0] = int(data_address_int/256)
    des3_key_int_list[1] = int(data_address_int%256)
    data_address_bytes = int_list2bytes(des3_key_int_list)
    rf_command_bytes = [cla_bytes,0xB0]
    rf_command_bytes.extend(data_address_bytes)
    rf_command_bytes.extend(bytes([package_size_int]))

    data_bytes, s1,s2 = sendCommand(card_service,rf_command_bytes)
    if s1 == 144 and s2 == 0:
      data_read_bytes.extend(data_bytes)
  # 读取剩余数据
  if package_bytes_left_int!=0:
    if package_number_int!=0:
        i = i+1
    data_address_int = address_start_int + i * package_size_int
    des3_key_int_list[0] = int(data_address_int/256)
    des3_key_int_list[1] = int(data_address_int%256)
    data_address_bytes = int_list2bytes(des3_key_int_list)
    rf_command_bytes = [cla_bytes,0xB0]
    rf_command_bytes.extend(data_address_bytes)
    rf_command_bytes.extend(bytes([package_size_int]))
    data_bytes, s1,s2 = sendCommand(card_service,rf_command_bytes)
    if s1 == 144 and s2 == 0:
      data_read_bytes.extend(data_bytes)
  return data_read_bytes

# ISO14443-4A更新数据
def ISO14443_4A_UpdateBinary(card_service,cla_bytes, address_start_int, length_int, data_write_bytes, RF_PACKAGE_SIZE):
  des3_key_int_list = [0 for i in range(2)]
  package_size_int = RF_PACKAGE_SIZE
  package_number_int = int(length_int / package_size_int)
  package_bytes_left_int = length_int % package_size_int
  i = 0
  # 写整包数据
  for i in range (0, package_number_int):
    data_address_int = address_start_int + i * package_size_int
    des3_key_int_list[0] = int(data_address_int/256)
    des3_key_int_list[1] = int(data_address_int%256)
    data_address_bytes = int_list2bytes(des3_key_int_list)
    rf_command_bytes = [cla_bytes,0xD6]
    rf_command_bytes.extend(data_address_bytes)
    rf_command_bytes.extend(bytes([package_size_int]))
    rf_command_bytes.extend(data_write_bytes[i*package_size_int : (i+1)*package_size_int])
    data_bytes,s1,s2 = sendCommand(card_service,rf_command_bytes)
    tm.sleep(0.01)
  # 写剩余数据
  if package_bytes_left_int!=0:
    # tm.sleep(0.01)
    if package_number_int!=0:
        i = i+1
    data_address_int = address_start_int + i * package_size_int
    des3_key_int_list[0] = int(data_address_int/256)
    des3_key_int_list[1] = int(data_address_int%256)
    data_address_bytes = int_list2bytes(des3_key_int_list)
    
    rf_command_bytes = [cla_bytes,0xD6]
    rf_command_bytes.extend(data_address_bytes)
    rf_command_bytes.extend(bytes([package_bytes_left_int]))
    rf_command_bytes.extend(data_write_bytes[i*package_size_int:i*package_size_int+package_bytes_left_int])
    data_bytes, s1,s2 = sendCommand(card_service,rf_command_bytes)
    tm.sleep(0.01)
  return data_bytes

# 读取配置文件
def COS_Read_Config(card_service,Des3_Cipher, address_int, length_int, package_size):
  result_print("COS读取配置数据")
  result = False
  # 选中CONFIG
  rf_command_bytes = [0xA2,0xA4,0x00,0x0C,0x02,0xCF,0x01]
  data_bytes, s1,s2  = sendCommand(card_service,rf_command_bytes)
  # 读数据
  data_bytes = ISO14443_4A_ReadBinary(card_service,0xA2, address_int, length_int, package_size)
  data_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), data_bytes))
  data_bytes = Des3_Cipher.decrypt(data_bytes)
  data_str = bytes2hexstr(data_bytes)
  result = True
  result_print('config file :'+ data_str)
  return data_bytes

# 读取配置文件
def COS_Read_Data(card_service,Des3_Cipher, address_int, length_int, package_size):
  result_print("COS读取DATA数据")
  result = False
  # 选中CONFIG
  rf_command_bytes = [0xA2,0xA4,0x00,0x0C,0x02,0x00,0x01]
  data_bytes, s1,s2  = sendCommand(card_service,rf_command_bytes)
  # 读数据
  data_bytes = ISO14443_4A_ReadBinary(card_service,0xA2, address_int, length_int, package_size)
  data_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), data_bytes))
  data_bytes = Des3_Cipher.decrypt(data_bytes)
  data_str = bytes2hexstr(data_bytes)
  result = True
  result_print('DATA file :'+ data_str)
  return data_bytes

# 修改配置文件
def COS_Write_Config(card_service,Des3_Cipher, address_int, length_int, write_bytes, package_size):
  result_print("COS写入配置数据")
  result = False
  # 选中CONFIG
  rf_command_bytes = [0xA2,0xA4,0x00,0x0C,0x02,0xCF,0x01]
  data_bytes, s1, s2 = sendCommand(card_service,rf_command_bytes)
  write_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), write_bytes))
  data_write_bytes = Des3_Cipher.encrypt(write_bytes)
  data_bytes = ISO14443_4A_UpdateBinary(card_service,0xA2, address_int, length_int, data_write_bytes, package_size)
  if data_bytes!=b'':
    result = True
    result_print("COS写入配置数据 成功")
  if result == False:
    result_print("COS写入配置数据 失败")
  return result

# 修改data文件
def COS_Write_Data(card_service,Des3_Cipher, address_int, length_int, write_bytes, package_size):
  result_print("COS写入data数据")
  result = False
  # 选中CONFIG
  rf_command_bytes = [0xA2,0xA4,0x00,0x0C,0x02,0x00,0x01]
  data_bytes, s1, s2 = sendCommand(card_service,rf_command_bytes)
  write_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), write_bytes))
  data_write_bytes = Des3_Cipher.encrypt(write_bytes)
  data_bytes = ISO14443_4A_UpdateBinary(card_service,0xA2, address_int, length_int, data_write_bytes, package_size)
  if data_bytes!=b'':
    result = True
    result_print("COS写入配置数据 成功")
  if result == False:
    result_print("COS写入配置数据 失败")
  return result


# 数据解析
def COS_Analysis(card_service,Des3_Cipher, DATA_SIZE, show_picture_tag):
  TEMPTURE_SHOW = True                                                                                    # 显示温度
  # TEMPTURE_CAL_TYPE = "KB"                                                                              # KB校准
  TEMPTURE_CAL_TYPE = "3POS"  
  result_print("COS数据解析")
  # 选中DATA
  rf_command_bytes = [0xA2,0xA4,0x00,0x0C,0x02,0xDA,0x01]
  data_bytes, s1,s2 = sendCommand(card_service,rf_command_bytes)
  # 读取数据
  data_bytes = ISO14443_4A_ReadBinary(card_service,0xA2, 0, 80, DATA_SIZE)
  data_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), data_bytes))
  data_bytes = Des3_Cipher.decrypt(data_bytes)
  print('report: '+bytes2hexstr(data_bytes))
  # 解析数据
  data_bias = 12
  CID_bytes  = data_bytes[data_bias+0: data_bias+2]
  TID_bytes  = data_bytes[data_bias+2: data_bias+8]
  GTIN_bytes = data_bytes[data_bias+8: data_bias+18]
  VID_bytes  = data_bytes[data_bias+18:data_bias+26]
  MID_bytes  = data_bytes[data_bias+26:data_bias+34]
  MAC_bytes  = data_bytes[data_bias+34:data_bias+42]
  TRNG_bytes = data_bytes[data_bias+42:data_bias+50]
  PAGE_bytes = data_bytes[data_bias+50:data_bias+51]
  RNUM_bytes = data_bytes[data_bias+51:data_bias+55]
  if TEMPTURE_CAL_TYPE=="KB":
    RES_bytes  = data_bytes[data_bias+55:data_bias+58]
    K_bytes    = data_bytes[data_bias+58:data_bias+62]
    B_bytes    = data_bytes[data_bias+62:data_bias+66]
    info_json = {
          "CID":bytes2hexstr(CID_bytes),
          "TID":bytes2hexstr(TID_bytes),
          "GTIN":bytes2hexstr(GTIN_bytes),
          "VID":bytes2hexstr(VID_bytes),
          "MID":bytes2hexstr(MID_bytes),
          "MAC":bytes2hexstr(MAC_bytes),
          "TRNG":bytes2hexstr(TRNG_bytes),
          "PAGE":bytes2hexstr(PAGE_bytes),
          "RUNM":bytes2hexstr(RNUM_bytes),
          "RES":bytes2hexstr(RES_bytes),
          "K":bytes2hexstr(K_bytes),
          "B":bytes2hexstr(B_bytes)
      }
  else:
    Cal_Data = [[0 for i in range(2)] for j in range(3)]
    Cal_Data[0][0] = (data_bytes[data_bias+55]*16 + (data_bytes[data_bias+56]>>4))/10
    Cal_Data[0][1] = (data_bytes[data_bias+56]&0x0F)*256 + data_bytes[data_bias+57]
    Cal_Data[1][0] = (data_bytes[data_bias+58]*16 + (data_bytes[data_bias+59]>>4))/10
    Cal_Data[1][1] = (data_bytes[data_bias+59]&0x0F)*256 + data_bytes[data_bias+60]
    Cal_Data[2][0] = (data_bytes[data_bias+61]*16 + (data_bytes[data_bias+62]>>4))/10
    Cal_Data[2][1] = (data_bytes[data_bias+62]&0x0F)*256 + data_bytes[data_bias+63]
    info_json = {
        "CID":bytes2hexstr(CID_bytes),
        "TID":bytes2hexstr(TID_bytes),
        "GTIN":bytes2hexstr(GTIN_bytes),
        "VID":bytes2hexstr(VID_bytes),
        "MID":bytes2hexstr(MID_bytes),
        "MAC":bytes2hexstr(MAC_bytes),
        "TRNG":bytes2hexstr(TRNG_bytes),
        "PAGE":bytes2hexstr(PAGE_bytes),
        "RUNM":bytes2hexstr(RNUM_bytes),
        "CAL1":{
              "TEMP":str(Cal_Data[0][0]),
              "ADC":str(Cal_Data[0][1])
          },
        "CAL2":{
              "TEMP":str(Cal_Data[1][0]),
              "ADC":str(Cal_Data[1][1])
          },
        "CAL3":{
              "TEMP":str(Cal_Data[2][0]),
              "ADC":str(Cal_Data[2][1])
          }
    }
  result_print(info_json)
  record_number_int = bytes2int(RNUM_bytes)
  record_data_size_int = int(record_number_int*11/8)
  if(record_number_int*11%8):
    record_data_size_int += 1
  record_data_size_mod_int = record_data_size_int%8
  if(record_data_size_mod_int):
    record_data_size_int = record_data_size_int + (8-record_data_size_mod_int)
  # 读取数据
  NDEF_MAX_INT = 4032
  start_address_int = 78
  if (start_address_int+record_data_size_int)>NDEF_MAX_INT:
    record_data_size_int = record_data_size_int - 8
    record_number_int = int(record_data_size_int*8/11)
  data_bytes = ISO14443_4A_ReadBinary(card_service,0xA2, 78, record_data_size_int, DATA_SIZE)
  data_bytes = b''.join(map(lambda d:int.to_bytes(d, 1, 'little'), data_bytes))
  data_bytes = Des3_Cipher.decrypt(data_bytes)
  # 解析adc
  tempture_data = [0 for i in range(record_number_int)]
  repeat_cnt = int(record_number_int/8)
  count_residue = record_number_int%8
  if count_residue>0:
    repeat_cnt += 1
  decode_count = 0
  for i in range(0, repeat_cnt):
    for j in range(0, 8):
      if decode_count>=record_number_int:
        break
      else:
        decode_count += 1
      if j==0:
        adc_data_int = data_bytes[i*11]*256+data_bytes[i*11+1]
        adc_data_int = (adc_data_int&0x0000FFE0)>>5
      elif j==1:
        adc_data_int = data_bytes[i*11+1]*256+data_bytes[i*11+2]
        adc_data_int = (adc_data_int&0x00001FFC)>>2
      elif j==2:
        adc_data_int = data_bytes[i*11+2]*65536+data_bytes[i*11+3]*256+data_bytes[i*11+4]
        adc_data_int = (adc_data_int&0x0003FF80)>>7
      elif j==3:
        adc_data_int = data_bytes[i*11+4]*256+data_bytes[i*11+5]
        adc_data_int = (adc_data_int&0x00007FF0)>>4
      elif j==4:
        adc_data_int = data_bytes[i*11+5]*256+data_bytes[i*11+6]
        adc_data_int = (adc_data_int&0x00000FFE)>>1
      elif j==5:
        adc_data_int = data_bytes[i*11+6]*65536+data_bytes[i*11+7]*256+data_bytes[i*11+8]
        adc_data_int = (adc_data_int&0x0001FFC0)>>6
      elif j==6:
        adc_data_int = data_bytes[i*11+8]*256+data_bytes[i*11+9]
        adc_data_int = (adc_data_int&0x000003FF8)>>3
      elif j==7:
        adc_data_int = data_bytes[i*11+9]*256+data_bytes[i*11+10]
        adc_data_int = (adc_data_int&0x000007FF)>>0
      adc_data_int = int(adc_data_int)
      if TEMPTURE_SHOW==True:
        if(adc_data_int<Cal_Data[1][1]):                            # 温度小于第二个校准点,使用第一个点和第二个点计算KB值
          tempture1 = Cal_Data[0][0]
          adc1 = Cal_Data[0][1]
          tempture2 = Cal_Data[1][0]
          adc2 = Cal_Data[1][1]
        else:                         
          tempture1 = Cal_Data[1][0]
          adc1 = Cal_Data[1][1]
          tempture2 = Cal_Data[2][0]
          adc2 = Cal_Data[2][1]
        if (adc1 - adc2) == 0:
            print('标签未标定')
            return info_json
        k = (tempture1-tempture2)/(adc1-adc2)
        b = tempture1 - (k*adc1)
        tempture_float = k*adc_data_int + b
        tempture_data[decode_count-1] = tempture_float
      else:
        tempture_data[decode_count-1] = adc_data_int
  result_print(str(tempture_data))
  info_json['tempture_data'] = tempture_data
  # 波形显示
  if show_picture_tag:
    DATA_FILTER = 0
    x = [0 for i in range(record_number_int)]
    for i in range(0, record_number_int):
      x[i] = i
    plt.figure(figsize=(20.48, 10.24))
    plt.title('Tempture Record')
    lable_name = bytes2hexstr(VID_bytes)
    plt.plot(x, tempture_data, label= lable_name)
    plt.legend() # 显示图例
    plt.ylim(0, 2048)
    plt.ylabel('adc value')
    plt.xlabel('time')
    plt.show()
  return info_json

# 读取芯片UID
def read_uid(card_service):
  rf_command_bytes = [0xFF,0xCA,0x00,0x00,0x00]
  res,s1,s2 = sendCommand(card_service,rf_command_bytes)
  return bytes2hexstr(res)

def write_data(card_service,Des3_Cipher,write_bytes):
    print('进来了')
    COS_Write_Config(card_service, Des3_Cipher, 49216, len(write_bytes), write_bytes, 56)
    data_bytes = COS_Read_Config(card_service, Des3_Cipher, 49216, len(write_bytes), 56)
    data_bytes = data_bytes[:len(data_bytes)]
    result = bytes.decode(data_bytes[:len(data_bytes) -16])
    return result





# card_service = init()
# result = read_uid(card_service)
# Des3_Cipher = COS_Access(card_service,'0xA0 0xA1 0xA2 0xA3 0xA4 0xA5 0xA6 0xA7','0xA8 0xA9 0xAA 0xAB 0xAC 0xAD 0xAE 0xAF')


# Des3_Cipher = COS_Access(card_service,'0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07','0x08 0x09 0x00 0x0B 0x0C 0x0D 0x0E 0x0F')
# COS_Analysis(card_service,Des3_Cipher,56,False)

# COS_Write_Config(card_service,Des3_Cipher,49162,8,[0xF0, 0x03, 0x00, 0x0F, 0x20, 0x00, 0xF6, 0x00],8)


# data_bytes = COS_Read_Config(card_service,Des3_Cipher,49162,8,8)
# COS_Read_Tempture(card_service,Des3_Cipher)
# a = rnd.randbytes(8)
#
# write_str = '毛毛;;15751396666;;子涵;;202112170001;;浙江省杭州市萧山啊啊区鸿兴路111号;;data:image/jpeg;base64,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'
# str2byte = bytes(write_str, encoding = "utf8")
# print(bytes2hexstr(str2byte))


# COS_Write_Config(card_service,Des3_Cipher,49216,len(str2byte),str2byte,56)
#
# data_bytes = COS_Read_Config(card_service,Des3_Cipher,49216,len(str2byte),56)
# print(str2byte)
# print(data_bytes)
# print(bytes.decode(data_bytes[:len(data_bytes) -16]))

