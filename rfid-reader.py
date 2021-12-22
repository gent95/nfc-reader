import serial
import binascii

def openSer():
    ser = serial.Serial("com6", 9600, timeout=0.5)
    ser.bytesize = 8  # 字节大小
    ser.parity = serial.PARITY_NONE  # 无校验
    ser.stopbits = 1  # 停止位
    print("已连接端口：" + str(ser.name) + "\n")
    return ser;

aa= openSer()