import os
import requests
import mysql.connector
from elasticsearch import Elasticsearch
import xlwt

#创建mysql连接对象
def mysqlConnectionInit(host,port,user,password,database):
	conn=mysql.connector.connect(host = host # 连接名称，默认127.0.0.1
		,user = user # 用户名
		,passwd=password # 密码
		,port= port # 端口，默认为3306
		,db=database # 数据库名称
		,charset='utf8' # 字符编码
		)
	cur = conn.cursor() # 生成游标对象
	return conn,cur

#执行sql
def execSelect(conn,cur,sql):
	cur.execute(sql) # 执行SQL语句
	data = cur.fetchall() # 通过fetchall方法获得数据
	cur.close
	conn.close
	return data

#下载pdf
def request_download(chipNum):
	if not os.path.exists('./image/'): #os模块判断并创建
		os.makedirs('./image/', exist_ok=True)
	#邦德威pdf
	# pdf_url = 'http://121.229.41.37:8091/file/pdf/'+str(chipNum)+'_.pdf'
	#evvm 厂家pdf
	pdf_url = 'http://evvmapi.vandh.org/file/pdf/'+str(chipNum)+'.pdf'
	r = requests.get(pdf_url)
	with open('./image/'+chipNum+'.pdf', 'wb') as f:
		f.write(r.content)  

#导出pdf
def export_pdf():
	#邦德威
	#conn,cur = mysqlConnectionInit('121.229.41.37',3306,'majt','t8D!CyUCGlKD','evvm_ws')
	# sql = 'SELECT * FROM `evvm_ws`.`chip` WHERE `factoryId` = 153 AND `status` = 6' 

	# evvm
	conn,cur = mysqlConnectionInit('119.3.178.181',3306,'majt','t8D!CyUCGlKD','evvm')
	sql = 'SELECT * FROM `evvm`.`chip` WHERE `factoryId` = 166 AND `status` <> 1 AND `status` <> 0'

	data = execSelect(conn,cur,sql)
	for row in data[:]:
		request_download(row[0])
		print(row[0])

#初始化es连接对象
def elasticsearch_connection_init():
	es = Elasticsearch(["125.124.132.156:9201"])
	return es


#查询vvm温度数据
def elasticsearch_export(es,businessId):
	body = {
		"query": {
			"match_phrase": {
				"businessId": {
					"query": businessId
				}
			}
		},
		"size": 100000,
		"from": 0,
		"sort": [
		    {
		        "createTime.keyword":{
		            "order":"asc"
		        }
		    }
		    ]
	}
	data = es.search(index="vvm01", body=body)
	hits = data['hits']['hits']
	data = [0 for i in range(len(hits))]

	for i in range(len(hits)):
		record = hits[i]['_source']
		data[i] = [record['businessId'],record['temp'],record['createTime']]

	return data


#导出vvm温度数据到excel

def exportES2excel():
	conn,cur = mysqlConnectionInit('125.124.123.66',3309,'root','A123456','zy-vvm')
	sql = 'SELECT * FROM `zy-vvm`.`vvm_bussiness` WHERE `create_by` = 13612341234 AND `create_time` > 2021-11-06 AND `bind_status` = 1'
	data = execSelect(conn,cur,sql)
	es = elasticsearch_connection_init()
	workbook = xlwt.Workbook( encoding="utf-8" )
	for row in data[:]:
		data = elasticsearch_export(es,row[0])
		sheet = workbook.add_sheet(row[3],True)
		for i in range(len(data)):
			for j in range(len(data[i])):
				sheet.write( i, j, data[i][j])

	workbook.save('vvm温度数据.xlsx')

# exportES2excel()

es = elasticsearch_connection_init()
data = elasticsearch_export(es,'0a5ac4c6-19b5-416e-ab11-9027655a3632')
conn,cur = mysqlConnectionInit('125.124.123.66',3309,'root','A123456','zy-kgzs')
for data in data[:]:
	sql = 'INSERT INTO vvm_temp_2222222 (temp, create_time) VALUES (%s,%s)'
	param =(data[1],data[2])
	print(str(data[2]))
	data = cur.execute(sql,param) # 执行SQL语句
	
conn.commit()