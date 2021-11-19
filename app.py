from flask import Flask,request
import securityReader as reader
from gevent import pywsgi


app = Flask(__name__)


@app.after_request
def cors(environ):
    environ.headers['Access-Control-Allow-Origin'] = '*'
    environ.headers['Access-Control-Allow-Method'] = '*'
    environ.headers['Access-Control-Allow-Headers'] = 'x-requested-with,content-type'
    return environ

# 读无源芯片温度数据
@app.route("/read_wy")
def read_wy():
	keya = request.args.get('keya')
	keyb = request.args.get('keyb')
	if len(keya) == 0 or len(keyb) == 0:
		return '必要参数不能为空'

	card_service = reader.init()
	Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
	info_json = reader.COS_Read_Tempture(card_service,Des3_Cipher)


	result = {
		"code":200,
		"msg":'操作成功',
		"keya":keya,
		"keyb":keyb,
		"info" :info_json
	}
	return result

# 读有源芯片温度数据
@app.route("/read_yy")
def read_yy():
	keya = request.args.get('keya')
	keyb = request.args.get('keyb')
	if len(keya) == 0 or len(keyb) == 0:
		return '必要参数不能为空'

	card_service = reader.init()
	Des3_Cipher = reader.COS_Access(card_service,keya,keyb)
	info_json = reader.COS_Analysis(card_service,Des3_Cipher,60,False)


	result = {
		"code":200,
		"msg":'操作成功',
		"keya":keya,
		"keyb":keyb,
		"info" :info_json
	}
	return result

# 激活有源芯片
@app.route("/activation")
def activation():
	keya = request.args.get('keya')
	keyb = request.args.get('keyb')
	if len(keya) == 0 or len(keyb) == 0:
		return '必要参数不能为空'



@app.route("/write")
def activation():
	keya = request.args.get('keya')
	keyb = request.args.get('keyb')
	payload = request.args.get('payload')
	if len(keya) == 0 or len(keyb) == 0:
		return '必要参数不能为空'


server = pywsgi.WSGIServer(('0.0.0.0', 5000), app)
server.serve_forever()
app.run()
	