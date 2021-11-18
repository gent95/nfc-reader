import wx
import securityReader as nfc_reader

class NFC_READER(wx.Frame):
	def __init__(self, parent,title):
		super(NFC_READER, self).__init__(parent, title = title,size = (600,200))
		panel = wx.Panel(self) 
		vbox = wx.BoxSizer(wx.VERTICAL) 
	         
		hbox1 = wx.BoxSizer(wx.HORIZONTAL) 
		l1 = wx.StaticText(panel, -1, "KeyA:") 
			
		hbox1.Add(l1, 1, wx.ALIGN_LEFT,5) 
		self.t1 = wx.TextCtrl(panel) 
			
		hbox1.Add(self.t1,1,wx.ALIGN_LEFT,15) 
		self.t1.Bind(wx.EVT_TEXT,self.OnKeyTyped) 
		vbox.Add(hbox1) 

		hbox2 = wx.BoxSizer(wx.HORIZONTAL) 
		l2 = wx.StaticText(panel, -1, "KeyB:") 
			
		hbox2.Add(l2, 1, wx.ALIGN_LEFT,5) 
		self.t2 = wx.TextCtrl(panel) 
			
		hbox2.Add(self.t2,1,wx.ALIGN_LEFT,15) 
		self.t2.Bind(wx.EVT_TEXT,self.OnKeyTyped) 
		vbox.Add(hbox2) 


		panel.SetSizer(vbox)
		self.Centre() 
		self.Show()

	def OnKeyTyped(self, event): 
		if len(event.GetString()) > 16:
			print('长度超出')

app = wx.App() 
NFC_READER(None, '中义读卡器') 
app.MainLoop()
		

# def openfile(event):     # 定义打开文件事件
#     path = path_text.GetValue()
#     with open(path,"r",encoding="utf-8") as f:  # encoding参数是为了在打开文件时将编码转为utf8
#         content_text.SetValue(f.read())

# def init_device():
# 	card_service = nfc_reader.init()

# def saveContent(event):
# 	card_service = nfc_reader.init()
# 	Des3_Cipher = nfc_reader.COS_Access(card_service,'0xA0 0xA1 0xA2 0xA3 0xA4 0xA5 0xA6 0xA7','0xA8 0xA9 0xAA 0xAB 0xAC 0xAD 0xAE 0xAF')

# def create_window():
# 	app = wx.App()
# 	frame = wx.Frame(None,title = "中义NFC读写器",pos = (1000,200),size = (500,400))
# 	path_text = wx.TextCtrl(frame,pos = (5,5),size = (350,24))

# 	open_button = wx.Button(frame,label = "打开",pos = (5,5),size = (50,24))
	
# 	save_button = wx.Button(frame,label = "保存",pos = (430,5),size = (50,24))
# 	init_device_button = wx.Button(frame,label = "打开读卡器",pos = (570,20),size = (100,24))
	 
# 	# content_text= wx.TextCtrl(frame,pos = (5,39),size = (475,300),style = wx.TE_MULTILINE)
# 	open_button.Bind(wx.EVT_BUTTON,openfile)
# 	save_button.Bind(wx.EVT_BUTTON,saveContent)
# 	init_device_button.Bind(wx.EVT_BUTTON,init_device)



# 	 panel = wx.Panel(self) 
#      box = wx.BoxSizer(wx.VERTICAL) 
#      lbl = wx.StaticText(panel,-1,style = wx.ALIGN_CENTER)


# 	frame.Show()
# 	app.MainLoop()


# create_window()