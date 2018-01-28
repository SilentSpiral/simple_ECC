import os, random, base64, time

p =0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF 
a =0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC 
b =0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93 
n =0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123 
Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7 
Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G =(Gx,Gy)

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)  # g为公因子
		return (g, x - (b // a) * y, y)

def modinv(a, m):
	g, x, y = egcd(a, m)
	if (g != 1):
		print('modular inverse does not exist')
	else:
		return x % m

def PointAdd(a,p,A,B):
	if A[0]==None:
		return B
	if B[0]==None:
		return A
	if A[0]==B[0]:
		if A[1]!=B[1]:
			return(None,None)
		else:
			lam=(((3*(A[0]**2)+a)%p)* modinv(2*A[1], p))%p
	else:
		lam=(((B[1]-A[1])%p)* modinv((B[0]-A[0])%p, p))%p
	x3=(lam**2-A[0]-B[0] )% p
	y3=(lam*(A[0]-x3)-A[1]) % p
	return (x3,y3)
	
def MultipyPoint(n,A,a,p):   #借鉴了模重复平方计算法
	D=(None,None)
	E=bin(n)[2:]
	for i in range(len(E)):
		D=PointAdd(a,p,D,D)
		if E[i]=="1":
			D=PointAdd(a,p,D,A)
	return D
	
def bytes2int(text,l,r): #加密输入l=31,解密输入l=32
	b=text
	data = []
	for i in range(r):
		a=b[:l]
		c = 0
		for j in range(l):
			c+=a[j]<<(8*(l-j-1))
		data.append(c)
		b=b[l:]
	return data
	
def int2bytes(data,l):    #解密输出l=31,加密输出l=32
	text = []
	for i in data:
		A = i
		for j in range(l)[::-1]:
			text.append((A >> 8*j) % 0x100)
	text = bytes(text)
	return text
	
def MessageDiv(A):
	if (len(A))%31!=0:
		A=A+bytes(31-(len(A))%31)
	r=len(A)//31
	return bytes2int(A,31,r)

def encrypt(message,Qx,Qy):
	block = MessageDiv(message)
	data = []
	for i in block:
		flag = False
		while not flag:
			k=random.randrange(300,n-1)
			X1=MultipyPoint(k,G,a,p)
			X2=MultipyPoint(k,Q,a,p)
			if X2[0]!=None:
				flag=True
		C=X2[0]*i%n
		data.append(X1[0])
		data.append(X1[1])
		data.append(C)
	return int2bytes(data,32)

def decrypt(message,d):
	r=len(message)//96
	C = bytes2int(message,32,r*3)
	data = []
	for i in range(r):
		X1=(C[0],C[1])
		X2=MultipyPoint(d,X1,a,p)
		V=modinv(X2[0], n)
		data.append((C[2]*V)%n)
		C=C[3:]
	return int2bytes(data,31)

if __name__ == "__main__":
	os.system("title  ECC")
	coding=['utf-8','GBK']
	Inv = input('请选择:1.加密 2.解密: ')
	
	if Inv == '2':
		d = eval(input('请输入私钥d: '))
		Message = bytes(input('\n请输入base64格式的密文: '), encoding='ascii')
		start = time.clock()
		Message = base64.b64decode(Message)
		text = decrypt(Message,d)
	else:
		Qx = eval(input('请输入公钥Qx: '))
		Qy = eval(input('请输入公钥Qy: '))
		Q = (Qx,Qy)
		choose=int(input('\n请选择明文编码:1.utf-8 2.GBK: '))-1
		EnCo=coding[choose]
		Message = bytes(input('请输入明文: '), encoding=EnCo)
		start = time.clock()
		text = encrypt(Message,Qx,Qy)
	
	ans = ['UTF-8','GBK']
	
	if Inv == '1':
		text = base64.b64encode(text)
		text = str(text, encoding="ascii")
		print('\n密文(以base64形式输出):\n', text)
	else:
		#print(text)
		#print(len(text))
		flag=0
		print('\n明文:\n')
		for i in range(2):
			try:
				plaintext = " "+ans[i]+': '+text.decode(coding[i])
				print(plaintext)
				flag+=1
			except:
				#print("*"+ans[i]+"解码失败!")
				pass
		if flag==0:
			print("\n解密失败!\n请核对密文/密钥的完整性或使用其他编码字符集\n")
		elif flag==1:
			print("")
		else:
			print("-----------------------------\n*请根据语义判断明文内容\n")
			
	end = time.clock()
	print("\n运算耗时 %f秒" % (end  - start))
	
	os.system("PAUSE")