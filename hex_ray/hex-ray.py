from idaapi import *
from re import *

def isNumber(s):
	try:
		float(s)
		return True
	except ValueError:
		return False

def index_serach(s,s2):
	try:
		return s2.index(s)
	except ValueError:
		return -1


addr = here()
start = SegStart(addr)
end = SegEnd(addr)

hexray = LocByName(GetFunctionName(addr))
asm = ""
reg = ['eax','ebx','ecx','edx','esi','edi','esp','ebp']
tmp = ['','','','','','','','','','','','','','','']
push_tmp = []

prologue = 0
check = 0
arg_count = 0

f = open("C:\Users\y0ubat\Desktop\hex-ray00.c","w")
f.write("int " + GetFunctionName(addr) + "()\n{\n")

for h in FuncItems(hexray):
	check = 0

	if "xor     eax, eax" == GetDisasm(h):
		prologue = 1
		continue
	elif prologue == 0:
		continue
	
	if GetDisasm(h).find("[ebp+var_C]") > 0:
		f.write("\treturn " + str(tmp[0])+";\n") 
		break
	
	ins = GetMnem(h)
	op1 = GetOpnd(h,0)
	op2 = GetOpnd(h,1)

	if "mov" == ins:
		if findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:
			pass
		else: 
			op1 = findall(r"var_[(0-9a-fA-F)]{1,}",op1)

		if findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
			pass
		else:
			op2 = findall(r"var_[(0-9a-fA-F)]{1,}",op2)

		if index_serach(op2,reg) >= 0:    # if op2 reg
			check = 1
			if op1[0].find("var_") >= 0:
				f.write("\tint " + str(op1[0]) + "= " + str(tmp[index_serach(op2,reg)])+";\n")


		if index_serach(op1,reg) >= 0:     # if op1 reg
			if op2[0].find("var_") >= 0:
				tmp[index_serach(op1,reg)] = str(op2[0])
				print tmp
			else:
				if check == 1:              # op2 check 
					pass
				else:
					if op2.find("h") >= 0:
						op2 = op2.split('h')[0]
						tmp[index_serach(op1,reg)] = str(int(op2,16))
					else:
						if isNumber(op2):
							tmp[index_serach(op1,reg)] = str(op2)



		if op1[0].find("var_") >= 0:   # if op1 var 
			if check == 1:
				pass
			else:		    
				if op2.find("h") >= 0:
					op2 = op2.split('h')[0]
					f.write("\tint " + op1[0]+"="+ str(int(op2,16))+";\n")
				else:
					if isNumber(op2):
						f.write("\tint " + op1[0]+"="+ str(op2)+";\n")

			

	if "lea" == ins:
		if findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
			pass
		else:
			op2 = findall(r"var_[(0-9a-fA-F)]{1,}",op2)

		if index_serach(op1,reg) >= 0:
			tmp[index_serach(op1,reg)] = "&"+str(op2[0])

	if "xor" == ins:
		if findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:
			pass
		else: 
			op1 = findall(r"var_[(0-9a-fA-F)]{1,}",op1)

		if findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
			pass
		else:
			op2 = findall(r"var_[(0-9a-fA-F)]{1,}",op2)

		if index_serach(op2,reg) >= 0:
			if op1[0].find("var_") >= 0:
				f.write("\t"+str(op1[0]) + " ^= " + str(tmp[index_serach(op2,reg)])+";\n")



	if "sub" == ins:
		if findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:
			pass
		else: 
			op1 = findall(r"var_[(0-9a-fA-F)]{1,}",op1)

		if findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
			pass
		else:
			op2 = findall(r"var_[(0-9a-fA-F)]{1,}",op2)



	if "add" == ins:
		if findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:
			pass
		else: 
			op1 = findall(r"var_[(0-9a-fA-F)]{1,}",op1)

		if findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
			pass
		else:
			op2 = findall(r"var_[(0-9a-fA-F)]{1,}",op2)



	if "push" == ins:
		if findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:

			if index_serach(op1,reg) >=0:
				push_tmp.append(tmp[index_serach(op1,reg)])
			else:
				push_tmp.append(str(op1))

			print push_tmp
			
		else: 
			op1 = findall(r"var_[(0-9a-fA-F)]{1,}",op1)
			push_tmp.append(str(op1[0]))
			print push_tmp
			
			
	if "call" == ins:
		arg_count = len(push_tmp)
		if arg_count == 1:
			f.write("\t" + str(op1) + "(" + push_tmp[0] + ");\n")
			del(push_tmp[0])
		if arg_count > 1:
			f.write('\t' + str(op1) + "(" + push_tmp[1] + ", "+ push_tmp[0]+");\n")
			del(push_tmp[1])
			del(push_tmp[0])



		



	print "\n"
	print "ins : " + ins
	print "op1 : " + str(op1)
	print "op2 : " + str(op2)
"""
	asm += GetDisasm(h) + '\n'


for h2 in asm.split("\n"):
	if h2.split("     ")[0] == 'mov':
		ins = h2.split("     ")[0]
		op1 = h2.split("     ")[1].split(", ")[0]
		op2 = h2.split("     ")[1].split(", ")[1]
		print "\n"
		print "ins : " + ins
		print "op1 : " + op1
		print "op2 : " + op2

	if h2.split("     ")[0] == 'lea':
		ins = h2.split("     ")[0]
		op1 = h2.split("     ")[1].split(", ")[0]
		op2 = h2.split("     ")[1].split(", ")[1]
		print "\n"
		print "ins : " + ins
		print "op1 : " + op1
		print "op2 : " + op2

	if h2.split("     ")[0] == 'sub':
		ins = h2.split("     ")[0]
		op1 = h2.split("     ")[1].split(", ")[0]
		op2 = h2.split("     ")[1].split(", ")[1]
		print "\n"
		print "ins : " + ins
		print "op1 : " + op1
		print "op2 : " + op2

	if h2.split("     ")[0] == 'add':
		ins = h2.split("     ")[0]
		op1 = h2.split("     ")[1].split(", ")[0]
		op2 = h2.split("     ")[1].split(", ")[1]
		print "\n"
		print "ins : " + ins
		print "op1 : " + op1
		print "op2 : " + op2


	if h2.split("     ")[0] == 'xor':
		ins = h2.split("     ")[0]
		op1 = h2.split("     ")[1].split(", ")[0]
		op2 = h2.split("     ")[1].split(", ")[1]
		print "\n"
		print "ins : " + ins
		print "op1 : " + op1
		print "op2 : " + op2


"""

f.write("\n}")