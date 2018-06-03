import sys

count = 0
postfix = "], ex),[])."

limit = 10

f = open("ips.pl", 'r')
f_w = open("evidence.pl", 'w')

for line in f:
	if (count < limit):
		prefix = "rule(f" + str(count) + "(),attackSourceIP(["
		ip = line.replace('.', ',').replace('\n', '')
		f_w.write(prefix + ip + postfix + "\n")
		f_w.write("rule(f" + str(count) + "a(),ip([" + ip + "], []).\n")
		count += 1	
	else:
		break
