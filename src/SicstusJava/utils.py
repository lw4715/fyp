import sys
malware_name = 'wannacry'

n = 6
filename = 'fireeyetech'
f = open(filename + '.txt', 'r')
counter = 0
line_count = -1
es = []
for line in f:
	if counter == 0:
		es.append([])
		line_count += 1
	w = line.replace("\n", "")
	if len(w) > 2:
		es[line_count].append(w)
		counter = (counter + 1)%n


print(es, len(es))
f_w = open("tmp/" + filename + "prolog_rule.pl", 'w')
cnt = 0
for e in es:
	if len(e) == n:
		rule = "fileCharaMalware({}_filechara{}, {}).\n".format(malware_name, cnt, malware_name)
		rule += "fileChara('{}', '{}', '{}', '{}', '{}', '{}', {}_filechara{}).\n".format(e[0],e[1],e[2],e[3],e[4],e[5], malware_name, cnt)
		cnt += 1
		print(rule)
		f_w.write(rule)


n = 3
filename = 'fireeyetech_loader'
f = open(filename + '.txt', 'r')
counter = 0
line_count = -1
es = []
for line in f:
	if counter == 0:
		es.append([])
		line_count += 1
	w = line.replace("\n", "")
	if len(w) > 2:
		word = w.split(": ")[1]
		es[line_count].append(word)
		counter = (counter + 1)%n


print(es, len(es))
f_w = open("tmp/" + filename + "prolog_rule.pl", 'w')
cnt = 0
for e in es:
	if len(e) == n:
		rule = "loaderFileArtifactMalware({}_loaderfileArt{}, {}).\n".format(malware_name, cnt, malware_name)
		rule += "loaderFileArtifact('{}', '{}', '{}', {}_loaderfileArt{}).\n".format(e[0],e[1],e[2], malware_name, cnt)
		cnt += 1
		print(rule)
		f_w.write(rule)

# n = 1
# filename = 'fireeyetech_args'
# f = open(filename + '.txt', 'r')
# counter = 0
# line_count = -1
# es = []
# for line in f:
# 	if counter == 0:
# 		es.append([])
# 		line_count += 1
# 	w = line.replace("\n", "")
# 	if len(w) > 2:
# 		es[line_count].append(w)
# 		counter = (counter + 1)%n

# print(es, len(es))
# f_w = open("tmp/" + filename + "prolog_rule.pl", 'w')
# for e in es:
# 	if len(e) == n:
# 		rule = "processArguments('{}',{}).\n".format(e[0], malware_name)
# 		print(rule)
# 		f_w.write(rule)
