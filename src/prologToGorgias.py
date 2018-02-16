import sys

def convertRulesFile(filename):
    f = open(filename + ".pl", 'r')
    r = ""
    for line in f:
        r += convertRules(line) + "\n"
    f_w = open("tmp/" + filename + "gorgias.pl", 'w')
    f_w.write(r)

def convertPrefFile(filename):
        f = open(filename + ".pl", 'r')
        r = ""
        counter = 0
        for line in f:
            r += convertPref(line, counter) + "\n"
            counter += 1
        f_w = open("tmp/" + filename + "gorgias_pref.pl", 'w')
        f_w.write(r)

def convertRules(prolog_r):
    if prolog_r[0] == "%" or prolog_r[0] == "\n":
        return ""
    prolog_r = clean(prolog_r)
    print prolog_r
    rule = prolog_r.split(":-")
    print(rule)
    head = rule[0]
    if len(rule) > 1:
        body = rule[1]
    else:
        body = ""
    return "rule(, " + head + ", [" + body + "])."

def convertPref(pseudo_r, count):
    return "rule(p" + str(count) + ", " + clean(pseudo_r) + ", [])."

def clean(prolog):
    return prolog.replace(" ", "").replace(".", "").replace("\n", "").split("%")[0]

if __name__ == "__main__":
    rules = sys.argv[1]
    pref = sys.argv[2]

    if rules:
        convertRulesFile(rules)
    if pref:
        convertPrefFile(pref)
