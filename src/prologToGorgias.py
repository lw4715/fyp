import sys

def convertRulesFile(filename):
    f = open(filename + ".pl", 'r')
    r = ""
    for line in f:
        r += convertRules(line) + "\n"
    f_w = open(filename + "gorgias.pl", 'w')
    f_w.write(r)

def convertPrefFile(filename):
        f = open(filename + ".pl", 'r')
        r = ""
        for line in f:
            r += convertPref(line) + "\n"
        f_w = open(filename + "gorgias_pref.pl", 'w')
        f_w.write(r)

def convertRules(prolog_r):
    if prolog_r[0] == "%" or prolog_r[0] == "\n":
        return ""
    prolog_r = prolog_r.replace(" ", "")
    prolog_r = prolog_r.replace(".", "")
    prolog_r = prolog_r.replace("\n", "")
    prolog_r = prolog_r.split("%")[0]
    print prolog_r
    rule = prolog_r.split(":-")
    print(rule)
    head = rule[0]
    body = rule[1]
    return "rule(, " + head + ", [" + body + "])."
def convertPref(pseudo_r):
    return "rule(p, " + pseudo_r + ", [])."

if __name__ == "__main__":
    rules = sys.argv[1]
    pref = sys.argv[2]

    if rules:
        convertRulesFile(rules)
    if pref:
        convertPrefFile(pref)
