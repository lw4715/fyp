import sys

def convertRulesFile(filename="tmp", prefix="", c=0):
    f = open("tmp/" + filename + ".pl", 'r')
    r = ""
    count = c
    for line in f:
        r += convertRules(line, prefix, count) + "\n"
        count += 1
    f_w = open("tmp/" + filename + "gorgias.pl", 'w')
    f_w.write(r)

def convertPrefFile(filename="tmp1"):
    f = open("tmp/" + filename + ".pl", 'r')
    r = ""
    counter = 0
    for line in f:
        r += convertPref(line, counter) + "\n"
        counter += 1
    f_w = open("tmp/" + filename + "gorgias_pref.pl", 'w')
    f_w.write(r)

def convertRules(prolog_r, prefix, count):
    if prolog_r[0] == "%" or prolog_r[0] == "\n":
        return ""
    prolog_r = clean(prolog_r)
    # print(prolog_r)
    rule = prolog_r.split(":-")
    # print(rule)
    head = rule[0]
    if len(rule) > 1:
        body = rule[1]
    else:
        body = ""
    return "rule({}{}, {}, [{}]).".format(prefix, count, head, body)


def convertPref(pseudo_r, count):
    return "rule(p" + str(count) + ", " + clean(pseudo_r) + ", [])."

def clean(prolog):
    return prolog.replace(" ", "").replace(".", "").replace("\n", "").split("%")[0]

def convertPredicateToOutputRule(predicates):
    list_deltas = ""
    for i in range(len(predicates)):
        list_deltas += ", D" + str(i)
    goal = "goal(A, M, X{}) :- ".format(list_deltas)
    rules = ""
    for cnt, p in enumerate(predicates):
        delta = "D" + str(cnt)
        delta_pred = addDelta(p, delta)
        rules += "{} :- prove([{}], {}).\n".format(delta_pred, p, delta)
        goal += "\n  ({}, writeToFile({}, {}); \+ {}, write(neg({}))), nl,".format(delta_pred, p, cnt, delta_pred, p)
    list_goal = list(goal)
    list_goal[-1] = '.'
    goal = ''.join(list_goal)
    # print(rules)
    # print(goal)
    rules += "\n" + goal
    # print(rules)
    return rules

def addDelta(pred, delta):
    return pred[:-1] + "," + delta + pred[-1]

def convertPredFile(filename="preds"):
    f = open("tmp/" + filename, 'r')
    preds = []
    for line in f:
        preds.append(line.replace("\n", ""))
    f_w = open("tmp/" + filename + "output_rule.pl", 'w')
    f_w.write(convertPredicateToOutputRule(preds))

def renumberRules(filename):
    f = open(filename + '.pl', 'r')
    
    counter = 0
    r = ""
    for line in f:
        if line.startswith("rule("):
            split = line.split("(")
            head = split[0]
            label = split[1].split(",")
            label[0] = "bg" + str(counter) + "()"
            split[1] = ",".join(label)
            counter += 1
            r += ("(".join(split))
        else:
            r += line

    f_w = open(filename + '_renumbered.pl', 'w')
    f_w.write(r)

if __name__ == "__main__":
    # convertPredicateToOutputRule(["requireHighResource(A)", "culpritIsFrom(X, A)", "forBlackMarketUse(M)"])
    # convertPrefFile()
    #rules = sys.argv[1]
    #pref = sys.argv[2]

    #if rules:
    # convertRulesFile()
    renumberRules('SicstusJava/backgroundgorgias')
    #if pref:
    #    convertPrefFile(pref)
    # convertRulesFile()
    # convertPrefFile()
