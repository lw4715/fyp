:- multifile rule/3.
rule(op_wannacryattack0, hasCapability(_875,wannacryattack),[]).
rule(op_wannacryattack1, neg(hasMotive(_875,wannacryattack)),[]).
rule(op_wannacryattack2, governmentLinked(superhard,china),[]).
rule(op_wannacryattack2, governmentLinked(dota,china),[]).
