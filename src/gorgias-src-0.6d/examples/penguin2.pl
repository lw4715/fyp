:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

abducible(flatfeet(_), []).
abducible(neg(flatfeet(_)), []).

rule(r1(X), fly(X), [bird(X)]).
rule(r2(X), neg(fly(X)), [penguin(X)]).
rule(r3(X), penguin(X), [walkslikepeng(X)]).
rule(r4(X), neg(penguin(X)), [neg(flatfeet(X))]).
rule(r5(X), bird(X), [penguin(X)]).
rule(r6, bird(t), []).
rule(r7, walkslikepeng(t), []).
%rule(r8, neg(flatfeet(t)), []).

rule(pr1, prefer(r2(X), r1(X)), []).
rule(pr2, prefer(r4(X), r3(X)), []).
