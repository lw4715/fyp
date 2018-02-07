


:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').


rule(r1, p, [q(Y)]).
rule(r2(X), q(X), [member(X, [1,2,3,4,5])]).
rule(r3, neg(q(2)), []).
rule(pr1, prefer(r3,r2(2)), []).
