
:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(r1, p,      []).
rule(r2, neg(p), []).
rule(r3, q,      [p]).

rule(pr, prefer(r1,r2), []).
