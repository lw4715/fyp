
:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(r1, p,      []).
rule(r2, neg(p), []).
rule(r3, q,      [p]).

rule(pr1, prefer(r1,r2), []).
rule(pr2, prefer(r2,r1), []).

rule(prpr1, prefer(pr1,pr2), []).
