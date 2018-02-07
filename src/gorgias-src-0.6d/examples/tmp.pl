:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(r1, neg(p), []).
rule(r2, p, [q]).
rule(s1, q, []).
rule(s2, neg(q), []).

rule(pr1, prefer(r2,r1), []).
% rule(pr2, prefer(s1,s2), []).
