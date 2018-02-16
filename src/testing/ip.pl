:- compile('/homes/lw4715/Computing/FYP/gorgias-src-0.6d/lib/gorgias.pl').
:- compile('/homes/lw4715/Computing/FYP/gorgias-src-0.6d/ext/lpwnf.pl').

rule(r1(X), (isCulprit(X)), []).
rule(r2(X), neg(isCulprit(X)), [originFrom(IP, X)]). 
rule(r3(X), (isCulprit(X)), [originFrom(IP, X), ipIsSpoofed(IP)]).

rule(f1, originFrom(ip1, china), []).
rule(f2, originFrom(ip2, us), []).
rule(f3, ipIsSpoofed(ip1), []).

rule(p1(X), prefer(r3(X), r2(X)), []).
rule(p2(X), prefer(r2(X), r1(X)), []).
