:- compile('/homes/lw4715/Computing/FYP/gorgias-src-0.6d/lib/gorgias.pl').
:- compile('/homes/lw4715/Computing/FYP/gorgias-src-0.6d/ext/lpwnf.pl').

rule(r1(X), isCulprit(X), [originFrom(IP, X)]).
rule(r2(X), neg(isCulprit(X)), [originFrom(IP, X), isSpoofed(IP)]).

rule(f1, originFrom(ip, senegal), []).
rule(f2, isSpoofed(ip), []).

rule(pr1(X), prefer(r2(X), r1(X)), []).
