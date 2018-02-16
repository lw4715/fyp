:- compile('/homes/lw4715/Computing/FYP/gorgias-src-0.6d/lib/gorgias.pl').
:- compile('/homes/lw4715/Computing/FYP/gorgias-src-0.6d/ext/lpwnf.pl').

rule(notGuiltyByDefault(X), (isCulprit(X)), []).
rule(ipGeolocation(X), neg(isCulprit(X)), [originFrom(IP, X)]). 
rule(spoofedIp(X), (isCulprit(X)), [originFrom(IP, X), ipIsSpoofed(IP)]).

rule(fact1, originFrom(ip1, china), []).
rule(fact2, originFrom(ip2, us), []).
rule(fact3, ipIsSpoofed(ip1), []).

rule(p1(X), prefer(spoofedIp(X), ipGeolocation(X)), []).
rule(p2(X), prefer(ipGeolocation(X), notGuiltyByDefault(X)), []).
