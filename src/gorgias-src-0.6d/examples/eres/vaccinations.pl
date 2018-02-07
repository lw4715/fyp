:- compile('../../lib/gorgias').
:- compile('../../ext/lpwnf').
:- compile('eres').

% Vaccinations example

rule(d1(T), initiation(protected,T), [happens(injectA,T), holds(typeO,T)]).
rule(d2(T), initiation(protected,T), [happens(injectB,T), neg(holds(typeO,T))]).

rule(d3, happens(injectA,2), []).
rule(d4, happens(injectB,3), []).
