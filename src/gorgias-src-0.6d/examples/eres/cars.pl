:- compile('../../lib/gorgias').
:- compile('../../ext/lpwnf').
:- compile('eres').

% Cars

rule(d1(T), initiation(running,T), [happens(turnOn,T), holds(petrol,T)]).
rule(d2(T), termination(running,T), [happens(turnOff,T)]).
rule(d3(T), termination(petrol,T), [happens(empty,T)]).
rule(d4(T), neg(holds(running,T)), [neg(holds(petrol,T))]).


rule(d5, holds(running,1), []).
rule(d6, happens(turnOff,2), []).
rule(d7, happens(turnOn,5), []).
rule(d8, happens(empty,8), []).

% Queries:
% prove([holds(running,6)],D).
