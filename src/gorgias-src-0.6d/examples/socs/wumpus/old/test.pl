
:- compile('../../../lib/gorgias2').
:- compile('../../../ext/lpwnf2').
:- compile('wumpus.eres').


rule(happens(walk(south),0),happens(walk(south),0),[]).
rule(happens(walk(south),1),happens(walk(south),1),[]).
rule(happens(walk(south),2),happens(walk(south),2),[]).

rule(holds(percept(bump(south)),3), holds(percept(bump(south)),3),[]).
rule(holds(percept(bump(south)),4), holds(percept(bump(south)),4),[]).

test1(D) :- resolve([holds(at(self,xy(4,0)),4)],D).
test2(D) :- prove([holds(at(self,xy(4,0)),4)],D).
