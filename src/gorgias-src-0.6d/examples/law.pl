% ================================================================== %
%				LAW EXAMPLE			     %	
% ================================================================== %
% This example is taken from the paper 'Rules about rules: assessing %
% conflicting arguments in legal reasoning' by Henry Prakken and     %
% Giovanni Sartor. 						     %	 
% ================================================================== % 

:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').


rule(r11(E),   proves_guilty(E),            []).
rule(r12(E),   neg(proves_guilty(E)),       [neg(admissible_evidence(E))]).
rule(r2,       forged_evidence(f,e),        []).
rule(r3(X,E),  neg(admissible_evidence(E)), [forged_evidence(X,E)]).
rule(r41(X,E), neg(forged_evidence(X,E)),   [police_officer(X)]).
rule(r42(X,E), forged_evidence(X,E),        [dishonest(X)]).
rule(r5,       police_LA(f),                []).
rule(r6(X),    police_officer(X),           [police_LA(X)]).
rule(r7(X),    dishonest(X),                [police_LA(X)]).
rule(r8,       neg(dishonest(f)),           []).


rule(pr1,      prefer(r12(_),r11(_)),       []).
rule(pr2,      prefer(r42(_,_), r41(_,_)),  []).
rule(pr3,      prefer(r41(_,_), r2),        []).
rule(pr4,      prefer(r42(_,_), r2),        []).
rule(pr5,      prefer(r8, r7(_)),           []).
