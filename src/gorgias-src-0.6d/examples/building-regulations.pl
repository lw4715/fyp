% ============================================================== %
%			     BUILDING REGULATIONS EXAMPLE	 %	
% ============================================================== %
% This example is taken from the paper 'Rules about rules: 	 %	
% assessing conflicting arguments in legal reasoning' by Henry   %
% Prakken and Giovanni Sartor. It is used to illustrate the use  %
% of dynamic priority rules. 					 %       
% ============================================================== %

:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(r1(X), neg(may_be_modified(X)),      [protected_building(X)]).
rule(r2(X), may_be_modified(X),           [needs_restructuring(X)]).

rule(pr1(X,Y), prefer(X,Y),               [artistic_protection_rule(X), town_planning_rule(Y)]).
rule(pr2(X,Y), prefer(X,Y),               [earlier(Y,X)]).

rule(f1, artistic_protection_rule(r1(_)), []).
rule(f2, town_planning_rule(r2(_)),       []).
rule(f3, earlier(r1(_), r2(_)),           []).
rule(f4, protected_building(villa0),      []).
rule(f5, needs_restructuring(villa0),     []).
rule(f6, earlier(pr2(_,_), pr1(_,_)),       []). 


% Queries
% -------
% [NO]  may_be_modified(villa0)
% [YES] neg(may_be_modified(villa0))
