% This example implements the rules used by E-RES


% Generation rules

rule(pg(F,T2,T1), holds(F,T2), [initiation(F,T1)]) :- istime(T1), T2 is T1 +1.
rule(ng(F,T2,T1), neg(holds(F,T2)), [termination(F, T1)]) :- istime(T1), T2 is T1 +1.

% Persistence rules

rule(pp(F,T2,T1), holds(F,T2), [holds(F,T1)]) :- istime(T1), lt(T1,T2).
rule(np(F,T2,T1), neg(holds(F,T2)), [neg(holds(F, T1))]) :- istime(T1), lt(T1,T2).


% Priority relationships

rule(temporal(pg,pp,F1,F2,T1,T2,T3,T4), prefer(pg(F1,T4,T2), pp(F2,T3,T1)), []) :- 
	incompatible(F2,F1),
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	leq(T1,T2).
rule(temporal(pg,np,F,F,T1,T2,T3,T4), prefer(pg(F,T4,T2), np(F,T3,T1)), []) :- 
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	leq(T1,T2).
rule(temporal(pg,pg,F1,F2,T1,T2,T3,T4), prefer(pg(F1,T4,T2), pg(F2,T3,T1)), []) :- 
	incompatible(F2,F1),
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	lt(T1,T2).
rule(temporal(pg,ng,F1,F2,T1,T2,T3,T4), prefer(pg(F1,T4,T2), ng(F2,T3,T1)), []) :-
	incompatible(F2,F1),
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	lt(T1,T2).



rule(temporal(ng,pp,F1,F2,T1,T2,T3,T4), prefer(ng(F1,T4,T2), pp(F2,T3,T1)), []) :- 
	incompatible(F2,F1),
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	leq(T1,T2).
rule(temporal(ng,np,F,F,T1,T2,T3,T4), prefer(ng(F,T4,T2), np(F,T3,T1)), []) :- 
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	leq(T1,T2).
rule(temporal(ng,pg,F1,F2,T1,T2,T3,T4), prefer(ng(F1,T4,T2), pg(F2,T3,T1)), []) :- 
	incompatible(F2,F1),
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	lt(T1,T2).
rule(temporal(ng,ng,F1,F2,T1,T2,T3,T4), prefer(ng(F1,T4,T2), ng(F2,T3,T1)), []) :-
	incompatible(F2,F1),
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	lt(T1,T2).


rule(temporal(pp,np,F,F,T1,T2,T3,T4), prefer(pp(F,T4,T2), np(F,T3,T1)), []) :- 
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	lt(T1,T2).
rule(temporal(np,pp,F,F,T1,T2,T3,T4), prefer(np(F,T4,T2), pp(F,T3,T1)), []) :- 
	istime(T1),
	istime(T2),
	istime(T3),
	istime(T4),
	lt(T1,T2).


% Higher-Order Priorities



% Auxiliary predicates
/*
leq(X,X).
leq(X,Y):- lt(X,Y).

lt(X, Y) :- 
	Y > 0, 
	X is Y-1.
lt(X,Y) :-
	NewY is Y-1, 
	NewY > 0, 
	lt(X, NewY).

*/

leq(X,Y) :- X=<Y.
lt(X,Y) :- X<Y.

abducible(holds(percept(_),T), []) :- istime(T).
abducible(neg(holds(percept(_),T)), []) :- istime(T).

abducible(happens(_,T2), []) :-
	current(t(T1)),T1=<T2.

%%abducible(failed(_,_), []).
%%abducible(neg(failed(_,_)), []).


istime(T2) :- member(T2, [0,1,2,3,4,5,6,7]).
