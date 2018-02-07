% This example implements the rules used by E-RES


% Generation rules

rule(pg(F,T2,T1), holds(F,T2), [T1<T2, initiation(F,T1)]) :- time(T1).
rule(ng(F,T2,T1), neg(holds(F,T2)), [T1<T2, termination(F, T1)]) :- time(T1).

% Persistence rules

rule(pp(F,T2,T1), holds(F,T2), [T1<T2, holds(F,T1)]) :- time(T1).
rule(np(F,T2,T1), neg(holds(F,T2)), [T1<T2, neg(holds(F, T1))]) :- time(T1).

% Priority relationships

rule(pr1, prefer(pg(F,T,T2), np(F,T,T1)), [T1=<T2]) :- time(T1).
rule(pr2, prefer(ng(F,T,T2), pp(F,T,T1)), [T1=<T2]) :- time(T1).
rule(pr3, prefer(pg(F,T,T2), ng(F,T,T1)), [T1<T2]) :- time(T1).
rule(pr4, prefer(ng(F,T,T2), pg(F,T,T1)), [T1<T2]) :- time(T1).
%rule(pr5, prefer(pp(F,T,T2), np(F,T,T1)), [T1<T2]) :- time(T1).
%rule(pr5, prefer(np(F,T,T2), pp(F,T,T1)), [T1<T2]) :- time(T1).


% Auxiliary predicates

rule(lt1(X,Y), lt(X, Y), [Y > 0, X is Y-1]).
rule(lt2(X,Y), lt(X, Y), [NewY is Y-1, NewY > 0, lt(X, NewY)]).

abducible(holds(_,0), []).
abducible(neg(holds(_,0)), []).

%abducible(happens(_,_), []).
%abducible(happens(_,_), []).

time(T) :- member(T, [0,1,2,3,4,5,6,7,8,9]).
