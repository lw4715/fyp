% ==================================================================== %
%                          GD EXAMPLE (Give or Keep Objects - ERES)    %
% ==================================================================== %
% A policy for deciding whether to Give or Keep objects as can arise   %
% for example within the context of a resource allocation problem.     %
% ==================================================================== %

:- compile('../../lib/gorgias').
:- compile('../../ext/lpwnf').

abducible(at(requested(_,_),_), []).
abducible(at(have(_),_), []).
abducible(urgent(_), []).
abducible(neg(X), []) :- abducible(X, []).

istime(T) :- member(T, [0,1,2,3,4,5,6,7,8,9]).

rule(r1(Res,Ag,T1,T2), happens(give(Res,Ag),T2), [at(have(Res),T2), at(requested(Res,Ag),T1)]) :- istime(T1), istime(T2), T1<T2.
rule(r2(Res,Ag,T), neg(happens(give(Res,Ag),T)), [at(have(Res),T), at(need(Res),T)]) :- istime(T).


rule(p1(Res,ResAux,Ag,T1,T2), prefer(r1(Res,Ag,T1,T2),r2(Res,Ag,T2)), [higher_rank(Ag), at(alternative(Res, ResAux),T2)]).
rule(p2(Res,Ag,T1,T2), prefer(r2(Res,Ag,T2), r1(Res,Ag,T1,T2)), [competitor(Ag)]).


rule(c1(Res), prefer(p2(Res,Ag,_,T2),p1(Res,_,Ag,_,T2)), [urgent_need(Res)]).


rule(a1(Res,ResAux,T), at(alternative(Res,ResAux),T), [at(have(ResAux),T), same_type(ResAux,Res)]).
rule(a2(Res,Goal), urgent_need(Res), [requirement(Res,Goal), urgent(Goal)]).



rule(f00, same_type(truck0, car0), []).
rule(f0, same_type(car0, truck0), []).
rule(f1, at(need(car0),T), []) :- istime(T), T>1, T<5.
rule(f2, requirement(car0, goal1), []).
rule(f4, higher_rank(asdf), []).
rule(f5, competitor(asdf), []).
rule(f6, competitor(qwerty), []).
%% rule(f7, urgent(goal1), []).

%complement(at(F1,T),at(F2,T)) :- F1 \= F2.


%%% Queries:
% prove([happens(give(car0,qwerty),2)],D).
% prove([happens(give(car0,qwerty),1)],D).
% prove([happens(give(car0,asdf),2)],D).
% prove([urgent(goal1),happens(give(car0,asdf),2)],D).
% prove([happens(give(car0,asdf),1)],D).
