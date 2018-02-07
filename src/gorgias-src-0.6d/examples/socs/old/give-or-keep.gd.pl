% ==================================================================== %
%                          GD EXAMPLE (Give or Keep Objects)           %
% ==================================================================== %
% A policy for deciding whether to Give or Keep objects as can arise   %
% for example within the context of a resource allocation problem.     %
% ==================================================================== %

:- compile('../../lib/gorgias').
:- compile('../../ext/lpwnf').


abducible(requested(_,_), []).
abducible(have(_)       , []).
%% abducible(need(_)       , []).
%% abducible(higher_rank(_), []).
%% abducible(competitor(_), []).
%% abducible(urgent_need(_), []).
abducible(neg(X), []) :- abducible(X, []).


rule(r1(Res,Ag), give(Res,Ag), [requested(Res,Ag), have(Res)]).
rule(r2(Res,Ag)   , neg(give(Res,Ag))   , [need(Res), have(Res)]).


rule(p1(Res,ResAux,Ag), prefer(r1(Res,Ag),r2(Res,Ag)), [higher_rank(Ag), alternative(Res, ResAux)]).
rule(p2(Res,Ag), prefer(r2(Res,Ag), r1(Res,Ag)), [competitor(Ag)]).


rule(c1(Res), prefer(p2(Res,Ag),p1(Res,_,Ag)), [urgent_need(Res)]).


rule(a1(Res,ResAux), alternative(Res,ResAux), [have(ResAux), same_type(ResAux,Res)]).
rule(a2(Res,Goal), urgent_need(Res), [need(Res,Goal), urgent(Goal)]).



rule(f00, same_type(truck0, car0), []).
rule(f0, same_type(car0, truck0), []).
rule(f1, need(car0), []).
rule(f2, need(car0, goal1), []).
rule(f4, higher_rank(asdf), []).
rule(f5, competitor(qwerty), []).


%% Comment next line and uncomment the line after that.
rule(f3, urgent(goal1), []). 
rule(f7, competitor(asdf), []).



