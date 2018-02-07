
%% Basic part of the cycle theory.

rule(tr('GI' , G)    ,  tr('GI'  , G)    , [c_GD(G)]).
rule(tr('PI' , G)    ,  tr('PI'  , G)    , [c_GS(G)]).
rule(tr('AE' , A)    ,  tr('AE'  , A)    , [c_AS(A)]).
rule(tr('AOI', F)    ,  tr('AOI' , F)    , [c_FS(F)]).
rule(tr('PR' , null) ,  tr('PR'  , null) , []).


complement(tr(Tr1,_),tr(Tr2,_)) :-
	transition(Tr1,_),
	transition(Tr2,_),
	Tr1 \= Tr2.

rule(c_AS(A), c_AS(happens(A,T)), []) :- 
	todo(happens(A,T)),
	current(t(T)),
	\+ done(happens(A,T)).

rule(c_GS(G), c_GS(holds(G,T1)), []) :- 
	todo(add(p_goal(G))),
	current(t(T0)),
	gt(T1,T0),
	\+ has_plan(holds(G,T1),_).

rule(c_GS(G), c_GS(neg(holds(G,T1))), []) :- 
	todo(add(n_goal(G))),
	current(t(T0)),
	gt(T1,T0),
	\+ has_plan(holds(G,T1),_).

rule(c_FS(F), c_FS(obs(F,T)), []) :- 
	todo(holds(F,T)),
	\+ done(holds(F,T)),
	current(t(T)).





/*

%%% This is here to make things more interesting. Prefer to win when you have the gold.

rule(prefer(tr('PI',holds(win,T0)),tr(TR,_)),prefer(tr('PI',holds(win,T0)),tr(TR,_)),[holds(have(gold),T0)]) :-
	current(t(T0)),
	transition(TR,_).


*/
