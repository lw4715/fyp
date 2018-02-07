% Implements Temporal Reasoning in Gorgias

:- multifile kb_tr__rule/3, kb_tr__initiation/3, kb_tr__termination/3.

% Generation rules

kb_tr__rule(pg(A,L,T2,T1), holds(L,T2), []) :- 
	lt(T1,T2),
	kb_tr__initiation(A,L,T1).

kb_tr__rule(ng(A,L,T2,T1), neg(holds(L,T2)), []) :- 
	lt(T1,T2),
	kb_tr__termination(A,L, T1).

% Persistence rules


kb_tr__rule(pp(L,T2,T1), holds(L,T2), [holds(L,T1)]) :- lt(T1,T2).
kb_tr__rule(np(L,T2,T1), neg(holds(L,T2)), [neg(holds(L, T1))]) :- lt(T1,T2).

% Priority relationships

kb_tr__rule(tr(pg(A1,T,T2),np(T,T1),L), prefer(pg(A1,L,T,T2), np(L,T,T1)), []) :- leq(T1,T2).
kb_tr__rule(tr(ng(A1,T,T2),pp(T,T1),L), prefer(ng(A1,L,T,T2), pp(L,T,T1)), []) :- leq(T1,T2).
kb_tr__rule(tr(pg(A1,T,T2),ng(A2,T,T1),L), prefer(pg(A1,L,T,T2), ng(A2,L,T,T1)),[]) :- lt(T1,T2).
kb_tr__rule(tr(ng(A1,T,T2),pg(A2,T,T1),L), prefer(ng(A1,L,T,T2), pg(A2,L,T,T1)),[]) :- lt(T1,T2).

%% kb_tr__rule(tr(pp(T,T2),np(T,T1),L), prefer(pp(L,T,T2), np(L,T,T1)), []) :- lt(T1,T2).
%% kb_tr__rule(tr(np(T,T2),pp(T,T1),L), prefer(np(L,T,T2), pp(L,T,T1)), []) :- lt(T1,T2).


%% Auxilliary predicates

% lt(?X, +Y)

lt(X,Y) :-
	self__timestamp_current(Timestamp),
	self__epsilon(Epsilon),
	Lower_Timestamp is Timestamp - Epsilon,
        Y > Lower_Timestamp,
        X is Y-1.

lt(X,Y) :-
	self__timestamp_current(Timestamp),
	self__epsilon(Epsilon),
	Lower_Timestamp is Timestamp - Epsilon,
        NewY is Y-1,
        NewY > Lower_Timestamp,
        lt(X, NewY).

leq(X,X).
leq(X,Y) :- lt(X,Y).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

kb_tr__rule(holds(obs((CID,L)),T),holds(obs((CID,L)),T),[]) :-
	!,
	kb_0__observed(CID,(L,_),T).

kb_tr__rule(holds(obs(L),T),holds(obs(L),T), []) :- 
	kb_0__observed(L,T).


kb_tr__rule(neg(holds(obs(L),T)),neg(holds(obs(L),T)), []) :- 	kb_0__observed(neg(L),T).


%%kb_tr__rule(holds(obs(C,Op,T),T),holds(obs(C,Op,T),T), []) :- kb_0__observed(C,Op,T).
%%kb_tr__rule(holds(obs(L),T), holds(obs(L),T), [holds(obs(L,_),T)]).


kb_tr__rule(happens(L,T), happens(L,T), []) :- kb_0__executed(L,T).



kb_tr__rule(now(Literal), now(Literal), []) :-
	self__now(Literal).
