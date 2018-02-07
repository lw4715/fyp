% This example implements the rules used by E-RES


% Generation rules

rule(pg(A,F,T2,T1), holds(F,T2), [initiation(A,F,T1)]) :- lt(T1,T2).
rule(ng(A,F,T2,T1), neg(holds(F,T2)), [termination(A,F, T1)]) :- lt(T1,T2).

% Persistence rules


rule(pp(F,T2,T1), holds(F,T2), [holds(F,T1)]) :- lt(T1,T2).
rule(np(F,T2,T1), neg(holds(F,T2)), [neg(holds(F, T1))]) :- lt(T1,T2).

% Priority relationships

rule(temporal(pg(A1,T,T2),np(T,T1),F), prefer(pg(A1,F,T,T2), np(F,T,T1)), []) :- leq(T1,T2).
rule(temporal(ng(A1,T,T2),pp(T,T1),F), prefer(ng(A1,F,T,T2), pp(F,T,T1)), []) :- leq(T1,T2).
rule(temporal(pg(A1,T,T2),ng(A2,T,T1),F), prefer(pg(A1,F,T,T2), ng(A2,F,T,T1)), []) :- lt(T1,T2).
rule(temporal(ng(A1,T,T2),pg(A2,T,T1),F), prefer(ng(A1,F,T,T2), pg(A2,F,T,T1)), []) :- lt(T1,T2).

%% rule(temporal(pp(T,T2),np(T,T1),F), prefer(pp(F,T,T2), np(F,T,T1)), []) :- lt(T1,T2).
%% rule(temporal(np(T,T2),pp(T,T1),F), prefer(np(F,T,T2), pp(F,T,T1)), []) :- lt(T1,T2).


%% Auxilliary predicates

% lt(?X, +Y)

lt(X,Y) :-
	Y > -1, 
	X is Y-1.

lt(X,Y) :-
	NewY is Y-1, 
	NewY > -1, 
	lt(X, NewY).

leq(X,X).
leq(X,Y) :- lt(X,Y).



% gt(?X, +Y)

gt(X,Y) :- X is Y+1,!.

gt(X,Y) :-
	current(t(T)),
	lookahead(Lookahead),
	Y < T + Lookahead, 
	X is Y+1.

gt(X,Y) :-
	current(t(T)),
	NewY is Y+1, 
	lookahead(Lookahead),
	NewY < T + Lookahead, 
	gt(X, NewY).

geq(X,X).
geq(X,Y) :- gt(X,Y).

%%% lookahead is at most 5
lookahead(5).


abducible(happens(_,_), []).
abducible(neg(happens(_,_)), []).

%%abducible(holds(percept(_),_), []).
%%abducible(neg(holds(percept(_),_)), []).
%%%%%%%%

complement(g_check(X), g_check(Y)) :-
	!,
	complement(X,Y).

complement(holds(F1,T),holds(F2,T)) :-
	incompatible(F1,F2).








rule(temporal(failed,termination,A,L,T), prefer(failed(A,neg(L),T),termination(A,L,T)), []).
rule(temporal(failed,initiation,A,L,T), prefer(failed(A,L,T),initiation(A,L,T)), []) :- L\=neg(_).

complement(termination(A,L,T),failed(A,neg(L),T)) :- !.
complement(initiation(A,L,T),failed(A,L,T)) :- L\=neg(_).

complement(failed(A,neg(L),T), termination(A,L,T)) :- !.
complement(failed(A,L,T), initiation(A,L,T)) :-  L\=neg(_).









%%%%%%%%
/* Problem with my_findall in the definitions below

rule(initiation(A,L,T), initiation(A,L,T), [happens(A,T)|Ps]) :-

	clause(initiates(A,L),Body),
	clause2list(Body, BodyList),

  	my_findall(Clause, member(aux(Clause),BodyList), AuxilliaryConds),
  	list2clause(AuxilliaryConds,AuxilliaryPredicates),
  	AuxilliaryPredicates,

	my_findall(F,(member(pre(C),BodyList),literal2fluent(C,F,T)),Preconds),
	my_findall(Cmd,member(cmd(Cmd),BodyList),Auxxs),
%	union(Preconds,[naf(failed(A,L,T))|Auxxs],Ps).
	union(Preconds,Auxxs,Ps).


rule(termination(A,L,T), termination(A,L,T), [happens(A,T)|Ps]) :-

	clause(terminates(A,L),Body),
	clause2list(Body, BodyList),

  	my_findall(Clause, member(aux(Clause),BodyList), AuxilliaryConds),
  	list2clause(AuxilliaryConds,AuxilliaryPredicates),
  	AuxilliaryPredicates,

	my_findall(F,(member(pre(C),BodyList),literal2fluent(C,F,T)),Preconds),
	my_findall(Cmd,member(cmd(Cmd),BodyList),Auxxs),
%	union(Preconds,[naf(failed(A,neg(L),T))|Auxxs],Ps).
	union(Preconds,Auxxs,Ps).


%%% A = Action, P = Predicate, T = Timepoint

rule(failed(A,P,T), failed(A,P,T), [g_check(happens(A,T)), NegativePostcondition | Ps]) :-

	((P = neg(L) -> clause(terminates(A,L),Body)) ; (P = L -> clause(initiates(A,L),Body))),
	clause2list(Body, BodyList),

	TNEXT is T + 1,

  	my_findall(Clause, member(aux(Clause),BodyList), AuxilliaryClausesList),
  	list2clause(AuxilliaryClausesList,AuxilliaryClausesMetaCall),
  	AuxilliaryClausesMetaCall,

	my_findall(Fluent,(member(pre(Precondition),BodyList),literal2fluent(Precondition,Fluent,T)),Preconditions),
	my_findall(Cmd,member(cmd(Cmd),BodyList),Cmds),
	union(Preconditions, Cmds, Ps),

	my_findall(NF,(member(post(Postcondition),BodyList),literal2fluent(Postcondition,PF,TNEXT),complement(PF,NF)), Postconditions),
	member(NegativePostcondition,Postconditions).

*/

/* %%% No concurrent actions */

rule(concurrency_failure(A1,A2,T), neg(happens(A1,T)), [g_check(happens(A2,T)), A1 \= A2]).


/* %%% Concurrency allowed -- Here we can add preference on actions

rule(failed(A1,L1,T), neg(happens(A1,T)), [happens(A2,T),initiation(A2,L2,T)]) :-
	incompatible(L1,L2).


%%% TRASH


rule(ramification(Fluent), Fluent, Ps) :-

	((Fluent = neg(holds(Literal,T)), P=neg(Literal)) ; (Fluent = holds(Literal,T), P=Literal)),

	clause(ramification(P), Body),
	clause2list(Body,BodyList),

  	my_findall(Clause, member(aux(Clause),BodyList), AuxilliaryClausesList),
  	list2clause(AuxilliaryClausesList,AuxilliaryClausesMetaCall),
  	AuxilliaryClausesMetaCall,

	my_findall(ConditionFluent, (member(condition(L),BodyList),literal2fluent(L,ConditionFluent,T)), Conditions),
	my_findall(Cmd,member(cmd(Cmd),BodyList),Cmds),
	union(Conditions, Cmds, Ps).




rule(neg(initiation(A,L,T)), neg(initiation(A,L,T)), [g_check(happens(A,T)), g_check(NegativePostcondition) | Ps]) :-

	clause(initiates(A,L),Body),
	clause2list(Body, BodyList),

	TNEXT is T + 1,

  	my_findall(Clause, member(aux(Clause),BodyList), AuxilliaryClausesList),
  	list2clause(AuxilliaryClausesList,AuxilliaryClausesMetaCall),
  	AuxilliaryClausesMetaCall,

	my_findall(Fluent,(member(pre(Precondition),BodyList),literal2fluent(Precondition,Fluent,T)),Preconditions),
	my_findall(Cmd,member(cmd(Cmd),BodyList),Cmds),

	my_findall(Cmd,member(cmd(Cmd),BodyList),Cmds),
	union(Preconditions, Cmds, Ps),

	my_findall(NF,(member(post(Postcondition),BodyList),literal2fluent(Postcondition,PF,TNEXT),complement(PF,NF)), Postconditions),
	member(NegativePostcondition,Postconditions).


rule(neg(termination(A,L,T)), neg(termination(A,L,T)), [g_check(happens(A,T)), g_check(NegativePostcondition) | Ps]) :-

	clause(terminates(A,L),Body),
	clause2list(Body, BodyList),

	TNEXT is T + 1,

  	my_findall(Clause, member(aux(Clause),BodyList), AuxilliaryClausesList),
  	list2clause(AuxilliaryClausesList,AuxilliaryClausesMetaCall),
  	AuxilliaryClausesMetaCall,

	my_findall(Fluent,(member(pre(Precondition),BodyList),literal2fluent(Precondition,Fluent,T)),Preconditions),
	my_findall(Cmd,member(cmd(Cmd),BodyList),Cmds),

	my_findall(Cmd,member(cmd(Cmd),BodyList),Cmds),
	union(Preconditions, Cmds, Ps),

	my_findall(NF,(member(post(Postcondition),BodyList),literal2fluent(Postcondition,PF,TNEXT),complement(PF,NF)), Postconditions),
	member(NegativePostcondition,Postconditions).


rule(temporal(failed,initiation,A,L,T), prefer(neg(initiation(A,L,T)),initiation(A,L,T)), []).
rule(temporal(failed,initiation,A,L,T), prefer(neg(termination(A,L,T)),termination(A,L,T)), []).

rule(failed(What), failed(What), [g_check(happens(A,T)), g_check(NF) | Ps]) :-

	(clause(initiates(A,L),Body), What=initiation(A,L,T);clause(terminates(A,L),Body), What=termination(A,L,T)),
	clause2list(Body, BodyList),

	T1 is T + 1,

  	my_findall(Clause, member(aux(Clause),BodyList), AuxilliaryConds),
  	list2clause(AuxilliaryConds,AuxilliaryPredicates),
  	AuxilliaryPredicates,

	my_findall(Pre_Fluent,(member(pre(Precondition),BodyList),literal2fluent(Precondition,Pre_Fluent,T)),Preconditions),
	my_findall(Cmd,member(cmd(Cmd),BodyList),Auxxs),
	union(Preconditions,Auxxs,Ps),

	my_findall(NPF,(member(post(Postcondition),BodyList),literal2fluent(Postcondition,PF,T1),complement(PF,NPF)), Postconds),

	member(NF,Postconds).

*/

