% ==================================================================== %
%                          Wumpus World                                %
% ==================================================================== %
%                                                                      %
% Author: Neophytos Demetriou (k2pts@cytanet.com.cy)                   %
%                                                                      %
% See README file.                                                     %
%                                                                      %
% ==================================================================== %

:- compile('../../../lib/gorgias2').
:- compile('../../../ext/lpwnf2').
:- compile('wumpus.basic').
:- compile('wumpus.behaviour').
:- compile('wumpus.gd').
:- compile('wumpus.eres').

:- dynamic current/1,todo/1,known/2,has_plan/2,done/1,to_tell/1,my_state/2.
:- multifile self/2.
%%%%

current(t(0)).
current(xy(0,0)).
current(last(tr(dummy,null))).
rule(f0, neg(holds(have(gold),0)), []).
rule(f1, holds(alive(wumpus),0), []).

%rule(f2, holds(at(self, xy(X,Y)),T), []) :- current(t(T)),current(xy(X,Y)).
%rule(f2(T), holds(at(self, xy(X,Y)),T), []) :- current(t(T)), current(xy(X,Y)).

known(0,0).

%% State
todo(dummy).
self(profile,dummy).
%self(profile,punctual).
%self(profile,careful).
%self(profile,cautious).
%%%%%%%

start :- play(0).

play(T0) :-
	current(xy(X,Y)),
	writeln('+++'),
	tell_agent(xy(X,Y),T0),
	writeln('+++'),
	retractall(known(X,Y)),
	assert(known(X,Y)),
        once(print_known_map(T0)),
        writeln('Press q to halt. Any other key to continue...'),
        get_single_char(Dummy),
        (Dummy = 113 -> halt ; once(continue_playing(T0))).

%continue_playing(T) :- play(T),!.
continue_playing(T0) :-
        retractall(current(t(_))),
        assert(current(t(T0))),
        T1 is T0 + 1,
	%%	forall((member(P,Percepts),reaction(P,R),write('Reaction for '), write(P), write(' is... '), writeln(R)),R),
	prove([tr(TR,C)],D), 
	writeln(''),
        write('Transition: '),
	transition(TR,Description),
        writeln(Description),
	write('Configuration: '),
	writeln(C),
	update_state(TR,C,T1),
	writeln(''),
        (TR='AE' -> play(T1) ; play(T0)).

update_state('GI',G,_) :-
	!,
	assert(todo(add(G))).

update_state('PI',GoalFluent,T) :-
	pi_state_update(GoalFluent),
	write('Planning...'),
	write(GoalFluent),
	write(' ---> '),
	prove([GoalFluent],D), !,
	write('Plan: '), writeln(D),
	forall((member(ass(X),D), X\=neg(_), \+ todo(X)), assert(todo(X))),
	assert(has_plan(GoalFluent,D)),
	writeln('[ ok ]').

update_state('PI',GoalFluent,T) :-
	!,
	assert(has_plan(GoalFluent,nada)),
	writeln('[ failed ]').
	



%% FIXME	
update_state('PR',null,T) :-
	!,
	retractall(todo(_)),
	retractall(has_plan(_,_)).

update_state('SI',F,T).


update_state('AE',A,T) :-
	!,
	assert(rule(A,A,[])),
	do(A).

update_state('AOI',obs(percept(F),Taux),T) :-
	!,
	current(xy(X,Y)),
	map(X,Y,Percepts),
	(member(F,Percepts) -> assert(rule(p_obs(F,T), holds(F,T), [])) ; assert(rule(n_obs(F,T), neg(holds(F,T)), []))),
	assert(done(holds(percept(F),Taux))).

update_state(TR,C,T) :-
	writeln(TR),
	writeln(C),
	writeln(T).

tell_agent(xy(X,Y),T) :-
        map(X,Y,P1),
	tell_list(P1,T),
	my_findall(P,to_tell(P), P2),
	tell_list(P2,T),
	(P2 \= [] -> retractall(to_tell(_)) ; true).

tell_list([],_).
tell_list([P|Ps],T) :-
	write('Telling...'),
	writeln(P),
	current(xy(X,Y)),
	assert(rule(holds(percept(P),T),holds(percept(P),T),[])),
	tell_list(Ps,T).

isvalid(xy(X,Y)) :- X >= 0, X =< 3, Y >= 0, Y =< 3.

map(0,0,[]).
map(0,1,[]).
map(0,2,[]).
map(0,3,[]).
map(1,0,[]).
map(1,1,[breeze]).
map(1,2,[]).
map(1,3,[stench]).
map(2,0,[glitter,breeze]).
map(2,1,[pit]).
map(2,2,[breeze,stench]).
map(2,3,[wumpus,stench]).
map(3,0,[]).
map(3,1,[breeze]).
map(3,2,[pit]).
map(3,3,[breeze,stench]).


print_known_map(T) :-
        writeln(''),
        writeln('==============================================================================='),
        write('Timepoint '), write(T), writeln(':'),
	writeln('-------------------------------------------------------------------------------'),
        print_row(0),
        writeln(''),
        print_row(1),
        writeln(''),
        print_row(2),
        writeln(''),
        print_row(3),
        writeln(''),
	writeln('-------------------------------------------------------------------------------'),
	my_location(XY,T),
	write('Agent believes that s/he is at position '),
	writeln(XY),
	writeln(''),
	write('Agent believes that s/he '),
	(prove_with(['RES','NAF','BUILT_IN'],[holds(have(gold),T)],_) -> writeln('has the gold.') ; true),
	(prove_with(['RES','NAF','BUILT_IN'],[neg(holds(have(gold),T))],_) -> writeln('does not have the gold.') ; true),
	writeln(''),
	write('Agent believes that s/he '),
	(prove_with(['RES','NAF','BUILT_IN'],[holds(have(arrow),T)],_) -> writeln('has the arrow.') ; true),
	(prove_with(['RES','NAF','BUILT_IN'],[neg(holds(have(arrow),T))],_) -> writeln('does not have the arrow.') ; true),
	writeln(''),
	write('Agent believes that Wumpus is '),
	(prove_with(['RES','NAF','BUILT_IN'],[holds(alive(wumpus),T)],_) -> writeln('alive.') ; true),
	(prove_with(['RES','NAF','BUILT_IN'],[neg(holds(alive(wumpus),T))],_) -> writeln('dead.') ; true),
	writeln(''),
	findall(Task, todo(Task), TODO),
	write('TODO: '),
	writeln(TODO),
	writeln(''),
	findall(Task, done(Task), DONE),
	write('DONE: '),
	writeln(DONE),
        writeln('===============================================================================').

print_row(X) :-
        print_cell(X,0),
        print_cell(X,1),
        print_cell(X,2),
        print_cell(X,3).

print_cell(X,Y) :-
        current(xy(X,Y)),
        (known(X,Y) -> (map(X,Y,Ps),write(['*'|Ps])) ; write('U')).
print_cell(X,Y) :-
        write(' '),
        (known(X,Y) -> (map(X,Y,Ps),write(Ps)) ; write('U')).


%%%%

%% transition(Label, Description)

transition('GI', 'Goal Introduction').
transition('PI', 'Plan Introduction').
transition('RE', 'Reactivity').
transition('SI', 'Sensing Introduction').
transition('POI','Passive Observation Introduction').
transition('AOI','Active Observation Introduction').
transition('AE', 'Action Execution').
transition('GR', 'Goal Revision').
transition('PR', 'Plan Revision').


%%%
reaction(dummy,dummy).
/*
reaction(glitter, assert(happens(grab(gold),T))) :-
	current(t(T)).
*/

do(happens(walk(Direction),TimeOfAction)) :-
	current(xy(X,Y)),
	adj(xy(X,Y),NewXY,Direction), 
	isvalid(NewXY), 
	!,
	retractall(current(xy(X,Y))), 
	assert(current(NewXY)),
	do_2(happens(walk(Direction),TimeOfAction)).


do(happens(walk(Direction),TimeOfAction)) :-
	current(xy(X,Y)),
	adj(xy(X,Y),NewXY,Direction), 
	\+ isvalid(NewXY),
	!,
	assert(to_tell(bump(Direction))),
	do_2(happens(walk(Direction),TimeOfAction)).

do(A) :- do_2(A).

do_2(happens(A,T)) :-
	retractall(todo(happens(A,T))),
	forall(resolveone(initiation(A,F,T),_), retractall(todo(add(p_goal(F))))),
	forall(resolveone(termination(A,F,T),_), retractall(todo(add(n_goal(F))))),
	forall(resolveone(initiation(A,F,T),_), retractall(has_plan(holds(F,_)))),
	forall(resolveone(termination(A,F,T),_), retractall(has_plan(neg(holds(F,_))))),
%%	forall(, writeln(retractall(todo(add(p_goal(F)))))),
%%	forall(resolveone(termination(A,F,T),_), retractall(todo(add(n_goal(F))))),
	assert(done(happens(A,T))).

my_location(XY,T) :-
	my_state(location(XY),T),!.
my_location(XY,T) :-
	prove_with(['RES','NAF','BUILT_IN'],[holds(at(self,XY),T),ground(XY)],_),
	assert(my_state(location(XY),T)).


util_memoize(Call) :-
	my_state(cache(Call),all),!.
util_memoize(Call) :- 
	Call,
	assert(my_state(cache(Call),all)).

my_state(dummy,0).


pi_state_update(holds(F,T)) :-
	retractall(todo(add(p_goal(F)))).
pi_state_update(neg(holds(F,T))) :-
	retractall(todo(add(n_goal(F)))).



isaction(walk(Direction)) :-
	isdirection(Direction).

isaction(shoot(Direction)) :-
	isdirection(Direction).

isaction(grab(gold)).


isdirection(east).
isdirection(south).
isdirection(north).
isdirection(west).
