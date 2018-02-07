% ==================================================================== %
%                          Wumpus World                                %
% ==================================================================== %
% See README file.                                                     %
% ==================================================================== %

:- compile('../../../lib/gorgias').
:- compile('../../../ext/lpwnf').

:- multifile map/3.
:- dynamic current/1.


%% Goal Introduction (GI)
%% Plan Introduction (PI)
%% Reactivity (RE)
%% Sensing Introduction (SI)
%% Passive Observation Introduction (POI)
%% Active Observation Introduction (AOI)
%% Action Execution (AE)
%% Goal Revision (GR)
%% Plan Revision (PR)




%% GD

rule(gd(survive), goal(survive), []).
rule(gd(explore), goal(explore), []).
rule(gd(exit),    goal(exit), [at(have(gold),time(T),location(X,Y))]) :- current(time(T)),current(location(X,Y)).

rule(h_p(gd(explore),gd(G)), prefer(gd(explore),gd(G)), [G \= explore]).

rule(h_p(gd(survive),gd(G)), prefer(gd(survive),gd(G)), [G \= survive,at(danger,time(T),location(X,Y))]) :- 
	current(time(T)),
	current(location(X,Y)).

rule(h_p(gd(exit),gd(G)), prefer(gd(exit),gd(G)), [G \= exit]).

rule(h_p(h_p(gd(exit),gd(explore)),h_p(gd(explore),gd(exit))), prefer(h_p(gd(exit),gd(explore)),h_p(gd(explore),gd(exit))), [at(have(gold),time(T),location(X,Y))]) :-
	current(time(T)),
	current(location(X,Y)).

rule(aux1(at(danger,time(T),location(X,Y))),at(danger,time(T),location(X,Y)),[at(alive,time(T),location(X,Y)),at(stench,time(T),location(X,Y))]) :-
	current(time(T)),
	current(location(X,Y)).

rule(aux2(at(danger,time(T),location(X,Y))),at(danger,time(T),location(X,Y)),[at(breeze,time(T),location(X,Y))]) :-
	current(time(T)),
	current(location(X,Y)).

complement(goal(G1),goal(G2)) :-
	isgoal(G1),
	isgoal(G2),
	G1 \= G2.

%% MISC 

rule(kb(Fluent,location(X,Y)), at(Fluent,_,location(X,Y)), [member(Fluent,Fs)]) :- map(X,Y,Fs),  known(X,Y).



%% Basic Part of the cycle theory starting from a current action execution transition.

rule(r('AE',C,T), at(tr('AE',C),T), [at(ec('AE',C),T)]) :- istime(T), isaction(A), C=do(A).
rule(r('PI',C,T), at(tr('PI',C),T), [at(ec('PI',C),T)]) :- istime(T), isgoal(G), C=reduce(G).
rule(r('AO',C,T), at(tr('AO',C),T), [at(ec('AO',C),T)]) :- istime(T), isfluent(F), C=obs(F).
rule(r('PR',C,T), at(tr('PR',C),T), [at(ec('PR',C),T)]) :- istime(T), C=null.


%% Punctual or Timely Behavior

rule(pr1('AE',Z,C,T), prefer(r('AE',C,T),r(Z,_,T)), [self(behavior,punctual), C=do(A), at(urgent(A),T)]) :- 
	istransition(Z).

rule(pr2('PI',Z,C,T), prefer(r('PI',C,T),r(Z,_,T)), [self(behavior,punctual), C=reduce(G), at(urgent(G),T)]) :- 
	istransition(Z), 
	Z \= 'PI'.

rule(pr3('AO',Z,C,T), prefer(r('AO',C,T),r(Z,_,T)), [self(behavior,punctual), C=obs(F), at(urgent(F),T)]) :- 
	istransition(Z), 
	Z \= 'AO'.

rule(pr4('PR',Z,C,T), prefer(r('PR',C,T),r(Z,_,T)), [self(behavior,punctual), C=null, at(nothing_urgent,T)]) :- 
	istransition(Z), 
	Z \= 'PR'.


%% Focused Behavior

rule(pr5('AE',Z,C,T), prefer(r('AE',C,T),r(Z,_,T)), [self(behavior,focused), at(todo(A),T), C=do(A)]) :-
	istransition(Z), 
	Z \= 'AE'.

rule(pr6('PI',Z,C,T), prefer(r('PI',C,T),r(Z,_,T)), [self(behavior,focused), at(mission(Goal),T), C=reduce(Goal)]) :- 
	istransition(Z), 
	Z \= 'PI'.



%% Careful Behavior

rule(pr7('PR',Z,C,T), prefer(r('PR',C,T),r(Z,_,T)), [self(behavior,careful), at(time_out,T)]) :- 
	istransition(Z), 
	Z \= 'PR'.


%% Cautious Behavior

rule(pr8('AE',A1,A2,T), prefer(r('AE',A1,T),r('AE',A2,T)), [self(behavior,cautious), needs(A,P),at(P,T)]) :-
	isaction(A1),
	isaction(A2).


rule(pr9('AO','AE',A1,T1), prefer(r('AO',A1,T1),r('AE',A2,T1)), [self(behavior,cautious), at(tr('AE',A2),T0)]) :-
	istime(T1),
	T0 is T1 - 1,
	isaction(A1),
	isaction(A2).


%% User-defined incompatibilities

complement(at(tr(Tr1,_),T),at(tr(Tr2,_),T)) :-
	istime(T),
	istransition(Tr1), 
	istransition(Tr2), 
	Tr1 \= Tr2.


% Extend this further.
complement(at(tr(TR,do(A1)),T),at(tr(TR,do(A2)),T)) :-
	istime(T),
	isaction(A1),
	isaction(A2),
	A1 \= A2.


%% Higher-order Priorities -- An example of mixed behavior (Punctual & Focused)

rule(hopr1('AE','PI',C), prefer(pr1('AE','PI',C,T),pr2('PI','AE',_,T)), [self(behavior,punctual),self(behavior,focused),at(in_danger,T),C=do(A)]) :- istime(T), sos_action(A).

rule(hopr2('AE','PI',C), prefer(pr1('AE','PI',C,T),pr6('PI','AE',_,T)), [self(behavior,punctual),self(behavior,focused),at(in_danger,T),C=do(A)]) :- istime(T), sos_action(A).

rule(hopr3('AE','AE',C), prefer(pr1('AE','AE',C,T),pr5('AE',_,_,T)), [self(behavior,punctual),self(behavior,focused),at(in_danger,T),C=do(A)]) :- istime(T),sos_action(A).






%%%%% Test data & auxiliary predicates %%%%%


istime(T) :- member(T, [0,1]).
istransition(Z) :- member(Z, ['AE','PI','AO','PR']).



%% Type information

isaction(A) :- member(A, [walk(east),walk(south),walk(west),walk(north),grab,shoot(east),shoot(south),shoot(west),shoot(north)]).
isgoal(G)   :- member(G, [explore,survive,gold,kill,exit]).
isfluent(F) :- member(F, [stench,breeze,glitter,bump,scream,smelly]).

sos_action(A) :- member(A, [avoid]).



%% Enabling conditions (for demo purposes only) -- we can extend this further, e.g. check that action preconditions are satisfied, etc.

rule(ec('AE',do(A),T), at(ec('AE',do(A)),T), []).
rule(ec('PI',C,T), at(ec('PI',C),T), []).
rule(ec('AO',C,T), at(ec('AO',C),T), []).
rule(ec('PR',C,T), at(ec('PR',C),T), []).


%% Simple definitions that apply for all test cases

rule(auxilliary(T), nothing_unusual, [
    neg(at(percept(stench),T)),
    neg(at(percept(breeze),T)),
    neg(at(percept(glitter),T)),
    neg(at(percept(bump),T))
]).

rule(needs(shoot,arrow), needs(shoot,have(arrow)), []).

pretty([]).
pretty([X|Xs]) :-
	writeln(''),
        writeln(X),
        pretty(Xs).


start :- play(0).

play(T0) :-
	retractall(current(time(_))),
	assert(current(time(T0))),
	passive_observation([Stench,Breeze,Glitter,Bump,Scream,Smelly]),
	T1 is T0 + 1,
	print_known_map,
	writeln('Press q to halt. Any other key to continue...'),
	get_single_char(Dummy),
	(Dummy = 113 -> halt ; continue_playing(T1)).

continue_playing(T) :-
	prove([goal(G)],D),
	member(gd(G), D),
	write('Goal Decision: '),
	writeln(G),
	play(T).


passive_observation([Stench,Breeze,Glitter,Bump,Scream,Smelly]) :-
	current(location(X,Y)),
	map(X,Y,Ps),
	in(s,Ps,Stench),
	in(b,Ps,Breeze),
	in(g,Ps,Glitter),
	in(w,Ps,Wumpus).

current(time(0)).
current(location(1,3)).

rule(test1, at(alive,time(0),_), []).
rule(test2, at(have(gold),time(0),_), []).

% b is breeze
% g is glitter
% p is pit
% s is stench
% w is wumpus
% TODO: map should only include information about wumpus and pits, the rest should be inferred by the environment agent
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


known(0,0).
known(X,Y).


in(P,Ps,1) :-
	member(P,Ps), !.
in(P,Ps,0).


print_known_map :-

	current(time(CT)),
	writeln(''),
	writeln('======================================================================'),
	write('Timepoint '), write(CT), writeln(':'),
	writeln('----------------------------------------------------------------------'),
	print_row(0),
	writeln(''),
	print_row(1),
	writeln(''),
	print_row(2),
	writeln(''),
	print_row(3),
	writeln(''),
	writeln('======================================================================').

print_row(X) :-
	print_cell(X,0),
	print_cell(X,1),
	print_cell(X,2),
	print_cell(X,3).

print_cell(X,Y) :-
	current(location(X,Y)),
	(known(X,Y) -> (map(X,Y,Ps),write(['*'|Ps])) ; write('U')).
print_cell(X,Y) :-
	write(' '),
	(known(X,Y) -> (map(X,Y,Ps),write(Ps)) ; write('U')).
	
	
