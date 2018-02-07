% ==================================================================== %
%                          Wumpus World                                %
% ==================================================================== %
%                                                                      %
% Author: Neophytos Demetriou (k2pts@cytanet.com.cy)                   %
%                                                                      %
% See README file.                                                     %
%                                                                      %
% ==================================================================== %

:- compile('../../../lib/gorgias').
:- compile('../../../ext/lpwnf').
:- compile('wumpus.eres').

:- dynamic current/1.

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


%% Basic part of the cycle theory.

rule(r('AE' , do(A))     ,  tr('AE'  , do(A))     , [c_AS(A)]).
rule(r('PI' , reduce(G)) ,  tr('PI'  , reduce(G)) , [c_GS(G)]).
rule(r('AOI', obs(F))    ,  tr('AOI' , obs(F))    , [c_FS(F)]).
rule(r('PR' , null)      ,  tr('PR'  , null)      , []).


rule(c_AS(A), c_AS(A), [isaction(A)]).
rule(c_GS(G), c_GS(G), [isgoal(G)]).
rule(c_FS(F), c_FS(F), [isfluent(F)]).



%%% Goals -- A goal is a triple of the form (Fluent_Literal,Parent_Goal,Temporal_Constraint)



isgoal(holds(GF,T)) :-
	todo(holds(GF,T)).


isaction(happens(A,T)) :-
	todo(happens(A,T)).


%% Domain specific

%%rule(i1, initiation(have(gold),T), [holds(same_sq(self,gold),T), happens(grab(gold), T)]) :- time(T).
%%rule(i2, initiation(win,T), [happens(exit,T),holds(have(gold),T),same_sq(self,start)]) :- time(T).

%%rule(ram1, holds(same_sq(self,gold),T), [holds(percept(glitter),T)]) :- time(T).

% FIXME: temporary hack
%% rule(ram2, holds(same_sq(self,start),T), [holds(percept(start),T)]) :- time(T).




%% Problem specific

%%rule(f0, holds(alive(wumpus),at(t(0),xy(X,Y))), []).

isaction(A) :- goal(win,10).

%%% Type information and other auxiliary predicates
current(time(0)).
current(xy(2,2)).
known(0,0).
known(X,Y).


rule(percept(dummy),_,_).

start :- play(0).

play(T0) :-
        retractall(current(time(_))),
        assert(current(time(T0))),
	current(xy(X,Y)),
        map(X,Y,Percepts),
	retractall(rule(percept(_),_,_)),
        T1 is T0 + 1,
	tell(Percepts,T1),
        print_known_map,
        writeln('Press q to halt. Any other key to continue...'),
        get_single_char(Dummy),
        (Dummy = 113 -> halt ; continue_playing(T1)).

%continue_playing(T) :- play(T),!.
continue_playing(T) :-
        prove([tr(TR,C)],D),
        write('Transition: '),
	transition(TR,Description),
        writeln(Description),
	write('Configuration: '),
	writeln(C),
        play(T).

tell([],_).
tell([P|Ps],T) :-
	write('Telling...'),
	writeln(P),
	assert(rule(percept(P),holds(percept(P),T),[])),
	tell(Ps,T).

map(0,0,[start]).
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
        current(xy(X,Y)),
        (known(X,Y) -> (map(X,Y,Ps),write(['*'|Ps])) ; write('U')).
print_cell(X,Y) :-
        write(' '),
        (known(X,Y) -> (map(X,Y,Ps),write(Ps)) ; write('U')).




%%%%%%%%%%%%%%%%%%%%%%%%%% FIXME

%% rule(t1, termination(alive(wumpus),T), [observed(scream,T)]).
