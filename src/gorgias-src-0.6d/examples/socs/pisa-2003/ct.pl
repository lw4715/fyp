% ==================================================================== %
%                          Cycle Theory                                %
% ==================================================================== %
% A cycle theory is viewed as a preference policy that will determine  %
% at each step the preferred next internal transition(s) to be         %
% executed. In effect, this policy ranks the various alternative       %
% transitions of the computee so that the most preferred can be chosen.%
% ==================================================================== %

:- compile('../../lib/gorgias').
:- compile('../../ext/lpwnf').


%% Basic Part of the cycle theory starting from a current action execution transition.

rule(r('AE','AE',C,T2), at(tr('AE',C),T2), [at(tr('AE',_),T1), at(ec('AE','AE',C),T2)]) :- istime(T2), T1 is T2 - 1,isaction(A), C=do(A).
rule(r('AE','PI',C,T2), at(tr('PI',C),T2), [at(tr('AE',_),T1), at(ec('AE','PI',C),T2)]) :- istime(T2), T1 is T2 - 1,isgoal(A), C=reduce(A).
rule(r('AE','AO',C,T2), at(tr('AO',C),T2), [at(tr('AE',_),T1), at(ec('AE','AO',C),T2)]) :- istime(T2), T1 is T2 - 1,isfluent(A), C=obs(A).
rule(r('AE','PR',C,T2), at(tr('PR',C),T2), [at(tr('AE',_),T1), at(ec('AE','PR',C),T2)]) :- istime(T2), T1 is T2 - 1,C=null.


%% Punctual or Timely Behavior

rule(pr1('AE','AE',Z,C,T2), prefer(r('AE','AE',C,T2),r('AE',Z,_,T2)), [self(behavior,punctual), C=do(A), at(urgent(A),T2)]) :- 
	istransition(Z).

rule(pr2('AE','PI',Z,C,T2), prefer(r('AE','PI',C,T2),r('AE',Z,_,T2)), [self(behavior,punctual), C=reduce(G), at(urgent(G),T2)]) :- 
	istransition(Z), 
	Z \= 'PI'.

rule(pr3('AE','AO',Z,C,T2), prefer(r('AE','AO',C,T2),r('AE',Z,_,T2)), [self(behavior,punctual), C=obs(F), at(urgent(F),T2)]) :- 
	istransition(Z), 
	Z \= 'AO'.

rule(pr4('AE','PR',Z,C,T2), prefer(r('AE','PR',C,T2),r('AE',Z,_,T2)), [self(behavior,punctual), C=null, at(nothing_urgent,T2)]) :- 
	istransition(Z), 
	Z \= 'PR'.


%% Focused Behavior

rule(pr5('AE','AE',Z,C,T2), prefer(r('AE','AE',C,T2),r('AE',Z,_,T2)), [self(behavior,focused), at(todo(A),T2), C=do(A)]) :-
	istransition(Z), 
	Z \= 'AE'.

rule(pr6('AE','PI',Z,C,T2), prefer(r('AE','PI',C,T2),r('AE',Z,_,T2)), [self(behavior,focused), at(mission(Goal),T2), C=reduce(Goal)]) :- 
	istransition(Z), 
	Z \= 'PI'.



%% Careful Behavior

rule(pr7('AE','PR',Z,C,T2), prefer(r('AE','PR',C,T2),r('AE',Z,_,T2)), [self(behavior,careful), at(time_out,T2)]) :- 
	istransition(Z), 
	Z \= 'PR'.





complement(at(tr(Tr1,_),T),at(tr(Tr2,_),T)) :-
	T = 1,
	istransition(Tr1), 
	istransition(Tr2), 
	Tr1 \= Tr2.


complement(at(tr('AE',do(A1)),T),at(tr('AE',do(A2)),T)) :-
	T = 1, 
	isaction(A1),
	isaction(A2),
	A1 \= A2.


%% Higher-order Priorities -- An example of mixed behavior (Punctual & Focused)

rule(hopr1('AE','AE','PI',C), prefer(pr1('AE','AE','PI',C,T),pr2('AE','PI','AE',_,T)), [self(behavior,punctual),self(behavior,focused),at(in_danger,T),C=do(A)]) :- istime(T), sos_action(A).

rule(hopr2('AE','AE','PI',C), prefer(pr1('AE','AE','PI',C,T),pr6('AE','PI','AE',_,T)), [self(behavior,punctual),self(behavior,focused),at(in_danger,T),C=do(A)]) :- istime(T), sos_action(A).

rule(hopr3('AE','AE','AE',C), prefer(pr1('AE','AE','AE',C,T),pr5('AE','AE',_,_,T)), [self(behavior,punctual),self(behavior,focused),at(in_danger,T),C=do(A)]) :- istime(T),sos_action(A).






%%%%% Test data & auxiliary predicates %%%%%


istime(T) :- member(T, [0,1]).
istransition(Z) :- member(Z, ['AE','PI','AO','PR']).



%% Type information -- ''isgoal(G)'' could be checked as in the gardening example, i.e. using argumentation.

isaction(A) :- member(A, [relax,assist,work,study,play,avoid]).
isgoal(G)   :- member(G, [gardening,survival,graduate,holiday,community_service]).
isfluent(F) :- member(F, [sunny_weather,fluent1,fluent2]).
sos_action(A) :- member(A, [avoid]).



%% Enabling conditions (for demo purposes only) -- we can extend this further, e.g. check that action preconditions are satisfied, etc.

rule(ec('AE','AE',C,T2), at(ec('AE','AE',C),T2), []).
rule(ec('AE','PI',C,T2), at(ec('AE','PI',C),T2), []).
rule(ec('AE','AO',C,T2), at(ec('AE','AO',C),T2), []).
rule(ec('AE','PR',C,T2), at(ec('AE','PR',C),T2), []).


%% All test cases start from a current action execution transition

rule(f(0,1), at(tr('AE',[]),0), []).


%% Simple definitions that apply for all test cases


% An action is urgent if it is part of the agent's todo list and it's deadline is due soon.

rule(f(0,2, urgent1(A)), at(urgent(A),Tnow), [at(todo(A),Tnow),deadline(A,Tend), Tend - Tnow < 3]) :- isaction(A).

% or if the agent is in danger and the action provides protection.

rule(f(0,3, urgent2(A)), at(urgent(A),Tnow), [at(in_danger,Tnow)]) :- sos_action(A),isaction(A).

% A goal is urgent if it is part of the agent's mission and if it's critical.

rule(f(0,2, urgent(G)), at(urgent(G),Tnow), [at(mission(G),Tnow),at(critical(G),Tnow)]) :- isgoal(G).


% A fluent is urgent if it is currently unknown and required.

rule(f(0,2, urgent(F)), urgent(F), [at(unknown(F),Tnow),at(required(F),Tnow)]) :- isfluent(F).




pretty([]).
pretty([X|Xs]) :-
	writeln(''),
        writeln(X),
        pretty(Xs).
