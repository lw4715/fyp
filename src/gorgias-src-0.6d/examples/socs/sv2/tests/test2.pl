%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Author: Neophytos Demetriou (nkd@ucy.ac.cy)
%%
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

:- compile('../sv').

:- multifile kb_gd__todo/1.
:- multifile kb_gd__rule/3.

:- multifile kb_re__action/2.
:- multifile kb_re__goal/2.
:- multifile kb_re__rule/3.

:- multifile  self__history/2.

:- multifile test__heading/1.
:- multifile test__comment/1.
:- multifile test__comment/2.

test__heading('TEST 2 -- Goal Decision').
test__comment('Example 1:').
test__comment(0,'Goal Introduction -- Leaving San Vincenzo. Note that everything is executed.').
test__comment(1,'Just check that the goal has been added to the state. In the upcoming screens it is going to be suspended.').
test__comment(2,'Note the passive observations that were introduced. Now, we have a new Goal Introduction -- Low Battery Alert. Note in the prolog file for this example that the low battery alert was a conditional goal (only to be considered when the computee can observe a low battery signal.').
test__comment(3,'Note that the new goal has been introduced. Also note that the punctual computee selects this goal for the input of a PI transition').

:- self__logging_set(on).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

kb_gd__incompatible(X,Y) :-
	kb_gd__istodo(X),
	kb_gd__istodo(Y),
	X \= Y.

kb_re__incompatible_ar(X,Y) :-
	kb_re__isop(X),
	kb_re__isop(Y),
	X \= Y.

kb_re__incompatible_gr(X,Y) :-
	kb_re__isgoal(X),
	kb_re__isgoal(Y),
	X \= Y.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% lsv = leaving san vincenzo
% nfa = news feeds aggregation
% lba = low battery alert

kb_gd__istodo((lsv,7)).
kb_gd__istodo((nfa,4)).
kb_gd__istodo((lba,anytime)) :- self__now(obs(low_battery)).




kb_gd__rule(gd(Item), gd(Item), []) :-
	kb_gd__istodo(Item).



kb_gd__rule(Label,Pref,[]) :-
	Label = prefer(more_urgent_wrt_type,gd(Gd_1),gd(Gd_2)),
	Pref = prefer(gd(Gd_1),gd(Gd_2)),
	kb_gd__istodo(Gd_1),
	kb_gd__istodo(Gd_2),
	Gd_1 \= Gd_2,
	kb_gd__more_urgent_wrt_type(Gd_1,Gd_2).



kb_gd__more_urgent_wrt_type((Item_1,_),(Item_2,_)) :-
	kb_gd__typeof(Item_1, Type_1),
	kb_gd__typeof(Item_2, Type_2),
	kb_gd__more_urgent_type(Type_1, Type_2).


kb_gd__more_urgent_type(Type_1,Type_2) :-
	Ranking = [operational,required,optional],
	nth(Type_1_Rank, Ranking, Type_1),
	nth(Type_2_Rank, Ranking, Type_2),
	Type_1_Rank < Type_2_Rank.


kb_gd__typeof(lsv,required).
kb_gd__typeof(nfa,optional).
kb_gd__typeof(lba,operational).


:- start.
:- self__commit(step('GI',[])).
:- start.
:- self__commit(step('PO',[obs(low_battery)])).
:- start.
:- self__commit(step('GI',[])).
:- start.



%%% REMINDER TO MYSELF (Neophytos): ALWAYS ADD THE LABEL AND HEAD OF A RULE BEFORE ANY OTHER CONDITIONS.
