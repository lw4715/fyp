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

test__heading('TEST 3 -- Goal Decision').
test__comment('Urgency wrt Time').

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
        Label = prefer(more_urgent_wrt_time,gd(Gd_1),gd(Gd_2)),
        Pref = prefer(gd(Gd_1),gd(Gd_2)),
        kb_gd__istodo(Gd_1),
        kb_gd__istodo(Gd_2),
        Gd_1 \= Gd_2,
        kb_gd__more_urgent_wrt_time(Gd_1,Gd_2).


kb_gd__more_urgent_wrt_time((_,T1),(_,T2)) :-
        number(T1),
        number(T2),
        T1 < T2.

kb_gd__more_urgent_wrt_time((_,T1),(_,T2)) :-
        number(T1),
        T2 = anytime.



:- start.
:- self__commit(step('GI',[])).
:- start.
:- self__commit(step('PO',[obs(low_battery)])).
:- start.
:- self__commit(step('GI',[])).
:- start.



%%% REMINDER TO MYSELF (Neophytos): ALWAYS ADD THE LABEL AND HEAD OF A RULE BEFORE ANY OTHER CONDITIONS.
