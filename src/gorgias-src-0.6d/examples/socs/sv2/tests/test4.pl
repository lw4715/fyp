%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Author: Neophytos Demetriou (nkd@ucy.ac.cy)
%%
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

:- compile('../sv').

:- multifile kb_0__evidence/1.
:- multifile self__iff/2.

:- multifile kb_gd__todo/1.
:- multifile kb_gd__rule/3.

:- multifile kb_re__action/2.
:- multifile kb_re__goal/2.
:- multifile kb_re__rule/3.

:- multifile  self__history/2.

:- multifile test__heading/1.
:- multifile test__comment/1.
:- multifile test__comment/2.


test__heading('TEST 0 -- Reactivity using Preference Reasoning I').

test__comment('').


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
        kb_gd__istodo(Item),
	self__isnull(NULL),
	\+ self__goal(Item,NULL,[]).



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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


self__iff([((lsv,7),[],[])],[action((call_taxi,3),(lsv,7),[],[]),action((send_fax,3), (lsv,7),[],[]),action((request_porter,5),(lsv,7),[obs(taxi_is_here)],[]),action((make_payment,6),(lsv,7),[],[])]).


kb_0__evidence(((Action,AT),_,_)) :- self__now(obs(failed(Action,AT))).



:- self__urgency_wrt_time_epsilon_set(0).
:- self__commit(step('GI',[])).
:- self__commit(step('PI',((lsv,7),[],[]))).
:- self__commit(step('AE',((call_taxi,3),(lsv,7),[],[]))).
:- self__commit(step('PO',[obs(failed(call_taxi,3))])).

:- start.
:- self__profile_reset([careful,punctual]).
:- test__current_profile.
