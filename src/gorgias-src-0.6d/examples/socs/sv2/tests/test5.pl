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
:- multifile kb_0__evidence/1.

:- multifile  self__history/2.
:- multifile self__iff/2.
:- multifile test__heading/1.
:- multifile test__comment/1.
:- multifile test__comment/2.


test__heading('TEST 5').

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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


self__iff([((lsv,7),[],[])],[action((order_tickets,3),(lsv,7),[],[]),action((reserve_table,5),(lsv,7),[obs(no_train_delays)],[])]).

kb_0__evidence(((Goal,GT),_,_)) :- self__now(obs(failed(Goal,GT))).

:- self__commit(step('GI',[])).
:- self__commit(step('PI',((lsv,7),[],[]))).
:- self__commit(step('AE',((order_tickets,3),(lsv,7),[],[]))).
:- self__commit(step('PO',[obs(failed(order_tickets,3))])).


:- self__pretty_state.

:- self__profile_reset(obs_efficient).
:- test__current_profile.

:- self__profile_reset([cautious,obs_efficient]).
:- test__current_profile.
