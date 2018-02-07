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


test__heading('TEST 0 -- Reactivity using Preference Reasoning I').

test__comment('').


:- self__logging_set(on).

%%:- self__commit(step('PO', [obs(single_taxi_available),obs(out_of_cash),obs(c1,(request(c0,share_taxi_p),0),1)])).


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

kb_re__isop(response(CID,Question,Answer)) :-
	self__id(SID),
	self__friend(CID),
	self__now(obs((CID,request(SID,Question)))),
	self__isanswer(Answer).

kb_re__action(Op, []) :-
	kb_re__isop(Op).

kb_re__rule(Pref,Pref,[]) :-
	Ar_1 = response(CID,share_taxi_p,accept),
	Ar_2 = response(CID,share_taxi_p,reject),
	Pref = prefer(ar(Ar_1),ar(Ar_2)).

kb_re__rule(Pref,Pref,[now(obs(single_taxi_available))]) :-
	Ar_1 = response(CID,share_taxi_p,accept),
	Ar_2 = response(CID,share_taxi_p,reject),
	Pref = prefer(ar(Ar_2),ar(Ar_1)).


kb_re__rule(Pref,Pref,[now(obs(out_of_cash))]) :-
	Ar_1 = response(CID,share_taxi_p,accept),
	Ar_2 = response(CID,share_taxi_p,reject),
	Pref1 = prefer(ar(Ar_1),ar(Ar_2)),
	Pref2 = prefer(ar(Ar_2),ar(Ar_1)),
	Pref  = prefer(Pref1,Pref2).
    

kb_re__rule(Pref,Pref,[now(neg(obs(out_of_cash)))]) :-
	Ar_1 = response(CID,share_taxi_p,accept),
	Ar_2 = response(CID,share_taxi_p,reject),
	Pref1 = prefer(ar(Ar_1),ar(Ar_2)),
	Pref2 = prefer(ar(Ar_2),ar(Ar_1)),
	Pref  = prefer(Pref2,Pref1).

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


self__urgency_wrt_time_epsilon(7).
self__profile(punctual).
self__profile(cautious).
self__profile(obs_efficient).

self__iff([((lsv,7),[],[])],[action((call_taxi,3),(lsv,7),[],[]),action((send_fax,3), (lsv,7),[],[]),action((request_porter,4),(lsv,7),[obs(taxi_is_here)],[]),action((make_payment,5),(lsv,7),[],[])]).

inbox(5, [obs(low_battery)]).

:- nonstop.
