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

test__comment(0, 'The computee accepts the offer to share a taxi. Eventhough there is a single taxi available, the computee knows (via its temporal reasoning capability) that Francisco does not have enough cash.').

test__comment(1, 'Now, note that the reaction to accept the offer has been added to the list of actions. Also note that the punctual profile selects the only action available since it is urgent and demotes the rest of the transitions.').

test__comment(2, 'Note that the executed action has been added to KB 0.').



:- self__logging_set(on).

:- self__commit(step('PO', [obs(single_taxi_available),obs(out_of_cash),obs(c1,(request(c0,share_taxi_p),0),1)])).


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






:- start.
:- self__commit(step('RE',[])).
:- start.
:- self__commit(step('AE',([((response(c1,share_taxi_p,accept),3),[],[],[])], []))).
:- start.
