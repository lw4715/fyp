%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Author: Neophytos Demetriou (nkd@cs.ucy.ac.cy)
%%
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

:- compile('../sv').

:- multifile abducible/2, rule/3, complement/2, kb_gd__todo/1, kb_gd__rule/3.


title('TEST 4').
comment('').


computee :: {

     super(computee_basic) &

     attributes([timepoint(2)]) &

     history(0,step('INIT',[])) &

     history(1,step('PO', [observed(c1, request(c0, share_taxi), 1)]))

}.


%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

kb_gd__todo(leaving_san_vincenzo).
kb_gd__todo(low_battery_alert) :- 
	self__now(low_battery).

kb_gd__todo_category(hey,asdf).
kb_gd__todo_category(heyhey,qwerty).

kb_gd__rule(gd(hey),gd(hey),[]).
kb_gd__rule(gd(heyhey),gd(heyhey),[]).
kb_gd__rule(prefer(gd(hey),gd(heyhey)), prefer(gd(hey),gd(heyhey)), []).
