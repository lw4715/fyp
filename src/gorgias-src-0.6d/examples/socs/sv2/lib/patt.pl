%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Author: Neophytos Demetriou (nkd@ucy.ac.cy)
%%
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

patt__isprofile(punctual).
patt__isprofile(careful).
patt__isprofile(focused).
patt__isprofile(impatient).
patt__isprofile(cautious).
patt__isprofile(obs_efficient).




%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% PATTERNS AND PROFILES OF OPERATIONAL BEHAVIOUR: Letting the preference rules
%% be conditional on the current state of the computee opens up the possibility
%% to produce a variety of patterns of operation. The overall operational 
%% behaviour of the computee as given by generic cycle theories is thus
%% dynamic, depending on the particular circumstances under which the 
%% transitions are executed.
%% 
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


%% PUNCTUAL -- This is a pattern where a computee attempts to satisfy its goals
%% on time. It plans and executes its actions in order to achieve a timely
%% completion of its goals. Hence transitions for the completion of actions and
%% goals that are becoming relatively urgent are given preference over ones for
%% other goals and actions and over other operations of the computee.


patt__rule(prefer(punctual,step('AE',As),step(Z,X)), prefer(step('AE',As),step(Z,X)), []) :-
	self__profile(punctual),
	fun__action_urgent_wrt_time(As).

patt__rule(prefer(punctual,step('PI',Gs),step(Z,X)), prefer(step('PI',Gs),step(Z,X)), []) :-
	self__profile(punctual),
	fun__goal_urgent_wrt_time(Gs).

/*

patt__rule(prefer(punctual,step('AO',Fs),step(Z,X)), prefer(step('AO',Fs),step(Z,X)), []) :-
	self__profile(punctual),
	fun__fluent_urgent_wrt_time(Fs).

patt__rule(prefer(punctual,step('PR',[]),step(Z,X)), prefer(step('PR',[]),step(Z,X)), []) :-
	self__profile(punctual),
	nothing_urgent_or_to_be_sensed.
*/

%% CAREFUL -- This is a pattern where when some failure occurs, e.g. some
%% action execution has timed out, then the computee prefers to reexamine its
%% current goals and plans before continuing with their further reduction and
%% execution. Hence the computee prefers to do revision transitions over the 
%% the other transitions in order to first let the effect of the failure
%% propagate in its current state.

patt__rule(prefer(careful,step('PR',[]),step(Z,X)), prefer(step('PR',[]),step(Z,X)), []) :-
	self__profile(careful),
	fun__action_timeout,
	Z \= 'PR'.



%% FOCUSED -- This is a pattern where once a computee has chosen a plan to 
%% execute prefers to continue with this plan (refining and/or executing
%% further) until the plan is finished or it has become invalid at which point
%% the computee can consider other plans or other goals, etc. Hence transitions
%% that relate to an existing plan have preference over transitions that relate
%% to other plans, e.g. transitions that introduce other plans.

patt__rule(prefer(focused,step('AE',As),step(Z,X)), prefer(step('AE',As),step(Z,X)), []) :-
	self__profile(focused),
	self__last_transition_eq('AE',Previous_As),
	fun__action_selection(As),
	fun__action_sp(Previous_As,As),
	Z \= 'AE'.


%% IMPATIENT -- This is a pattern where whenever a computee finds out that an
%% existing action or plan is invalidated by the environment prefers to abandon
%% it. Hence it prefers to execute other plans for other goals or for the same
%% goal.

patt__rule(prefer(impatient,step(Z,X),step('AE',As)), prefer(step(Z,X),step('AE',As)), []) :-
	self__profile(impatient),
	ct__istransition(Z), 
	Z \= 'AE',	
	ct__ec(Z,X),
	fun__action_failed(Prev_As),
	fun__action_sp(Prev_As,As).



%% CAUTIOUS -- This is a pattern where the computee prefers not to attempt to
%% execute an action when it does not know that this can be done, i.e. it does
%% not know that its preconditions hold. It prefers to execute actions for
%% which it knows that the preconditions hold. Hence it would also prefer to do
%% a sensing introduction transition over an action execution transition.
%% Similarly, in a cautious pattern the computee would prefer to check that the
%% desired effects (in a plan) of an action hold after its execution.

patt__rule(prefer(cautious,step('SI',Fs),step('AE',As)), prefer(step('SI',Fs),step('AE',As)), []) :-
	self__profile(cautious),
	fun__action_pre_get(As,Fs),
	Fs \= [].

patt__rule(prefer(cautious,step('AE',As),step(Z,X)), prefer(step('AE',As),step(Z,X)), []) :-
	self__profile(cautious),
	ct__istransition(Z),
	fun__action_pre(As).



%% OBS_EFFICIENT -- Our criterion of optimality here is to minimize the number of observations. Therefore, 'SI' and 'AO' transitions are ranked lower than other transitions.


patt__rule(prefer(obs_efficient,step('AE',X),step('SI',Fs)), prefer(step('AE',X),step('SI',Fs)), []) :-
	self__profile(obs_efficient),
	ct__ec('AE',X),
	Fs \= [].


%% Higher-Order Priorities for Cautious and Obs_Efficient Pattern of Behaviour
%% ... as long as there were no failed actions in the previous step

patt__rule(Pref, Pref, []) :-
	self__profile(cautious),
	self__profile(obs_efficient),
	Pref_1 = prefer(cautious,Step_1,Step_2),
	Pref_2 = prefer(obs_efficient,Step_2,Step_1),
	Pref = prefer(Pref_1,Pref_2),
	fun__action_failed(_).

patt__rule(Pref, Pref, []) :-
	self__profile(cautious),
	self__profile(obs_efficient),
	Pref_1 = prefer(cautious,Step_1,Step_2),
	Pref_2 = prefer(obs_efficient,Step_2,Step_1),
	Pref = prefer(Pref_2,Pref_1),
	\+ fun__action_failed(_).















%% Interrupt Component Preferences


patt__rule(prefer(interrupt,step('RE',[]),step(Z,X)), prefer(step('RE',[]),step(Z,X)), []) :-
	self__id(SID),
	self__friend(CID),
	self__now(obs((CID,request(SID,_)))).



%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Higher-Order Priorities
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% An interrupt dominates any profile preference after a PO transition

patt__rule(Pref, Pref, []) :-
	Pref_1 = prefer(interrupt,Step_1,Step_2),
	Pref_2 = prefer(Profile,Step_2,Step_1),
	Pref = prefer(Pref_1,Pref_2),
	self__last_transition('PO'),
	self__profile(Profile).

% careful dominates punctual

patt__rule(Pref, Pref, []) :-
	Pref_1 = prefer(careful,Step_1,Step_2),
	Pref_2 = prefer(punctual,Step_2,Step_1),
	Pref = prefer(Pref_1,Pref_2),
	self__profile(punctual),
	self__profile(careful).
	
