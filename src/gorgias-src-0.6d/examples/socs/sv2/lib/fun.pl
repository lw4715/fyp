%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Author: Neophytos Demetriou (nkd@ucy.ac.cy)
%%
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

fun__goal_selection(((Goal,GT),Parent_Goal,TC)) :-
	self__goal((Goal,GT),Parent_Goal,TC),
	self__goal_has_nochild((Goal,GT)),
	self__temporal_constraints_validate(GT,TC),
	self__goal_ancestors_eq(Parent_Goal,Ancestors),
	self__goal_check_ancestors_nopass(Ancestors).

fun__goal_urgent_wrt_time(((_,GT),_,_)) :-
	self__timestamp_current(Timestamp),
	self__urgency_wrt_time_epsilon(Epsilon),
	GT =< Timestamp + Epsilon.



fun__action_selection(((Op,AT),Goal,Preconditions,TC)) :-
	self__action((Op,AT),Goal,Preconditions,TC),
	self__temporal_constraints_validate(AT,TC),
	\+ kb_0__executed(((Op,AT),Goal,Preconditions,TC)),
	self__goal_ancestors_eq(Goal,Ancestors),
	self__goal_check_ancestors_nopass(Ancestors).
	


fun__action_urgent_wrt_time(((_,AT),_,_,_)):-
	self__timestamp_current(Timestamp),
	self__urgency_wrt_time_epsilon(Epsilon),
	AT =< Timestamp + Epsilon.


fun__action_timeout :-
	self__timestamp_current(Timestamp),
	self__action((Op,AT),Goal,Preconditions,TC),
	\+ kb_0__executed(((Op,AT),Goal,Preconditions,TC)),
	AT < Timestamp.


fun__action_sp(Prev_As,As) :-
	Prev_As = ((_,_),Goal_1,_,_),
	As = ((Op_2,AT_2),Goal_2,Preconditions_2,TC_2),
	self__action((Op_2,AT_2),Goal_2,Preconditions_2, TC_2),
	self__toplevel_goal_is(Goal_1,Toplevel),
	self__toplevel_goal_is(Goal_2,Toplevel).
	

fun__action_failed(As) :-
	kb_0__evidence(As).


fun__action_pre_get(((_,_),_,Ps,_),Ps).


fun__action_pre_get(PPs) :-
	self__action((Op,AT),Goal,Ps,TC),
	fun__action_pre_get(((Op,AT),Goal,Ps,TC),PPs).
	


fun__action_pre(((_,_),_,Ps,_)) :-
	forall(member(P,Ps),self__now(P)).
