%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Transitions v.0.1
%%% 01/08/2003	SOCS Project
%%% Based on deliverable D4 (pp. 46--53)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Transitions			ComputeeState * Input -> ComputeeState
%%% predicate used: 		transition(Transition,Input)

:- use_module(library(lists)). 
:- use_module(library(objects)).

:- multifile goal/4,action/4.
:- dynamic executed/2,observed/2,goal/4,action/4.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Goal Introduction
%%% Description: 		revise the top-level goals of the cmpt
%%% Capability used: 		goal decision 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
/*  Description [Kostas]:  goal_decision(KB, Goals) - Goals is a
possibly empty list of goals: (i) if goal_decision fails, returns [],
meaning no goals; in this case the goals and plan are updated with [];
(ii) goal decision should return a unique goal id, probably by using
gensym on some constant e.g. '#g' 
   Personal notes, problems to address:
 * checking whether the goals returned by the goal
 decision capability are actually not already achieved should be done
 within the capability maybe? 
 * is the first really needed? to check.
*/


transition(gi,_):-
	goal_decision(NewTopGoals), 
	(NewTopGoals=[]
         ->
	drop_goal(nil)
	;
	remove_obsolete_goals(NewTopGoals),
	goals_to_be_dropped(NewTopGoals, OldGoals),
	drop_list_goals(OldGoals),
	format('goals dropped:~w~n', [OldGoals]),
	goals_to_be_added(NewTopGoals, NewGoals),
	add_list_goals(NewGoals),
	format('goals added:~w~n', [NewGoals]),
	purge_plans
	).

remove_obsolete_goals(NewTopGoals) :- true. 
% need to check whether some goals are already satisfied
% don't know how to do that yet

% drop those goals that are currently in the goals but no more in the
% new top goals

goals_to_be_dropped(NewTopGoals,OldGoals) :-
	get_toplevelgoals(Goals),
	list_delete(Goals,NewTopGoals,OldGoals).

% add those goals that were not previously in the goals but are now in
% the new top goals
	
goals_to_be_added(NewTopGoals,NewGoals) :- 
	get_toplevelgoals(Goals),
	list_delete(NewTopGoals,Goals,NewGoals). 




%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Plan Introduction
%%% Description: 		update current goals and current plan
%%% Capability used: 		planning, identify_preconditions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

transition(pi,Goals):-
	sort_goals(Goals,MGoals,SGoals),
	% separate mental goals and sensing goals
	construct_sensing_actions(SGoals,SActions), 
	% sensing actions for sensing goals	
	add_list_actions(SActions),		
	plan_mental_goals(MGoals,NewActions,NewGoals),
	% get the actions and goals to be added
	add_list_goals(NewGoals),
	add_list_actions(NewActions).
	
	
plan_mental_goals([FirstGoal|OtherGoals],NewActions,NewGoals) :-
	planning(FirstGoal,As,Gs),
	FirstGoal = goal(GoalLabel,_,_,_),
	construct_actions_from_plan(GoalLabel,As,ActionsFirstGoal),
	construct_goals_from_plan(GoalLabel,Gs,GoalsFirstGoal),
	append(ActionsFirstGoal,Actions,NewActions),
	append(GoalsFirstGoal,Goals,NewGoals),
	plan_mental_goals(OtherGoals,Actions,Goals).	

construct_actions_from_plan([],[]).
construct_actions_from_plan(GoalLabel,[FirstAs|OtherAs],[FirstAction|OtherActions]) :-
	FirstAs = action(Fluent,Tc), 
	% as given by the planning capability
	identify_preconditions(Fluent,Precond),
	% get the preconditions for this Fluent 
	FirstAction = action(Fluent,GoalLabel,Precond,Tc),
	construct_actions_from_plan(GoalLabel,OtherAs,OtherActions).
	
construct_goals_from_plan([],[]).
construct_goals_from_plan(LabelGoal,[FirstGs|OtherGs],[FirstGoal|OtherGoals]) :-
	FirstGs = goal(Label,Fluent,Tc), 
	% as given by the planning capability
	FirstGoal = goal(Label,Fluent,LabelGoal,Tc),
	construct_goals_from_plan(OtherGs,OtherGoals). 
	
	
sort_goals([],[],[]).
sort_goals([FirstGoal|OtherGoals],NewMGoals,NewSGoals) :-
	FirstGoal = goal(_,Fluent,_,_),
	(sensing_goal(Fluent)
	->
	NewSGoals = [FirstGoal|SGoals],
	NewMGoals = MGoals;
	NewMGoals = [FirstGoal|MGoals],
	NewSGoals = SGoals
	),
	sort_goals(OtherGoals,MGoals,SGoals).


construct_sensing_actions([],[]).
construct_sensing_actions([FirstSGoal|OtherSGoals],[FirstSAction|OtherSActions]) :-
	FirstSGoal = goal(_,Fluent,ParentGoal,TConst),
	identify_preconditions(Fluent,Precond), 
	FirstSAction = action(sense(Fluent),ParentGoal,Precond,TConst),
	% looks dodgy (label of the first goal instead?)
	construct_sensing_actions(OtherSGoals,OtherSActions).	

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Reactivity
%%% Description: 		includes new goals and plans from constraints
%%% Capability used: 		reactivity, identify_preconditions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

transition(re,_) :-
	reactivity(NewGoals,NewActions),
	add_list_goals(NewGoals),
	construct_precond_actions(NewActions,NewPrecondActions),
	add_list_actions(NewPrecondActions).	

construct_precond_actions([],[]).
construct_precond_actions([FirstAction|OtherActions],[FirstPAction|OtherPActions]) :-
	FirstAction = action(Op,ParentGoal,TConst), 
	identify_preconditions(Op,Precond),
	FirstPAction = action(Op,ParentGoal,Precond,TConst),
	construct_precond_actions(OtherActions,OtherPActions).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Sensing Introduction
%%% Description: 		
%%% Capability used: 		identify_preconditions 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

transition(si,Preconds) :-
	construct_sensing_actions(Preconds,SensingActions),
	add_list_actions(SensingActions).

construct_sensing_actions([],[]).
construct_sensing_actions([FirstPrecond,OtherPreconds],[FSAction|OtherSActions]) :-
	FirstPrecond = precond(Op,Goal), %
	identify_preconditions(sense_precondition(Op),D),
	FSAction = sense_precondition(Op,Goal,D,'FIX ME t1<t2'),
	construct_sensing_actions(OtherPreconds,OtherSActions). %time issue here

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Passive Observation Introduction
%%% Description: 		
%%% Capability used: 		goal decision 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Active Observation Introduction
%%% Description: 		
%%% Capability used: 		checking_environment 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

transition(aoi,Fluents) :-
	construct_observed_fluents(Fluents,ObservedFluents),
	add_kb0(ObservedFluents).

construct_observed_fluents([],[]).
construct_observed_fluents([FirstFluent|OtherFluents],[FirstOFluent|OtherOFluents]) :-
	(checking_environment(FirstFluent,Val)
	->
	FirstOFluent = observed(FirstFluent,Val);
	(checking_environment(neg(FirstFluent),val)
	->
	FirstOFluent = observed(neg(FirstFluent),Val)
	)),
	construct_observed_fluents(OtherFluents,OtherOFluents).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Action Execution
%%% Description: 		performing actions in plans
%%% Capability used: 		sensing
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Description: in any case, add the fact that the action has been
%%% executed in kb0, and, if the action is a sensing action
%%% (sense/sense_precond) add observation on top of that. 


transition(ae,Actions) :- 
	construct_executed_actions(Actions,ExActions),
	add_kb0(ExActions),
	select_sensing_fluents(Actions,SensingActions),
	construct_observed_fluents(SensingActions,ObsSensingActions),
	add_kb0(ObsSensingActions).
	
construct_executed_actions([],[]).
construct_executed_actions([FirstAction|OtherActions],[FirstExAction|OtherExActions]) :-
	FirstAction = action(Op,_,_,TConst),
	FirstExAction = executed(Op,TConst),
	construct_executed_actions(OtherActions,OtherExActions).

select_sensing_fluents([],[]).
select_sensing_fluents([FirstAction|OtherActions],NewSFluents) :-
	FirstAction = action(Op,_,_,_),
	(sensing_action(Op)
	->
	Op =.. [_|[Fluent]],
	NewSFluents = [Fluent|SFluents]
	;
	NewSFluents = SFluents
	),
	select_sensing_fluents(OtherActions,SFluents).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Goal Revision
%%% Description: 		keeping only those goals worth achieving
%%% Capability used: 		
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Plan Revision
%%% Description: 		keeping actions in plans still relevant
%%% Capability used: 		
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%






%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% extra_list
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%% list_delete(List1,List2,List3) 
%%% select elements of List1 that are not in List2, the result is in List3

list_delete([],_,[]).
list_delete([Hd1|Tl1],List2,[Hd1|Tl3]) :- 
	non_member(Hd1,List2), 
	list_delete(Tl1,List2,Tl3),!.
list_delete([_|Tl1],List2,List3) :-
	list_delete(Tl1,List2,List3).
	

/* or:
*/

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% toy-capacities for the sake of test
%%% examples :-)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% FIX ME
valid_temporal_constraints(_,_).

%goal_decision(exd4, NewToplevelGoals) :- 
%	NewToplevelGoals = [goal(g0,problem_fixed(p2,t),nil,5<T)]. 
	
%goal_decision(exd4, NewToplevelGoals) :- 
%	NewToplevelGoals = [goal(g3,take_a_nap,nil,9),goal(g0,problem_fixed(p2,t),nil,8)]. 

goal_decision(exd4, NewToplevelGoals) :- 
	NewToplevelGoals = [goal(g3,take_a_nap,nil,9)]. 


reactivity(NewGoals,NewActions) :-
	NewGoals = [],
	NewActions = [action(give(y,pen,T),nil,T=5)].

identify_preconditions(Op,Precond) :-
	Op = give(y,pen,T),
	Precond = have(y,pen).
identify_preconditions(_,nil).


checking_environment(have(y,pen),10).
checking_environment(neg(have(y,car)),10).

%%%
%%% test for action execution
%%%

[action(tell(c1,c2,request(r1),d,t),g1,nil,T=3),action(sense(have(y,pen)),nil,nil,T=6)].

%%% test: transition(ae,Actions)
%%% check that only the sensing action is observed.


%%% test: transition(pi,)

% list of goals selected for planning (know(weather) is a sensing goal)
% [goal(g10,in_touch_with(tom),nil,10),goal(g11,know(weather),nil,T<8)]

% plan as given given by the planning capability
planning(goal(g10,in_touch_with(tom),nil,T),As,Gs) :-
	 As = [	action(write(tom),T-1),
		action(get_adress(tom),T-2),
		action(get_connection,T-3)],
	Gs =[].

