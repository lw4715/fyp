%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Transitions v.0.1
%%% 07/07/2003	SOCS Project
%%% Based on deliverable D4 (pp. 46--53)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Transitions			ComputeeState * Input -> ComputeeState
%%% predicate used: 		transition(Transition,ComputeeState,Input)

:- use_module(library(lists)). 
:- use_module(library(objects)).



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


transition(gi,Computee):-
	goal_decision(Computee, NewTopGoals), 
	(NewTopGoals=[]
         ->
	Computee::drop_goal(nil)
	;
	remove_obsolete_goals(NewTopGoals),
	goals_to_be_dropped(Computee, NewTopGoals, OldGoals),
	Computee::drop_list_goals(OldGoals),
	format('goals dropped:~w~n', [OldGoals]),
	goals_to_be_added(Computee, NewTopGoals, NewGoals),
	Computee::add_list_goals(NewGoals),
	format('goals added:~w~n', [NewGoals]),
	Computee::purge_plans
	).

remove_obsolete_goals(NewTopGoals) :- true. 
% need to check whether some goals are already satisfied


% drop those goals that are currently in the goals but no more in the
% new top goals

goals_to_be_dropped(Computee,NewTopGoals,OldGoals) :-
	Computee::get_toplevelgoals(Goals),
	list_delete(Goals,NewTopGoals,OldGoals).

% add those goals that were not previously in the goals but are now in
% the new top goals
	
goals_to_be_added(Computee,NewTopGoals,NewGoals) :- 
	Computee::get_toplevelgoals(Goals),
	list_delete(NewTopGoals,Goals,NewGoals). 




%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Plan Introduction
%%% Description: 		update current goals and current plan
%%% Capability used: 		planning
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

transition(pi,Computee,Action):- true.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Reactivity
%%% Description: 		revise the top-level goals of the cmpt
%%% Capability used: 		reactivity
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Sensing Introduction
%%% Description: 		revise the top-level goals of the cmpt
%%% Capability used: 		goal decision 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Passive Observation Introduction
%%% Description: 		revise the top-level goals of the cmpt
%%% Capability used: 		goal decision 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Active Observation Introduction
%%% Description: 		revise the top-level goals of the cmpt
%%% Capability used: 		goal decision 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Name of the transition: 	Action Execution
%%% Description: 		performing actions in plans
%%% Capability used: 		sensing
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Description: in any case, add the fact that the action has been
%%% executed in kb0, and, if the action is a sensing action
%%% (sense/sense_precond) add observation on top of that. 


transition(ae,Computee,Action) :- 
	Computee::add_knowledge(executed(Action)).



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
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%goal_decision(exd4, NewToplevelGoals) :- 
%	NewToplevelGoals = [goal(g0,problem_fixed(p2,t),nil,5<T)]. 
	
%goal_decision(exd4, NewToplevelGoals) :- 
%	NewToplevelGoals = [goal(g3,take_a_nap,nil,9),goal(g0,problem_fixed(p2,t),nil,8)]. 

goal_decision(exd4, NewToplevelGoals) :- 
	NewToplevelGoals = [goal(g3,take_a_nap,nil,9)]. 