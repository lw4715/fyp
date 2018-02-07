%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%	New version -- modules instead of attributes
%%%	Predicates used: 
%%%		goal(Label,Fluent,ParentGoal,TempConst).
%%%		action(Operator,ParentGoal,Precond,TempConst). 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
:- use_module(library(lists)). 


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
:- multifile goal/4,action/4.
:- dynamic goal/4,action/4.

:- use_module(kbplan).
:- load_files([init_goals,init_plans]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% 	 	add_goal(Goal)
%%% 		add_list_goals(Goals)
%%% 		get_subgoals(ParentGoal,SubGoals)
%%% 		get_toplevelgoals
%%% 		leafgoal
%%% 		get_allsubgoals()
%%% 		drop_goal(Goal)
%%%		get_list_labels(Labels)
%%% 		get_ancestors(LabelGoal,Ancestors)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% here you define what is a sensing goal.

sensing_goal(Op) :-
	Op =.. [GoalName|_],
	member(GoalName,[know]).

add_goal(NewGoal) :-
	NewGoal = goal(_,_,_,_),
	assert(NewGoal).

add_list_goals([]).
add_list_goals([NewGoal|OtherNewGoals]) :-
	add_goal(NewGoal),
	add_list_goals(OtherNewGoals). 


get_subgoals(LabelParentGoal,LabelSubGoals) :-
	findall(X,goal(X,_,LabelParentGoal,_),LabelSubGoals).


get_allsubgoals(Goal,[Goal]) :- 
	leafgoal(Goal).
get_allsubgoals(Goal,[Goal|SubGoalTrees]) :- 
	get_subgoals(Goal,SubGoals),
	get_allsubgoals2(SubGoals,SubGoalTrees).

get_allsubgoals2([],[]).
get_allsubgoals2([FirstSubGoal|OtherSubGoals],GoalTrees) :-
	get_allsubgoals(FirstSubGoal,GoalTree1), 
	get_allsubgoals2(OtherSubGoals,GoalTree2),
	append(GoalTree1,GoalTree2,GoalTrees).


get_toplevelgoals(TopLevelGoals) :-
	findall(X,goal(X,_,nil,_),TopLevelGoals).

leafgoal(LabelGoal) :- 
	goal(LabelGoal,_,_,_), get_subgoals(LabelGoal,[]).

get_ancestors(nil,[]).
get_ancestors(LabelGoal,[LabelParentGoal|OtherAncestors]) :-
	goal(LabelGoal,_,LabelParentGoal,_),
	get_ancestors(LabelParentGoal,OtherAncestors).

get_ancestors_eq(Goal,[Goal|Ancestors]) :-
	get_ancestors(Goal,Ancestors).

drop_goal(LabelGoal) :-
	get_allsubgoals(LabelGoal,LabelSubGoals),
	purge_goals(LabelSubGoals).

purge_goals([]).	
purge_goals([FirstGoal|OtherGoals]) :-
	retract(goal(FirstGoal,_,_,_)),
	purge_goals(OtherGoals).

drop_list_goals([]).
drop_list_goals([OldGoal|OtherOldGoals]) :-
	drop_goal(OldGoal),
	drop_list_goals(OtherOldGoals).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% 	 	add_action(Action)
%%%		--add an action 
%%% 		purge_plans  
%%%		--delete plan not related to existing goal	
%%%		get_plan(+Goal,-Plan)  
%%%		--return the plan (list of action) for goal Goals
%%%		sensing_actions
%%%		--check whether sensing action
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

sensing_action(Op) :-
	Op =.. [ActionName|_],
	member(ActionName,[sense,sense_preconditions]).

add_action(NewAction) :-
	NewAction = action(_,_,_,_),
	assert(NewAction).

add_list_actions([]).
add_list_actions([NewAction|OtherNewActions]) :-
	add_action(NewAction),
	add_list_actions(OtherNewActions). 

drop_action(OldAction) :-
	retract(OldAction).


get_plan(LabelGoal,Plan) :- 
	findall(action(Op,LabelGoal,PreCond,TempConst),action(Op,LabelGoal,PreCond,TempConst),Plan).

purge_plans :- 
	findall(action(Op,LabelGoal,PreCond,TempConst),action(Op,LabelGoal,PreCond,TempConst),AllActions), 
	purge_plans(AllActions).
purge_plans([]).
purge_plans([FirstAction|OtherActions]) :-
		FirstAction = action(_,ParentGoal,_,_),
		(goal(ParentGoal,_,_,_)
		->
		purge_plans(OtherActions);
		drop_action(FirstAction),
		purge_plans(OtherActions)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% kb0
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

add_kb0([]).
add_kb0([NewKnowledge|Tail]) :-
	assert(NewKnowledge),
	add_kb0(Tail). 

print_kb0 :-
	listing([observed/2,executed/2]).

print_computee :-
	print_kb0,
	listing([action/4,goal/4]).
	
