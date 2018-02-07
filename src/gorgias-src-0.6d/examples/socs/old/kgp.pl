%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%	Predicates used: 
%%%		goal(Label,Fluent,ParentGoal,TempConst).
%%%		action(Operator,ParentGoal,Precond,TempConst). 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
:- use_module(library(objects)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

computee :: {
	super(object) 	&
	attributes([name(nobody)])	&
	id_display(Terminal) :- 
		get(name(Name)),
		Terminal:: format('Computee name: ~w~n', [Name])	
	}. 

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% class: 	k_computee
%%% attributes: modules for the different (sub-)knowledge bases
%%% methods: 	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

k_computee :: {
	super(computee)	&
	attributes(	[kb_0([])],
			[kb_plan([])],
			[kb_tr([])],
			[kb_gd([])],
			[kb_react([])])	&

	add_knowledge(NewKnow) :- 
		get(kb_0(Know)),
		set(kb_0([NewKnow|Know]))&
	
	kb_display(Terminal) :- 
		get(kb_0(Kb_0)),
		get(kb_plan(Kb_plan)),
		get(kb_tr(Kb_tr)),
		get(kb_react(Kb_react)), 
		Terminal::format('Knowledge base~n',[]),
		Terminal::format('... for KB_0:~18|~w~n', [Kb_0]),
		Terminal::format('... for KB_plan:~18|~w~n', [Kb_plan]),
		Terminal::format('... for KB_tr:~18|~w~n', [Kb_tr]),
		Terminal::format('... for KB_plan:~18|~w~n', [Kb_react])	
	}. 

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% class: 	p_computee
%%% attributes: list of plans
%%% methods: 	add_plan
%%% 		purge_plans	
%%%		plans_display
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

p_computee :: {
	super(computee)		&
	
	attributes([plans([])])	&

	add_plan(NewPlan) :- 
		get(plans(Plans)),
		set(plans([NewPlan|Plan]))&

	drop_plan(OldPlan) :-
		get(plans(Plans)),
		lists:delete(Plans,OldPlan,NewPlans),
		set(plans(NewPlans)) &

	purge_plans :-
		get(plans(Plans)),
		get_list_labels(GoalLabels), 
		purge_plans2(Plans,GoalLabels) &
	purge_plans2([],_) &
	purge_plans2([FirstPlan|OtherPlans],GoalLabels) :-
		FirstPlan = action(_,ParentGoal,_,_),
		(lists:member(ParentGoal,GoalLabels)
		->
		drop_plan(FirstPlan)),
		purge_plans2(OtherPlans,Goals) &				

	plans_display(Terminal) :- 
		get(plans(Plans)),
		Terminal:: format('Plans:~w~n', [Plans])
	}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% class: 	g_computee
%%% attributes: list of goals 
%%% methods: 	add_goal(Goal)
%%% 		get_subgoals(ParentGoal,SubGoal)
%%% 		get_toplevelgoals
%%% 		leafgoal
%%% 		get_allsubgoals()
%%% 		drop_goal(Goal)
%%%		get_list_labels(Labels)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

g_computee :: {
	super(computee)		&

	attributes([goals([])])	&

	add_goal(NewGoal) :- 
		get(goals(Goals)),
		set(goals([NewGoal|Goals]))&

	add_list_goals([]) &
	add_list_goals([NewGoal|OtherNewGoals]) :-
		add_goal(NewGoal),
		add_list_goals(OtherNewGoals) &

	get_subgoals(ParentGoal,SubGoals) :-
		get(goals(Goals)),
		get_subgoals(ParentGoal,Goals,SubGoals) &
	get_subgoals(_,[],[])	&
	get_subgoals(ParentGoal,[FirstGoal|OtherGoals],[FirstGoal|OtherSubGoals]) :-
		FirstGoal = goal(_,_,ParentGoal,_), 
		get_subgoals(ParentGoal,OtherGoals,OtherSubGoals), ! &
	get_subgoals(ParentGoal,[FirstGoal|OtherGoals],SubGoals) :-
		get_subgoals(ParentGoal,OtherGoals,SubGoals) &

	get_toplevelgoals(TGoals) :- 
		get_subgoals(nil,TGoals) &

	leafgoal(Goal) :- 
		get_subgoals(Goal,SubGoals),
		SubGoals = [] &

	get_allsubgoals(Goal,[Goal]) :- leafgoal(Goal) &
	get_allsubgoals(Goal,[Goal|SubGoalTrees]) :- 
		get_subgoals(Goal,SubGoals),
		get_allsubgoals2(SubGoals,SubGoalTrees) &

	get_allsubgoals2([],[]) &
	get_allsubgoals2([goal(FirstSubGoal,_,_,_)|OtherSubGoals],GoalTrees) :-
		get_allsubgoals(FirstSubGoal,GoalTree1), 
		get_allsubgoals2(OtherSubGoals,GoalTree2),
		lists:append(GoalTree1,GoalTree2,GoalTrees) &

	purify([],_,[]) &
	purify([FirstGoal|OtherGoals],SubGoals,OtherPGoals) :-
		FirstGoal = goal(Label,_,_,_), 
		lists:member(Label,SubGoals), 
		purify(OtherGoals,SubGoals,OtherPGoals), ! &
	purify([FirstGoal|OtherGoals],SubGoals,[FirstGoal|OtherPGoals]) :-
		purify(OtherGoals,SubGoals,OtherPGoals) &

	drop_goal(OldGoal):- 
		get_allsubgoals(OldGoal,SubGoals),
		get(goals(CurrentGoals)),
		purify(CurrentGoals,SubGoals,NewGoals),
		set(goals(NewGoals)) &

	drop_list_goals([]) &
	drop_list_goals([OldGoal|OtherOldGoals]) :-
		drop_goal(OldGoal),
		drop_list_goals(OtherOldGoals) &

	get_list_labels(ListLabels) :- 
		get(goals(Goals)),
		get_list_labels2(Goals,ListLabels) &
	get_list_labels2([],[]) &
	get_list_labels2([FirstGoal|OtherGoals],[FirstLabel|OtherLabels]) :-
		FirstGoal = goal(FirstLabel,_,_,_),
		get_list_labels2(OtherGoals,OtherLabels) &

	goals_display(Terminal) :- 
		get(goals(Goals)),
		Terminal:: format('Goals:~w~n', [Goals])
	}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

computee_state :: {
	super(k_computee) 	&
	super(g_computee)	&
	super(p_computee)	&

	display(Terminal) :- 
		Terminal::format('**************************~n',[]), 
		id_display(Terminal), 
		kb_display(Terminal),
		goals_display(Terminal),
		plans_display(Terminal),
		Terminal::format('**************************~n',[])
	}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
tty :: {
	format(X,Y) :- :format(X,Y)
	}. 






%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Test (1)
%%% Computee Tweety
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


tweety :: {
	super(computee_state) 	&
	attributes([
		name(tweetycomputee),
		kb_0([observed(windy)]),
		kb_plan([]),
		kb_tr([]), 
		kb_gd([]), 
		kb_react([]),
		goals([	goal(g0,do(fly),nil,T>5),
			goal(g1,learn(fly),g0,8),
			goal(g2,try(fly),g0,9)]),
		plans([plan1])
		])
	}. 


exd4 :: {
	super(computee_state) 	&
	attributes([
		name(exd4),
		kb_0([]),
		kb_plan([]),
		kb_tr([]), 
		kb_gd([]), 
		kb_react([]),
		goals([	goal(g0,problem_fixed(p2,t),nil,5<T),
			goal(g1,get_resource(R1,T1),g0,5<T1),
			goal(g2,get_resource(R2,T2),g0,5<T2)]),
		plans([	action(tell(c1,c2,request(r1),d,t),g1,nil,5<T),
			action(tell(thanks),g9,nil,10)])
		])
	}. 


