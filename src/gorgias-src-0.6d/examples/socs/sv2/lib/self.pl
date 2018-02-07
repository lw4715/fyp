%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Implementing State and Capabilities for Intelligent Computees
%%
%% Neophytos Demetriou (nkd@ucy.ac.cy)
%%
%% This software is licensed under the Gnu Public License.
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


:- multifile complement/2.
:- multifile rule/3.

:- multifile kb_0__rule/3.
:- multifile kb_0__evidence/1.
:- multifile kb_gd__rule/3.
:- multifile kb_gd__todo/1.
:- multifile kb_re__rule/3.
:- multifile kb_re__goal/2.
:- multifile kb_re__action/2.

:- multifile self__history/2.
:- multifile self__iff/2. %% hook for the IFF planner

:- dynamic kb_0__observed/2.
:- dynamic kb_0__observed/3.
:- dynamic kb_0__executed/1.
:- dynamic kb_0__evidence/1.

:- dynamic self__history/2.
:- dynamic self__timestamp_current/1.
:- dynamic self__profile/1.
:- dynamic self__goal/3.
:- dynamic self__action/4.
:- dynamic self__logging/1.
:- dynamic self__friend/1.
:- dynamic self__urgency_wrt_time_epsilon/1.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__id(c0).                          /* unique identifier of the computee  */

self__epsilon(2).                      /* a sufficiently small number and 
                                        * that is used to denote how much 
				        * back in time should we check for
				        * effects of executed actions.
                                        */

self__isnull([]).                      /* the null recognizer, identifier    */

self__history(0, step('INIT',[])).     /* first step is the initialization   */

self__timestamp_current(1).            /* local clock of the computee        */

self__logging(off).                    /* log this session or not            */


self__urgency_wrt_time_epsilon(1).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__next(step(Transition,Input)) :-
	self__prove(step(Transition,Input)),
	self__log('Next step is   ... ~w', [step(Transition, Input)]).

self__prove(Query) :-
	gorgias__prove(Query).

self__prove(Query,Proof) :-
	gorgias__prove(Query,Proof).

self__commit(step(Transition, Input)) :-
	self__timestamp_current(Timestamp),
	self__history_add(Timestamp,step(Transition,Input)),
	self__log('Executing      ... ~w', [step(Transition, Input)]),
	self__transition_commit(Transition,Input),
	self__timestamp_incr(Timestamp).

self__now(Literal) :-
	self__timestamp_current(Timestamp),
	self__now(Literal,Timestamp).

self__now(Literal,Timestamp) :-
	self__literal_to_fluent(Literal,Timestamp,Fluent),
	self__prove(Fluent).



self__goal_decision(OGDs) :-
	findall(GD, self__prove(gd(GD)), GDs),
	list_to_ord_set(GDs, OGDs).

self__reaction(OGRs,OARs) :-
	findall(GR, self__prove(gr(GR)), GRs),
	findall(AR, self__prove(ar(AR)), ARs),
	list_to_ord_set(GRs,OGRs),
	list_to_ord_set(ARs,OARs).

self__plan(Goals,Plan) :-
	self__iff(Goals,Plan).
        

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__transition_commit('GI',Input) :-
	self__isnull(Input),
	self__goal_decision(GDs),
	self__log('Goal Decision  ... ~w', [GDs]),
	self__goal_tree_adjust(GDs),
	self__action_tree_adjust(GDs).

self__transition_commit('RE',Input) :-
	self__isnull(Input),
	self__reaction(GRs,ARs),
	self__log('Reaction is    ... Goals=~w, Actions=~w', [GRs,ARs]),
	self__reaction_tree_adjust(GRs,ARs).

self__transition_commit('PO',Observations) :-
	forall(member(Observation,Observations), self__obs_add(Observation)).

self__transition_commit('AO', Observations) :-
	forall(member(Observation,Observations), self__obs_add(Observation)).


self__transition_commit('AE', (Actions, Observations)) :-
	is_list(Actions),
	is_list(Observations),
	!,
	forall(member(Action,Actions), self__action_execution_add(Action)),
	forall(member(Observation,Observations), self__obs_add(Observation)).

        /* the environment should check whether this is a sensing action
         * and update the Observations list accordingly, as specified in D4.
         */

%%% this is only for testing
self__transition_commit('AE', Actions) :-
	self__transition_commit('AE', ([Actions], [])).


self__transition_commit('SI', SPs) :-
	forall(member(SP,SPs), self__action_add(SP)).
	
self__transition_commit('PI', Gs) :-
	self__diff_mental_and_sensing_goals(Gs, MGs, SGs),
	self__log('Mental Goals  ... ~w', [MGs]),
	self__log('Sensing Goals ... ~w', [SGs]),
	forall(member(SG,SGs),self__sensing_goal_add(SG)),
	self__plan(MGs,Plan),
	self__log('Plan is       ... ~w', [Plan]),
	forall(member(Action,Plan), self__action_add(Action)).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__friend_add(CID) :-
	assert(self__friend(CID)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__goal_add(goal(Goal, Parent, TC)) :-
	self__log('Adding Goal    ... ~w', [goal(Goal, Parent, TC)]),
	assert(self__goal(Goal,Parent,TC)).

self__action_add(action(Action, Goal, Preconditions, TC)) :-
	self__log('Adding Action  ... ~w', [action(Action, Goal, Preconditions, TC)]),
	assert(self__action(Action, Goal, Preconditions, TC)).

self__obs_add(obs(Literal)) :-
	self__log('Adding Obs     ... ~w', [obs(Literal)]),
	self__timestamp_current(Timestamp),
	assert(kb_0__observed(Literal,Timestamp)).

self__obs_add(obs(Literal,Timestamp)) :-
	self__log('Adding Obs     ... ~w', [obs(Literal,Timestamp)]),
	assert(kb_0__observed(Literal,Timestamp)).

self__obs_add(obs(CID,Op,Timestamp)) :-
	self__log('Adding Obs     ... ~w', [obs(CID,Op,Timestamp)]),
	self__friend_add(CID),
	assert(kb_0__observed(CID,Op,Timestamp)).

self__action_execution_add(Action) :-
	self__log('Action Exec    ... ~w', [Action]),
	assert(kb_0__executed(Action)).


self__goal_decision_add((Goal,anytime)) :-
	self__isnull(NULL),
	self__timestamp_for_anytime(Timestamp),
	self__goal_add(goal((Goal,Timestamp),NULL,[])).
self__goal_decision_add(Literal) :-
	self__isnull(NULL),
	self__goal_add(goal(Literal,NULL,[])).
	

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__history_add(Step) :-
	self__timestamp_current(Timestamp),
	self__history_add(Timestamp, Step).

self__history_add(Timestamp, Step) :-
	assert(self__history(Timestamp, Step)).

self__history_reset(List) :-
	retractall(self__history(_,_)),
	forall(member(Step, List), (self__history_add(Step), self__timestamp_incr)).
	

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__timestamp_reset :-
	self__timestamp_set(0).

self__timestamp_set(Timestamp) :-
	retractall(self__timestamp_current(_)),
	assert(self__timestamp_current(Timestamp)).

self__timestamp_incr :-
	self__timestamp_current(Timestamp),
	self__timestamp_incr(Timestamp).

self__timestamp_incr(Timestamp) :-
	New_Timestamp is Timestamp + 1,
	retractall(self__timestamp_current(_)),
	self__timestamp_set(New_Timestamp).

self__timestamp_next(Next_Timestamp) :-
	self__timestamp_current(Timestamp),
	Next_Timestamp is Timestamp + 1.

self__timestamp_for_anytime(Anytime) :-
	self__timestamp_current(Timestamp),
	self__epsilon(Epsilon),
	Anytime is Timestamp + Epsilon.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__profile_reset(List) :-
	is_list(List),
	self__profile_reset,
	self__profile_addall(List),
	write('\n'),
	self__log('Reset profile  ... ~w', [List]).


self__profile_reset(Profile) :-
	\+ is_list(Profile),
	self__profile_reset([Profile]).
	
self__profile_reset :-
	retractall(self__profile(_)).

self__profile_add(Profile) :-
	assert(self__profile(Profile)).

self__profile_addall(List) :-
	is_list(List),
	forall(member(Profile, List), self__profile_add(Profile)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__identifier_set(UID) :-
	retractall(self__id(_)),
	assert(self__id(UID)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__goal_tree_adjust([]) :-
	retractall(self__goal(_,_,_)).

self__goal_tree_adjust(GDs) :-
	self__isnull(NULL),
	retractall(self__goal(_,NULL,_)),
	forall(member(GD,GDs), self__goal_decision_add(GD)),
	self__goal_tree_purge(GDs).

self__goal_tree_purge(GDs) :-
	findall(Obsolete_Goal, self__goal_nopass(Obsolete_Goal), OGs),
	forall(member(OG, OGs), retractall(OG)).

self__goal_nopass(Obsolete_Goal) :-
	self__goal(Literal, Parent, TC),
	Obsolete_Goal = self__goal(Literal, Parent, TC),
	self__goal_isorphan(Obsolete_Goal).
	
self__goal_isorphan(self__goal(_,Parent,_)) :-
	self__isnull(NULL),
	Parent \= NULL,
	\+ self__goal(Parent,_,_).

self__goal_isorphan(self__goal(_,Parent,_)) :-
	self__goal(Parent, Grand_Parent, TC),
	self__goal_isorphan(self__goal(Parent, Grand_Parent, TC)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


self__action_tree_adjust([]) :-
	retractall(self__action(_,_,_,_)).

self__action_tree_adjust(GDs) :-
	GDs \= [],
	findall(Obsolete_Action, self__action_nopass(Obsolete_Action), OAs),
	forall(member(OA, OAs), retractall(OA)).

self__action_nopass(self__action(_,Goal,_,_)) :-
	self__action(_,Goal,_,_),
	\+ Goal.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__reaction_tree_adjust(GRs,ARs) :-
	self__reaction_goal_add(GRs),
	self__reaction_action_add(ARs).

self__reaction_goal_add([]).
self__reaction_goal_add([GR|GRs]) :-
	assert(GR),
	self__reaction_goal_add(GRs).


self__reaction_action_add([]).
self__reaction_action_add([Op|ARs]) :-
	self__isnull(NULL),
	self__timestamp_next(Timestamp),
	self__action_add(action((Op,Timestamp),NULL,[],[])),
	self__reaction_action_add(ARs).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


rule(Label, Head, Body) :-
	kb_tr__rule(Label, Head, Body).

rule(Label, Head, Body) :-
	kb_0__rule(Label, Head, Body).


rule(Label, Head, Body) :- 
	kb_gd__rule(Label, Head, Body).

rule(Label, Head, Body) :-
	kb_re__rule(Label, Head, Body).

rule(Label, Head, Body) :-
	ct__rule(Label, Head, Body).

rule(Label, Head, Body) :-
	patt__rule(Label, Head, Body).


complement(gd(X), gd(Y)) :- 
	kb_gd__incompatible(X,Y).

complement(ar(X), ar(Y)) :- 
	kb_re__incompatible_ar(X,Y).

complement(gr(X), gr(Y)) :- 
	kb_re__incompatible_gr(X,Y).

complement(step(X,_),step(Y,_)) :-
	ct__incompatible(X,Y).

complement(step(X,Input_1),step(X,Input_2)) :-
	ct__istransition(X),
	ct__ec(X,Input_1),
	ct__ec(X,Input_2),
	Input_1 \= Input_2.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%kb_gd__rule(gd(Goal),gd(Goal),[]) :- kb_gd__todo(Goal).

kb_re__rule(ar(Action), ar(Action), Body) :- kb_re__action(Action, Body).

kb_re__rule(gr(Goal), gr(Goal), Body) :- kb_re__goal(Goal, Body).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__literal_to_event(Literal,Event_Timestamp,Event) :-
	Event = happens(Literal, Event_Timestamp).

self__literal_to_fluent(neg(Literal),Timestamp,Fluent) :-
	Fluent = neg(holds(Literal, Timestamp)), !.

self__literal_to_fluent(Literal,Timestamp,Fluent) :-
	Fluent = holds(Literal, Timestamp).

self__diff_mental_and_sensing_goals([],[],[]).
self__diff_mental_and_sensing_goals([G|Gs],[G|MGs],SGs) :-
	self__ismental_goal(G),
	self__diff_mental_and_sensing_goals(Gs,MGs,SGs).
self__diff_mental_and_sensing_goals([G|Gs],MGs,[G|SGs]) :-
	self__issensing_goal(G),
	self__diff_mental_and_sensing_goals(Gs,MGs,SGs).
	
self__diff_mental_and_sensing_goals(G,[G],[]) :-
	self__ismental_goal(G).
self__diff_mental_and_sensing_goals(G,[],[G]) :-
	self__issensing_goal(G).

	
	

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__isanswer(accept).
self__isanswer(reject).


self__issensing_goal(((sense(_),_),_,_)).
self__ismental_goal(G) :-
	\+ self__issensing_goal(G).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__logging_set(X) :-
	retractall(self__logging(_)),
	assert(self__logging(X)).

self__log(Msg,Args) :-
	(self__logging(on) -> (write('Self: '), format(Msg,Args), write('\n')) ; true).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


self__temporal_constraints_validate(T,_) :-
	self__timestamp_current(Timestamp),
	Timestamp =< T.


self__last_transition(Transition) :-
	self__last_transition(Transition,_).

self__last_transition(Transition,Input) :-
	self__timestamp_current(T1),
	T0 is T1 - 1,
	self__history(T0,step(Transition,Input)).

self__last_transition_eq(Transition,Input) :-
	ground(Transition),
	self__timestamp_current(T1),
	T0 is T1 - 1,
	self__last_transition_eq(Transition,Input,T0).

self__last_transition_eq(Transition,Input,T0) :-
	ground(Transition),
	self__history(T0,step(Transition,Input)), !.
	
self__last_transition_eq(Transition,Input,T0) :-
	ground(Transition),
	TM1 is T0 - 1,
	TM1 > 0,
	self__last_transition_eq(Transition,Input,TM1).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


self__goal_has_nochild(G) :-
	\+ self__goal(_,G,_),
	\+ self__action(_,G,_,_).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__toplevel_goal_is(Goal,Goal) :-
	self__isnull(NULL),
	self__goal(Goal,NULL,_).

self__toplevel_goal_is(Goal,Toplevel_Goal) :-
	self__goal(Goal,Parent_Goal,_),
	\+ self__isnull(Parent_Goal),
	self__toplevel_goal_is(Parent_Goal,Toplevel_Goal).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

self__urgency_wrt_time_epsilon_set(Epsilon) :-
	retractall(self__urgency_wrt_time_epsilon(_)),
	self__log('Setting Urgency wrt Time = ~w',[Epsilon]),
	assert(self__urgency_wrt_time_epsilon(Epsilon)).
