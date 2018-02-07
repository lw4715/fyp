%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Cycle Theory Computation
%%
%% Neophytos Demetriou (nkd@ucy.ac.cy)
%%
%% This software is licensed under the Gnu Public License.
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


:- compile(tr).
:- compile(fun).
:- compile(ec).
:- compile(patt).
:- compile(self).

:- multifile rule/3, complement/2, executed/2, action/4,goal/3,failed/1.


ct__istransition('GI').
ct__istransition('PI').
ct__istransition('RE').
ct__istransition('SI').
ct__istransition('PO').
ct__istransition('AO').
ct__istransition('AE').
ct__istransition('GR').
ct__istransition('PR').


ct__incompatible(X, Y) :-
	ct__istransition(X),
	ct__istransition(Y),
	X \= Y.


%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% BASIC PART: determines the basic steps of operation by specifying the
%% allowed unitary cycle-steps from one transition to another.
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


%% Goal Introduction (GI) revises the top-level goals of the computee (and
%% accordingly the rest of the goal set) given the information from the goal
%% decision capability which decides the goals the computee should focus on
%% depending on its current circumstances. This transition revises also the
%% current plan of the computee, in order to keep only actions which are
%% relevant to the goals in the new set of goals.

ct__rule(step('GI', NULL), step('GI', NULL), []) :- 
	self__isnull(NULL),
	ct__ec('GI', NULL).



%% Plan Introduction (PI) revises the state of the computee by updating the
%% current set of goals and the current plan in order to take into account new
%% plans for the goals selected for planning. These new plans are provided by
%% the planning capability.

ct__rule(step('PI', Gs), step('PI', Gs), []) :- 
	ct__ec('PI', Gs).



%% Reactivity (RE) revises the current state according to the results of the
%% reactivity capability, which determines goals and actions deriving from the
%% reactive constraints. 

ct__rule(step('RE', NULL), step('RE', NULL), []) :-  
	self__isnull(NULL),
	ct__ec('RE', NULL).



%% Sensing Introduction (SI) allows a computee to explicitly add to its current
%% plan a set of sensing actions in order to check whether or not some 
%% preconditions of other actions in its current plan are satisfied.

ct__rule(step('SI', Fs), step('SI', Fs), []) :- 
	ct__ec('SI', Fs).



%% Active Observation (AO) allows the computee to update its current knowledge
%% base by possibly adding new observations from the environment. Differently
%% from PO (see below), however, the computee is deliberately looking for some
%% properties to hold in the environment.

ct__rule(step('AO', Fs), step('AO', Fs), []) :- 
	ct__ec('AO', Fs).



%% Action Execution (AE) is the transition which caters for actually performing
%% actions in plans. Its effect amounts at recording in KB_0 the fact that
%% certain actions have been executed and, in the case of sensing actions, the
%% effect of sensing.

ct__rule(step('AE', As), step('AE', As), []) :- 
	ct__ec('AE', As).



%% Goal Revision (GR) caters for revising the state by keeping only those goals
%% which are still worth achieving.

ct__rule(step('GR', NULL), step('GR', NULL), []) :-  
	self__isnull(NULL),
	ct__ec('GR', NULL).



%% Plan Revision (PR) caters for revising the state by keeping only those
%% actions in the plan which are still relevant and which can still be 
%% executed.

ct__rule(step('PR', NULL), step('PR', NULL), []) :-  
	self__isnull(NULL),
	ct__ec('PR', NULL).



%% Passive Observation (PO) updates the current knowledge base of the computee
%% by adding new observed facts which derive from changes in the environment.
%% A passive observation may be seen as the reaction of the computee to some
%% (unexpected or unpredictable) event (e.g. an interrupt) which happens in the
%% environment. The transition allows the computee to passively absorb or
%% incorporate the observable effects of these events (interrupts) into its
%% knowledge base.

%% NO CYCLE STEP AVAILABLE. TRIGGERED BY THE ENVIRONMENT.







%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% ENABLING CONDITIONS: They determine when a cycle step from one transition
%% to another is allowed or enabled.
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Hardcoded enabling conditions

ct__ec('GI',NULL) :-         
	self__isnull(NULL),
	ct__ec_aux_p('GI',NULL).

ct__ec('PI',Gs) :- 
	fun__goal_selection(Gs),
	ct__ec_aux_p('PI',Gs).

ct__ec('RE',NULL) :-      
	self__isnull(NULL),
	ct__ec_aux_p('RE',NULL).

ct__ec('AE',As) :-      
	fun__action_selection(As),
	ct__ec_aux_p('AE',As).

ct__ec('SI',Fs) :-      
	self__isnull(NULL),
	fun__action_pre_get(Fs),
	Fs \= [],
	ct__ec_aux_p('SI',Fs).

/*

ct__ec('AO',Fs) :-      
	self__isnull(NULL),
	c_FS(Fs_All), 
	Fs_All \= NULL, 
	resource_boundness(Fs_All, Fs),
	ct__ec_aux_p('AO',Fs).
*/

ct__ec('GR',NULL) :-     
	self__isnull(NULL),
	ct__ec_aux_p('GR',NULL).

ct__ec('PR',NULL) :-      
	self__isnull(NULL),
	ct__ec_aux_p('PR',NULL).



ct__ec_aux_p(Transition,Input) :-
	self__timestamp_current(T1),
	T0 is T1 - 1,
	self__history(T0,step(Prev_Transition,Prev_Input)),
	ct__ec_user_p(Prev_Transition, Prev_Input, Transition, Input).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
self__goal_ancestors_eq(NULL, []).
%%self__goal_ancestors_eq


self__goal_check_ancestors_nopass(NULL) :-
	!,
	self__isnull(NULL).

self__goal_check_ancestors_nopass(((Goal,anytime),Parent_Goal,_)) :-
	!,
	\+ self__now(Goal).

self__goal_check_ancestors_nopass(((Goal,Timestamp),Parent_Goal,_)) :-
	!,
	\+ self__now(Goal,Timestamp).


self__goal_check_ancestors_nopass([]).
self__goal_check_ancestors_nopass([G|Gs]) :-
	self__goal_check_ancestors_nopass(G),
	self__goal_check_ancestors_nopass(Gs).

%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% MOVE THIS TO SOME OTHER PLACE
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

resource_boundness([X|_], [X]).

contrary_fluent(holds(neg(L),T), holds(L,T)) :- !.
contrary_fluent(holds(L,T), holds(neg(L),T)).


goal_labels_to_fluents([],[]).
goal_labels_to_fluents([L|Ls], [Fluent|Fluents]) :-
	goal(L, _, _),
	goal_labels_to_fluents(Ls,Fluents).


%% FIX ME: USE THE ACTUAL PREDICATES, THIS IS ONLY HERE TO MAKE THE EXAMPLES WORK


valid_temporal_constraints(_,_).


%% Type predicates
