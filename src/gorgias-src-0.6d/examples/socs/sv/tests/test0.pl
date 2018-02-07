%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 
%% Author: Neophytos Demetriou (nkd@cs.ucy.ac.cy)
%%
%% Description: Demonstrates Reactivity
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

:- compile('../sv').

:- multifile abducible/2, rule/3, complement/2.


title('TEST 0').
comment('The interrupt component is triggered (all behaviours return the same cycle step to be executed). Note that the interrupt component dictates that either a GI, RE, or GR transition should take place next. However, an RE transition is preferred since the PO introduced a communication request and the computee\'s theory include a preference for this case. TO DO: We could relate this to a social norm that requires an immediate response to requests from other computees.').



computee :: {

     super(computee_basic) &

     attributes([timepoint(2)]) &

     history(0,step('INIT',[])) &

     history(1,step('PO', [observed(c1, request(c0, share_taxi), 1)]))

}.



%% The abducibles are only used for testing purposes.

abducible(out_of_cash, []).
abducible(neg(out_of_cash), []).


%% KB_0

observed(c1, request(c0, share_taxi), 1). % add a conditional request, e.g. same destination/airport?




%% KB_REACT

rule(kb_react(Reaction, What), kb_react(Reaction), [rr(Request,Response)]) :-
	computee::get(uid(Self)),
	computee::get(timepoint(TE)),
        computee::get(epsilon(Epsilon)),
	observed(X, What, T0),
	What = request(Self, Request),
	Reaction = tell(X, response(Self, Request, Response), TE), 
	TE =< T0 + Epsilon.


%% listing all possible responses to a request for sharing a taxi
rule(rr(share_taxi, accept), rr(share_taxi, accept), []).
rule(rr(share_taxi, reject), rr(share_taxi, reject), []).

%% preferences for sharing a taxi

% default   -- accept to share a taxi ...
% exception -- unless there's a single taxi available

rule(PREF, PREF, []) :-
	PREF = prefer(rr(share_taxi, accept),rr(share_taxi, reject)).

rule(PREF, PREF, [WHEN]) :-
	PREF = prefer(rr(share_taxi, reject),rr(share_taxi, accept)),
	WHEN = single_taxi_available.


%% higher order preferences for sharing a taxi

% default   -- reject when there's a single taxi available, info provided by PREF2 ...
% exception -- ... but accept if you are out of cash

rule(HO_PREF, HO_PREF, [WHEN]) :-
	PREF1 = prefer(rr(share_taxi, accept),rr(share_taxi, reject)),
	PREF2 = prefer(rr(share_taxi, reject),rr(share_taxi, accept)),
	HO_PREF = prefer(PREF2,PREF1),
	WHEN = neg(out_of_cash).

rule(HO_PREF, HO_PREF, [WHEN]) :-
	PREF1 = prefer(rr(share_taxi, accept),rr(share_taxi, reject)),
	PREF2 = prefer(rr(share_taxi, reject),rr(share_taxi, accept)),
	HO_PREF = prefer(PREF1,PREF2),
	WHEN = out_of_cash.
	
rule(f111, single_taxi_available,[]).	


complement(rr(Request,Response1), rr(Request,Response2)) :-
	incompatible(Response1,Response2).

incompatible(accept, reject) :- !.
incompatible(reject, accept).

%%

:- start.

:- computee::do(step('RE',[])).

:- writeln('-------------------------------------------------------------------------------').
