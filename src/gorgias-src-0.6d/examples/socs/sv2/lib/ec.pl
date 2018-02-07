%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Author: Neophytos Demetriou (nkd@ucy.ac.cy)
%%
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% User-defined enabling conditions

ct__ec_user_p(PREV_NAME,_,NAME,_) :-
	ct__ec_user_p(PREV_NAME,NAME).

% ...a 'GI' transition can follow any transition whenever there are
%    no goals in the current state

ct__ec_user_p(_, 'GI') :- 
	findall(G, fun__goal_selection(G),[]),
	!.

%% ... 'PR' can follow anything.

ct__ec_user_p(_,'PR') :- !.

% ...what might follow the initialization, i.e. the "initial" component

ct__ec_user_p('INIT', 'GI').
ct__ec_user_p('INIT', 'PI').


% ...what might follow an 'AE' transition, i.e. the "basic" component

ct__ec_user_p('AE','PI').
ct__ec_user_p('AE','AE').
ct__ec_user_p('AE','AO').
ct__ec_user_p('AE','PR').


% ...what might follow a 'PO' transition, i.e. the "interrupt" component

ct__ec_user_p('PO','GI').
ct__ec_user_p('PO','RE').
ct__ec_user_p('PO','GR').


% 'AE' is always qualified (provided a non-empty list of actions from c_AS/1 )

ct__ec_user_p(_,'AE').

% anything can follow a GI transition

ct__ec_user_p('GI',_).


%% SI after any transition

ct__ec_user_p(_,'SI').
