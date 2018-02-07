%
% check for the presence of "eclipse" module in ECLiPSe
%
prolog(eclipse) :-
	current_module(eclipse),
	!.

prolog(Prolog) :-
	prolog_flag(version,Version),
	first_token(Version,First,Rest),
	first_token(Rest,Second,_),
	prolog(First,Second,Prolog).

prolog('SICStus','3.7.1',pfdm).
prolog('SICStus',_,sicstus).
prolog('SWI-Prolog',_,swi).

first_token(X,Token,Rest) :-
	name(X,X_string),
	first_token_string(X_string,Token_string,Rest_string),
	name(Token,Token_string),
	name(Rest,Rest_string).

first_token_string([],[],[]).
first_token_string([32|Rest],[],Rest) :-
	!.
first_token_string([C|Cs],[C|Xs],Rest) :-
	first_token_string(Cs,Xs,Rest).

