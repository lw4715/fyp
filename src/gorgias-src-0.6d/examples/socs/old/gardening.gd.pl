% ==================================================================== %
%                          GD EXAMPLE (GARDENING)                      %
% ==================================================================== %
% A policy for deciding which "high-level" goals amongst Gardening,    %
% Holiday, and Work a computee should set for itself.                  %
% ==================================================================== %

:- compile('../../lib/gorgias').
:- compile('../../ext/lpwnf').

abducible(gardening        , []).
abducible(gardening_season , []).
abducible(weekend          , []).
abducible(short(_)         , []).
abducible(deadline(_)      , []).
abducible(work(_)          , []).
abducible(holiday(_)       , []).
abducible(special_offer(_) , []).
abducible(bonus_offer(_)   , []).
abducible(bank_holiday     , []).
abducible(neg(X), []) :- abducible(X, []).

rule(r1       , goal_option(gardening)     , [weekend]              ).
rule(r2(Trip) , goal_option(holiday(Trip)) , [weekend, short(Trip)] ).
rule(r3       , goal_option(work(Job))     , [deadline(Job)]        ).

rule(p1, prefer(r1,r2(_)),    [gardening_season]).
rule(p2, prefer(r2(Trip),r1), [special_offer(Trip)]).
rule(p3, prefer(r3(Job),r1),  [bonus_offer(Job)]).
rule(p4, prefer(r3,r2(_)),    [neg(bank_holiday)]).

rule(c1, prefer(p2,p1),       [bank_holiday]).


complement(goal_option(X), goal_option(Y)) :- type_go(X), type_go(Y), X \= Y.


% goal options type
type_go(gardening).
type_go(holiday(_)).
type_go(work(_)).
