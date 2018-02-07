% ================================================================== %
%		                 PASTA EXAMPLE                       %
%=================================================================== %
% This example is taken from the paper 'Rules about rules: assessing %
% conflicting arguments in egal reasoning' by Henry Prakken and      %
% Giovanni Sartor. It is used here to illustrate the use of 	     %
% auxiliary predicates and self-referencing rules.	             %
% ================================================================== %

:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').


rule(r1(X,Y,Z), can_be_sold(X,Z),           [countryEC(Y), Z \= Y, can_be_sold(X,Y), countryEC(Z)]).
rule(r2(X,Z),   neg(can_be_sold(X,Z)),      [endangers(X,Z)]).
rule(r3(X,Z),   neg(can_be_sold(X,Z)),      [prejudices(X,Z)]).
rule(r4(X),     neg(can_be_sold(X, italy)), [pasta(X), neg(made_of_hard_corn(X))]).
rule(r5,        countryEC(brd),             []).
rule(r6,        countryEC(italy),           []).
rule(r7,        can_be_sold(p, brd),        []).
rule(r8,        pasta(p),                   []).
rule(r9,        neg(made_of_hard_corn(p)),  []).


rule(pr1, prefer(r2(_,_), r1(_,_,_)),       []).
rule(pr2, prefer(r3(_,_), r1(_,_,_)),       []).
