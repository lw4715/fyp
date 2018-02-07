% ============================================================ %
%			      PLATYPUS EXAMPLE		       %
% =============================================================%
% This example is used to illustrate how a goal can be proved  %
% by using the same rules repeatedly	          	       %
% ============================================================ %

:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(r1(X), mammal(X),           [monotreme(X)]).
rule(r2(X), mammal(X),           [hasFur(X)]).
rule(r3(X), neg(mammal(X)),      [laysEggs(X)]).
rule(r4(X), neg(mammal(X)),      [hasBill(X)]).
rule(r5(X), monotreme(platypus), []).
rule(r6,    hasFur(platypus),    []).
rule(r7,    laysEggs(platypus),  []).
rule(r8,    hasBill(platypus),   []).

rule(pr1,   prefer(r1(_),r3(_)), []).
rule(pr2,   prefer(r2(_),r4(_)), []).
rule(pr3,   prefer(r4(_),r1(_)), []).
rule(pr4,   prefer(r3(_),r2(_)), []).
