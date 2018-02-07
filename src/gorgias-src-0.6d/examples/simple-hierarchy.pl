:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(f1, subclass(a,b), []).
rule(f2, subclass(c,b), []).
rule(f3, is_in(x1,a),   []).
rule(f4, is_in(x2,c),   []).


rule(d1(X), has(X,p),      [is_in(X,b)]).

% Exception

rule(d2(X), neg(has(X,p)), [is_in(X, c)]).
rule(pr1,   prefer(d2(X),d1(X)), []).


% General properties of subclass and is_in

rule(r1(C0,C2), subclass(C0,C2), [C0 \= C1, C1 \= C2, C0 \= C2, subclass(C0,C1), subclass(C1,C2)]).
rule(r2(X,C1),  is_in(X,C1),      [subclass(C0,C1), is_in(X,C0)]).


% Closed world assumptions for simple hierarchies

rule(d3(X,C), neg(is_in(X, C)),   []).
rule(d4(A,B), neg(subclass(A,B)), []).

