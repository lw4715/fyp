:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

    rule(r1(X), fly(X), [bird(X)]).
    rule(r2(X), neg(fly(X)), [penguin(X)]).

    rule(f1, bird(tweety), []).
    rule(f2, penguin(tweety), []).

    rule(pr1(X), prefer(r2(X), r1(X)), []).
