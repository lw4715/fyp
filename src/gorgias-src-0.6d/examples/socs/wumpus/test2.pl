:- compile('wumpus').


isgoal(p_goal(have(gold))).

rule(initiation(grab(gold), have(gold), T), initiation(grab(gold),have(gold),T), [happens(grab(gold),T),holds(percept(glitter),T)]).

self(profile,careful).

:- start.
