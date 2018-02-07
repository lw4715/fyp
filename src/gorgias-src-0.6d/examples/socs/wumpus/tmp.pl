
/* 

isgoal(n_goal(alive(wumpus))).

rule(termination(shoot(Direction), alive(wumpus),T),termination(shoot(Direction), alive(wumpus),T),[happens(shoot(Direction),T), holds(have(arrow),T)]) :- isdirection(Direction).

rule(failed(shoot(Direction),neg(alive(wumpus)),T),failed(shoot(Direction),neg(alive(wumpus)),T),[g_check(happens(shoot(Direction),T)), neg(holds(percept(scream),TNEXT))]) :- TNEXT is T + 1, isdirection(Direction).

*/
