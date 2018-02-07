:- compile(ct).
rule(self1, self(behavior,punctual), []).


%%% location (3,1)

%% Previous situation

rule(f(0,0),at(percept(direction(north)),0), []).


%% Current situation

rule(f(1,0),at(percept(direction(north)),1), []).
rule(f(1,1),at(percept(stench),1), []).
