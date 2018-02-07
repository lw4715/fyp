:- compile(ct).

rule(self1, self(behavior,punctual), []).

rule(f(2), at(time_out,1), []).
rule(f(3,1,A), at(todo(A),1), [member(A,[work,study,assist])]).
rule(f(3,2,G), at(mission(G),1), [member(G, [graduate,survival,community_service])]).
rule(f(4,1), at(deadline(study,2),1), []).
rule(f(4,2), at(critical(survival),1), []).
rule(f(4,3), at(unknown(sunny_weather),1), []).
rule(f(4,3), at(required(sunny_weather),1), []).
rule(f(5,1), at(in_danger,1), []).


:- prove([X],D),writeln('=========='),writeln('Solution:'),writeln('=========='),pretty(D).
