
goal(share_taxi, nil, 0).
goal(neg(share_taxi), nil, 0).


rule(r1, prefer(gd(goal(share_taxi,nil,0)),gd(goal(neg(share_taxi),nil,0))), [backrest_console]).

rule(r2, prefer(gd(goal(neg(share_taxi),nil,0)),gd(goal(share_taxi,nil,0))), [neg(backrest_console)]).


rule(prefer(r1,r2), prefer(r1,r2), [problem_finding_taxi]).


rule(problem_finding_taxi, problem_finding_taxi, []).
rule(backrest_console, backrest_console, []).
rule(neg(backrest_console), neg(backrest_console), []).

