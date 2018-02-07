
:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').


abducible(pay_normal(_,_),       []).
abducible(neg(pay_normal(_,_)),  []).
abducible(pay_install(_,_),      []).
abducible(neg(pay_install(_,_)), []).
abducible(pay_cash(_,_),         []).
abducible(neg(pay_cash(_,_)),     []).

abducible(high_season,           []).
abducible(neg(high_season),      []).

abducible(regular(_),            []).
abducible(neg(regular(_)),       []).


rule(d1(Ag,Prd), sell(Prd,Ag, high), [pay_install(Ag,Prd)]).
rule(d2(Ag,Prd), sell(Prd,Ag, low), [pay_cash(Ag,Prd)]).
rule(d3(Ag,Prd), neg(pay_install(Ag,Prd)), [bad_credit_history(Ag)]).
rule(d4(Ag,Prd), pay_install(Ag,Prd), [expensive(Prd), cash_flow_problems(Ag)]).

complement(sell(Prd,Ag,high), sell(Prd,Ag,low)).
complement(sell(Prd,Ag,low), sell(Prd,Ag,high)).


rule(f1, bad_credit_history(tom), []).
rule(f2, cash_flow_problems(tom), []).
rule(f3, expensive(peanuts), []).

rule(d5, neg(cash_flow_problems(john)), [neg(high_season)]).


rule(d6(Ag1,Ag2), guarantor(Ag1,Ag2), [neg(cash_flow_problems(Ag2))]).


rule(pr1(Ag1, Prd, Ag2), prefer(d4(Ag1,Prd),d3(Ag1,Prd)), [guarantor(Ag1, Ag2)]).
rule(pr2(Ag,Prd), prefer(d3(Ag,Prd),d4(Ag,Prd)), [high_season]).

rule(prpr(Ag1,Ag2,Prd), prefer(pr1(Ag1,Prd,Ag2), pr2(Ag1,Prd)), [regular(Ag2)]).
