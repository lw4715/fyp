:- multifile rule/3.
rule(t_sonyhack1, neg(requireHighResource(A)),[]).
rule(t_sonyhack2, neg(culpritIsFrom(X, A)),[]).
rule(t_sonyhack3, neg(forBlackMarketUse(M)),[]).
