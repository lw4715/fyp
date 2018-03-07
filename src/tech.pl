:- multifile rule/3.
rule(t_wannacryattack1, neg(requireHighResource(wannacryattack)),[]).
rule(t_wannacryattack2, neg(culpritIsFrom(_875,wannacryattack)),[]).
rule(t_wannacryattack3, neg(forBlackMarketUse(_1783)),[]).
rule(t_wannacryattack5, similar(wannacry,backdoorCantopee),[]).
rule(t_wannacryattack5, similar(trojanAlphanc,backdoorDuuzer),[]).
