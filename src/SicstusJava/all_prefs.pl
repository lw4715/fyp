% pref
%% REMEMBER TO UPDATE!
rule(p1_t(),prefer(r_t_attackOrigin(X,Att),r_t_attackOriginDefault(X,Att)),[]).
rule(p2a_t(),prefer(r_t_conflictingOrigin(X,_Y,Att),r_t_attackOrigin(X,Att)),[]).
rule(p2b_t(),prefer(r_t_conflictingOrigin(_Y,X,Att),r_t_attackOrigin(X,Att)),[]).
rule(p3_t(),prefer(r_t_nonOrigin(X,Att),r_t_attackOrigin(X,Att)),[]).
rule(p4a_t(),prefer(r_t_srcIP1(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p4b_t(),prefer(r_t_srcIP2(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p5_t(),prefer(r_t_lang1(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p6_t(),prefer(r_t_lang2(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p7_t(),prefer(r_t_infra(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p8_t(),prefer(r_t_domain(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p9a_t(),prefer(r_t_spoofIP(X,Att),r_t_srcIP1(X,Att)),[]).
rule(p9b_t(),prefer(r_t_spoofIP(X,Att),r_t_srcIP2(X,Att)),[]).
rule(p10a_t(),prefer(r_t_highSkill1(Att),r_t_neghighSkill(Att)),[]).
rule(p10b_t(),prefer(r_t_highSkill2(Att),r_t_neghighSkill(Att)),[]).
rule(p10c_t(),prefer(r_t_highSkill4(Att),r_t_neghighSkill(Att)),[]).
rule(p11a_t(),prefer(r_t_highSkill3(Att),r_t_highSkill1(Att)),[]).
rule(p11b_t(),prefer(r_t_highSkill3(Att),r_t_highSkill2(Att)),[]).
rule(p11c_t(),prefer(r_t_highSkill3(Att),r_t_highSkill4(Att)),[]).
rule(p12a_t(),prefer(r_t_highResource1(Att),r_t_highResource0(Att)),[]).
rule(p12b_t(),prefer(r_t_highResource2(Att),r_t_highResource0(Att)),[]).
rule(p12c_t(),prefer(r_t_highResource3(Att),r_t_highResource0(Att)),[]).
rule(p13a_t(),prefer(r_t_IPdomain2(S,M),r_t_IPdomain1(S,M)),[]).
rule(p13b_t(),prefer(r_t_IPdomain3(S,M),r_t_IPdomain1(S,M)),[]).

rule(p14a_t(),prefer(r_t_similar(M1,M2),r_t_similarDefault(M1,M2)),[]).
rule(p14b_t(),prefer(r_t_simCC1(M1,M2),r_t_similarDefault(M1,M2)),[]).
rule(p14c_t(),prefer(r_t_simCC2(M1,M2),r_t_similarDefault(M1,M2)),[]).
rule(p14d_t(),prefer(r_t_simCC3(M1,M2),r_t_similarDefault(M1,M2)),[]).

% prefer
rule(p1a_op(),prefer(r_op_ecMotive(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p1b_op(),prefer(r_op_ecMotive(C,T),r_op_nonGeopolitics2(C,T)),[]).
rule(p2a_op(),prefer(r_op_conflict(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p2b_op(),prefer(r_op_conflict(C,T),r_op_nonGeopolitics2(C,T)),[]).
rule(p3a_op(),prefer(r_op_conflict1(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p3b_op(),prefer(r_op_conflict1(C,T),r_op_nonGeopolitics2(C,T)),[]).
rule(p4a_op(),prefer(r_op_pMotive(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p4b_op(),prefer(r_op_pMotive(C,T),r_op_nonGeopolitics2(C,T)),[]).
rule(p4c_op(),prefer(r_op_pMotive1(C,T,_D),r_op_nonGeopolitics1(C,T)),[]).
rule(p4d_op(),prefer(r_op_pMotive1(C,T,_D),r_op_nonGeopolitics2(C,T)),[]).
rule(p5_op(),prefer(r_op_claimResp1(X,Att),r_op_claimResp0(X,Att)),[]).
rule(p6_op(),prefer(r_op_noCapability2(X,Att), r_op_hasCapability1(X, Att)), []).

% pref
rule(p0a(),prefer(r_str__claimedResp(X,Att),r_str__noEvidence(X,Att)),[]). %With any evidence,we prefer to attribute the culprit accordingly
rule(p0b(),prefer(r_str__motiveAndCapability(X,Att),r_str__noEvidence(X,Att)),[]).
rule(p0c(),prefer(r_str__motive(X,Att),r_str__noEvidence(X,Att)),[]).
rule(p0d(),prefer(r_str__motiveAndLocation(X,Att),r_str__noEvidence(X,Att)),[]).
rule(p0e(),prefer(r_str__loc(X,Att),r_str__noEvidence(X,Att)),[]).
rule(p0f(),prefer(r_str__social(X,Att),r_str__noEvidence(X,Att)),[]).
rule(p0g(),prefer(r_str__linkedMalware(X,Att),r_str__noEvidence(X,Att)),[]).

rule(p1a(),prefer(r_str__motiveAndCapability(_X,Att),r_str__claimedResp(_Y,Att)),[]).   
rule(p1b(),prefer(r_str__motiveAndLocation(_X,Att),r_str__claimedResp(_Y,Att)),[]). 
rule(p1c(),prefer(r_str__motive(_X,Att),       r_str__claimedResp(_Y,Att)),[]). 
rule(p1d(),prefer(r_str__social(_X,Att),       r_str__claimedResp(_Y,Att)),[]). 
rule(p1e(),prefer(r_str__linkedMalware(_X,Att),r_str__claimedResp(_Y,Att)),[]). %group claiming responsibility might just be facade e.g. guardians of peace sonyhack

rule(p6(),prefer(r_str__noCapability(X,Att), r_str__claimedResp(X,Att)),[]). % hacker group might claim responsibility for attack backed by nation state
rule(p8(),prefer(r_str__noCapability(X,Att), r_str__motive(X,Att)),[]).    
rule(p9(),prefer(r_str__noCapability(X,Att), r_str__motiveAndLocation(X,Att)),[]).    
rule(p10(),prefer(r_str__noCapability(X,Att), r_str__loc(X,Att)),[]).  
rule(p11(),prefer(r_str__noCapability(X,Att),r_str__social(X,Att)),[]). % social evidences e.g. twitter posts/ emails can be easily forged
rule(p12(),prefer(r_str__noCapability(X,Att),r_str__linkedMalware(X,Att)),[]).

rule(p18(),prefer(r_str__linkedMalware(X,Att),r_str__negAttackOrigin(X,Att)),[]).

rule(p19(),prefer(r_str__negAttackOrigin(X,Att), r_str__motive(X,Att)),[]).
rule(p20(),prefer(r_str__weakAttack(X,Att),      r_str__motive(X,Att)),[]).

rule(p21a(),prefer(r_str__targetItself1(X,Att),r_str__claimedResp(X,Att)),        [specificTarget(Att)]).
rule(p21b(),prefer(r_str__targetItself1(X,Att),r_str__motiveAndCapability(X,Att)),[specificTarget(Att)]).
rule(p21c(),prefer(r_str__targetItself1(X,Att),r_str__motive(X,Att)),             [specificTarget(Att)]).
rule(p21d(),prefer(r_str__targetItself1(X,Att),r_str__motiveAndLocation(X,Att)),  [specificTarget(Att)]).
rule(p21e(),prefer(r_str__targetItself1(X,Att),r_str__loc(X,Att)),                [specificTarget(Att)]).
rule(p21f(),prefer(r_str__targetItself1(X,Att),r_str__social(X,Att)),             [specificTarget(Att)]).
rule(p21g(),prefer(r_str__targetItself1(X,Att),r_str__linkedMalware(X,Att)),      [specificTarget(Att)]).

rule(p22a(),prefer(r_str__targetItself2(X,Att),r_str__claimedResp(X,Att)),        [specificTarget(Att)]).
rule(p22b(),prefer(r_str__targetItself2(X,Att),r_str__motiveAndCapability(X,Att)),[specificTarget(Att)]).
rule(p22c(),prefer(r_str__targetItself2(X,Att),r_str__motive(X,Att)),             [specificTarget(Att)]).
rule(p22d(),prefer(r_str__targetItself2(X,Att),r_str__motiveAndLocation(X,Att)),  [specificTarget(Att)]).
rule(p22e(),prefer(r_str__targetItself2(X,Att),r_str__loc(X,Att)),                [specificTarget(Att)]).
rule(p22f(),prefer(r_str__targetItself2(X,Att),r_str__social(X,Att)),             [specificTarget(Att)]).
rule(p22g(),prefer(r_str__targetItself2(X,Att),r_str__linkedMalware(X,Att)),      [specificTarget(Att)]).


rule(p23a(),prefer(r_str__linkedMalware(X,Att),r_str__noHistory(X,Att)),[]).
rule(p23c(),prefer(r_str__linkedMalware(X,Att),r_str__noMotive(X,Att)),[]).
rule(p23d(),prefer(r_str__linkedMalware(X,Att),r_str__weakAttack(X,Att)),[]).