:- multifile rule/3.
%% :- multifile hasResources/1.
%% :- multifile target/2.


listCases([ us_bank_hack ,  apt1 ,  gaussattack ,  stuxnetattack ,  sonyhack ,  wannacryattack ]).
case(X) :- listCases(L), member(X, L).

% us bank hack evidences
% rule(case1_f1, hasResources( iran ), []).
rule(case1_f2, target( usa ,  us_bank_hack ), []).
rule(case1_f3, imposedSanctions( usa ,  iran ), []).
rule(case1_f4, hijackCorporateClouds( us_bank_hack ), []).
rule(case1_f5, sophisticatedMalware( itsoknoproblem ), []).
rule(case1_f6, malwareUsedInAttack( itsoknoproblem ,  us_bank_hack ), []).
rule(case1_f7, attackYear( us_bank_hack , 2012), []).

% APT1
rule(case2_f1, majorityIpOrigin( china , apt1 ), []).
rule(case2_f2, sysLanguage(chinese, apt1 ), []).
rule(case2_f3, firstLanguage(chinese, china ), []).
rule(case2_f4, infraRegisteredIn( china , infra ), []).
rule(case2_f5, infraUsed( infra , apt1 ), []).
rule(case2_f6, hasEconomicMotive( china , infocomm ), []).
rule(case2_f7, industry( infocomm ,victim), []).
rule(case2_f8, target(victim, apt1 ), []).
rule(case2_f9, largeNumberOfVictims( apt1 ), []).
rule(case2_f10, highVolumeAttack( apt1 ), []).
rule(case2_f11, longDurationAttack( apt1 ), []).
rule(case2_f12, geolocatedInGovFacility( superhard , china ), []).
rule(case2_f13, publicCommentsRelatedToGov( dota , china ), []).
rule(case2_f14, identifiedIndividualInAttack( superhard , apt1 ), []).
rule(case2_f15, identifiedIndividualInAttack( dota , apt1 ), []).

%  gauss 
rule(case3_f1, sophisticatedMalware( gauss ), []).
rule(case3_f2, malwareUsedInAttack( gauss , gaussattack ), []).
rule(case3_f7, target( middleEast , gaussattack ), []).
rule(case3_f8, target( israel , gaussattack ), []).
rule(case3_f9, target( lebanon , gaussattack ), []).
rule(case3_f10, target( palestine , gaussattack ), []).
rule(case3_f12, infectionMethod( usb , gauss ), []).
rule(case3_f13, controlAndCommandEasilyFingerprinted( gauss ), []).
rule(case3_f14, hasPoliticalMotive( usa , iran ), []).
rule(case3_f15, hasPoliticalMotive( israel , iran ), []).
rule(case3_f16, ccServer( gowin7 ,  gauss ), []).
rule(case3_f17, ccServer( secuurity ,  gauss ), []).
rule(case3_f18, domainRegisteredDetails( gowin7 ,  adolph_dybevek ,  prinsen_gate_6 ), []).
rule(case3_f19, domainRegisteredDetails( secuurity ,  adolph_dybevek ,  prinsen_gate_6 ), []).
rule(case3_f20, addressType( prinsen_gate_6 ,  hotel ), []).

%  stuxnet 
rule(case4_f0, industry( nuclear ,stuxnet_victim), []).
rule(case4_f1, target(stuxnet_victim, stuxnetattack ), []).
rule(case4_f2, infectionMethod( usb , stuxnetattack ), []).
rule(case4_f3, spreadingMechanism( localNetwork , stuxnetattack ), []).
rule(case4_f4, stolenValidSignedCertificates( stuxnetattack ), []).
rule(case4_f6, target( iran , stuxnetattack ), []).
rule(case4_f7, usesZeroDayVulnerabilities( stuxnet ), []).
rule(case4_f8, recentNewsInYear( nuclearProgram ,  iran , 2010), []).
rule(case4_f9, causeOfConflict([ usa ,  israel ],  iran ,  nuclearProgram ), []).
rule(case4_f10, attackYear( stuxnetattack , 2010), []).
rule(case4_f11, malwareUsedInAttack( stuxnet ,  stuxnetattack ), []).
rule(case4_f12, specificConfigInMalware( stuxnet ), []).

%  sony 
rule(case5_f1, claimedResponsibility( guardiansOfPeace ,  sonyhack ), []).
rule(case5_f2, target( sony ,  sonyhack ), []).
rule(case5_f3, recentNewsInYear( theInterview ,  sony , 2014), []).
rule(case5_f4, attackYear( sonyhack , 2014), []).
rule(case5_f5, causeOfConflict( northkorea ,  sony ,  theInterview ), []).
rule(case5_f6, majorityIpOrigin( northkorea ,  sonyhack ), []).
rule(case5_f7, malwareUsedInAttack( trojanVolgmer ,  sonyhack ), []).
rule(case5_f8, malwareUsedInAttack( backdoorDestover ,  sonyhack ), []).

%  wannacry 
rule(case6_f1, malwareUsedInAttack( wannacry ,  wannacryattack ), []).
rule(case6_f2, malwareUsedInAttack( trojanAlphanc ,  wannacryattack ), []).
rule(case6_f3, malwareModifiedFrom( trojanAlphanc ,  backdoorDuuzer ), []).
rule(case6_f5, malwareUsedInAttack( trojanBravonc ,  wannacryattack ), []).
rule(case6_f6, similarCodeObfuscation( backdoorBravonc ,  infostealerFakepude ), []).
rule(case6_f7, sharedCode( wannacry ,  backdoorCantopee ), []).
rule(case6_f8, attackYear( wannacryattack , 2017), []).
