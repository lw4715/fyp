:- multifile rule/3.

% us bank hack evidences
rule(f1, hasResources(iran), []).
rule(f2, target(usa, us_bank_hack), []).
rule(f3, imposedSanctions(usa, iran), []).
rule(f4, hijackCorporateClouds(us_bank_hack), []).
rule(f5, sophisticatedMalware(itsoknoproblem), []).
rule(f6, malwareUsedInAttack(itsoknoproblem, us_bank_hack), []).

% APT1
rule(f1, majorityIpOrigin(china,apt1), []).
rule(f2, sysLanguage(chinese,apt1), []).
rule(f3, firstLanguage(chinese,china), []).
rule(f4, infraRegisteredIn(china,infra), []).
rule(f5, infraUsed(infra,apt1), []).
rule(f6, hasEconomicMotive(china,infocomm), []).
rule(f7, industry(infocomm,victim), []).
rule(f8, target(victim,apt1), []).
rule(f9, largeNumberOfVictims(apt1), []).
rule(f10, highVolumeAttack(apt1), []).
rule(f11, longDurationAttack(apt1), []).
rule(f12, geolocatedInGovFacility(superhard,china), []).
rule(f13, publicCommentsRelatedToGov(dota,china), []).
rule(f14, identifiedIndividualInAttack(superhard,apt1), []).
rule(f15, identifiedIndividualInAttack(dota,apt1), []).

% Gauss
% rule(f0, similar(gauss, flame), []).
rule(f1, sophisticatedMalware(gauss), []).
rule(f2, malwareUsedInAttack(gauss,gauss), []).
% rule(f4, malwareUsedInAttack(flame,flameattack), []).
% rule(f6, isCulprit(equationGroup,flameattack), []).
rule(f7, target(middleEast,gaussattack), []).
rule(f8, target(israel,gaussattack), []).
rule(f9, target(lebanon,gaussattack), []).
rule(f10, target(palestine,gaussattack), []).
% rule(f11, target(middleeast,flameattack), []).
rule(f12, infectionMethod(usb,gauss), []).
rule(f13, controlAndCommandEasilyFingerprinted(gauss), []).
rule(f14, hasPoliticalMotive(usa,iran), []).
rule(f15, hasPoliticalMotive(israel,iran), []).
rule(f16, ccServer(gowin7, gauss), []).
rule(f17, ccServer(secuurity, gauss), []).
rule(f18, domainRegisteredDetails(gowin7, "adolph dybevek", "prinsen gate 6"), []).
rule(f19, domainRegisteredDetails(secuurity, "adolph dybevek", "prinsen gate 6"), []).
rule(f20, addressType("prinsen gate 6", hotel), []).
% rule(f21, ccServer(gowin7, flame), []).
% rule(f22, ccServer(secuurity, flame), []).

% stuxnet
rule(f0, industry(nuclear,stuxnet_victim), []).
rule(f1, target(stuxnet_victim,stuxnetattack), []).
rule(f2, infectionMethod(usb,stuxnetattack), []).
rule(f3, spreadingMechanism(localNetwork,stuxnetattack), []).
rule(f4, stolenValidSignedCertificates(stuxnetattack), []).
rule(f6, target(iran,stuxnetattack), []).
rule(f7, usesZeroDayVulnerabilities(stuxnet), []).
rule(f8, recentNewsInYear(nuclearProgram,iran, 2010), []).
rule(f9, countriesAgainstTargetForReason([usa, israel], iran, nuclearProgram), []).
rule(f11, malwareUsedInAttack(stuxnet, stuxnetattack), []).
rule(f10, attackYear(stuxnetattack, 2010), []).
