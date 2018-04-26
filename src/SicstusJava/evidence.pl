:- multifile rule/3.
%% :- multifile hasResources/1.
%% :- multifile target/2.


listCases([ us_bank_hack ,  apt1 ,  gaussattack ,  stuxnetattack ,  sonyhack ,  wannacryattack ]).
case(X) :- listCases(L), member(X, L).

% us bank hack evidences
rule(case1_f1, target( usa ,  us_bank_hack ), []).
%% rule(case1_f2, targetCountry( usa ,  us_bank_hack ), []).
rule(case1_f3, imposedSanctions( usa ,  iran ), []).
rule(case1_f4, hijackCorporateClouds( us_bank_hack ), []).
rule(case1_f5, sophisticatedMalware( itsoknoproblembro ), []).
rule(case1_f6, malwareUsedInAttack( itsoknoproblembro ,  us_bank_hack ), []).
rule(case1_f7, attackYear( us_bank_hack , 2012), []).

% APT1
rule(case2_f1, majorityIpOrigin( china , apt1 ), []).
rule(case2_f2, sysLanguage(chinese, apt1 ), []).
rule(case2_f3, firstLanguage(chinese, china ), []).
rule(case2_f4, infraRegisteredIn( china , apt1_infra ), []).
rule(case2_f5, infraUsed( apt1_infra , apt1 ), []).
rule(case2_f6, hasEconomicMotive( china , infocomm ), []).
rule(case2_f7, industry( infocomm ,victims), []).
rule(case2_f8, target(victims, apt1 ), []).
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
%% rule(case3_f20, addressType( prinsen_gate_6 ,  hotel ), []).

%  stuxnet 
rule(case4_f0, industry( nuclear ,iranian_org), []).
rule(case4_f1, target(iranian_org, stuxnetattack ), []).
rule(case4_f2, infectionMethod( usb , stuxnetattack ), []).
rule(case4_f3, spreadingMechanism( localNetwork , stuxnetattack ), []).
rule(case4_f4, stolenValidSignedCertificates( stuxnetattack ), []).
rule(case4_f6, targetCountry( iran , stuxnetattack ), []).
rule(case4_f7, usesZeroDayVulnerabilities( stuxnet ), []).
rule(case4_f8, recentNewsInYear( nuclear ,  iran , 2010), []).
rule(case4_f9, causeOfConflict(usa,  iran ,  nuclear ), []).
rule(case4_f10, causeOfConflict(israel,  iran ,  nuclear ), []).
rule(case4_f11, attackYear( stuxnetattack , 2010), []).
rule(case4_f12, malwareUsedInAttack( stuxnet ,  stuxnetattack ), []).
rule(case4_f13, specificConfigInMalware( stuxnet ), []).
rule(case4_f14, infectionMethod( usb , stuxnet ), []).


%  sony 
rule(case5_f1, claimedResponsibility( guardiansOfPeace ,  sonyhack ), []).
rule(case5_f2, target( sony ,  sonyhack ), []).
rule(case5_f3, targetCountry( usa ,  sonyhack ), []).
rule(case5_f4, recentNewsInYear( theInterview ,  sony , 2014), []).
rule(case5_f5, attackYear( sonyhack , 2014), []).
rule(case5_f6, causeOfConflict( northkorea ,  sony ,  theInterview ), []).
rule(case5_f7, majorityIpOrigin( northkorea ,  sonyhack ), []).
rule(case5_f8, malwareUsedInAttack( trojanVolgmer ,  sonyhack ), []).
rule(case5_f9, malwareUsedInAttack( backdoorDestover ,  sonyhack ), []).

%  wannacry 
rule(case6_f1, malwareUsedInAttack( wannacry ,  wannacryattack ), []).
rule(case6_f2, malwareUsedInAttack( trojanAlphanc ,  wannacryattack ), []).
rule(case6_f3, malwareModifiedFrom( trojanAlphanc ,  backdoorDuuzer ), []).
rule(case6_f5, malwareUsedInAttack( trojanBravonc ,  wannacryattack ), []).
rule(case6_f6, similarCodeObfuscation( backdoorBravonc ,  infostealerFakepude ), []).
rule(case6_f7, sharedCode( wannacry ,  backdoorCantopee ), []).
rule(case6_f8, attackYear( wannacryattack , 2017), []).
rule(case6_f9, neg(specificTarget(wannacryattack)), []).
rule(case6_f10, hasKillSwitch(wannacry), []).
rule(case6_f10, numComputersAffected(wannacryattack, 200000), []).
rule(case6_f10, numCountriesAffected(wannacryattack, 100), []).
%% rule(8, hasKillSwitch(wannacry), []).
%% rule(9, type(wannacry,ransomware), []).
%% rule(10, propagationMechanism(wannacry,self_propagating), []).
%% rule(11, scale(wannacryattack,large), []).
%% rule(12, exploitVul('EternalBlue'), []).
%% rule(13, vulPatched('EternalBlue'), []).
%% rule(14, vulReleased(14,4,17,'EternalBlue'), []).
%% rule(15, dateOfAttack(12,5,17,wannacryattack), []).
%% rule(16, ccCommunicationChannel(tor), []).

%% rule(case6_f10, , []).
%% rule(case6_f10, , []).
%% rule(case6_f10, , []).


% DNC intrusion, expected culprits: fancyBear, cozyBear, russia
%% http://time.com/4600177/election-hack-russia-hillary-clinton-donald-trump/
%% http://time.com/4597457/the-downside-of-donald-trumps-fight-with-the-intelligence-community/
%% rule(case7_f1, claimedResponsibility('Guccifer2.0', dnc_hack), []).


rule(bg_dummy1, country(myCountry),[]).
rule(bg_dummy2, country(yourCountry),[]).
rule(bg_dummy3, country(hisCountry),[]).

%% dummy0
%% expected: 
%% randomGroup (claimResp)
rule(case_dummy0_f1, claimedResponsibility(randomGroup, dummy0), []).

%% dummy1 
%% expected: 
%% randomGroup (claimResp)
%% yourCountry (loc,linkedMalware)
rule(case_dummy1_f1, claimedResponsibility(randomGroup, dummy1), []).
rule(case_dummy1_f2, targetCountry(myCountry, dummy1), []).
rule(case_dummy1_f3, malwareUsedInAttack(dummy1_m1, dummy1), []).
rule(case_dummy1_f4, simlarCodeObfuscation(dummy1_m1, dummy1_m2), []).
rule(case_dummy1_f5, malwareLinkedTo(dummy1_m2, yourCountry), []).
rule(case_dummy1_f8, hasMotive(yourCountry,dummy1), []).
rule(case_dummy1_f9, attackSourceIP(dummy1_ip, dummy1), []).
rule(case_dummy1_f10, ipGeoloc(yourCountry, dummy1_ip), []).

%% dummy2
%% expected: 
%% randomGroup (claimResp)
%% yourCountry is the only target, assume attacker won't target itself 
rule(case_dummy2_f1, claimedResponsibility(randomGroup, dummy2), []).
rule(case_dummy2_f2, targetCountry(yourCountry, dummy2), []).
rule(case_dummy2_f3, malwareUsedInAttack(dummy2_m1, dummy2), []).
rule(case_dummy2_f4, simlarCodeObfuscation(dummy2_m1, dummy2_m2), []).
rule(case_dummy2_f5, malwareLinkedTo(dummy2_m2, yourCountry), []).
rule(case_dummy2_f8, hasMotive(yourCountry,dummy2), []).
rule(case_dummy2_f9, attackSourceIP(dummy2_ip, dummy2), []).
rule(case_dummy2_f10, ipGeoloc(yourCountry, dummy2_ip), []).

%% dummy2b
%% expected: 
%% randomGroup (claimResp)
%% yourCountry is the only target, assume attacker won't target itself 
rule(case_dummy2b_f1, claimedResponsibility(randomGroup, dummy2b), []).
rule(case_dummy2b_f2, targetCountry(yourCountry, dummy2b), []).
rule(case_dummy2b_f2b, targetCountry(myCountry, dummy2b), []).
rule(case_dummy2b_f3, malwareUsedInAttack(dummy2b_m1, dummy2b), []).
rule(case_dummy2b_f4, simlarCodeObfuscation(dummy2b_m1, dummy2b_m2), []).
rule(case_dummy2b_f5, malwareLinkedTo(dummy2b_m2, yourCountry), []).
rule(case_dummy2b_f8, hasMotive(yourCountry,dummy2b), []).
rule(case_dummy2b_f9, attackSourceIP(dummy2b_ip, dummy2b), []).
rule(case_dummy2b_f10, ipGeoloc(yourCountry, dummy2b_ip), []).

%% dummy3
%% expected: 
%% randomGroup (claimResp)
%% more than one ipgeolocation doesnt give location information about attack 
rule(case_dummy3_f1, claimedResponsibility(randomGroup, dummy3), []).
rule(case_dummy3_f2, targetCountry(yourCountry, dummy3), []).
rule(case_dummy3_f3, malwareUsedInAttack(dummy3_m1, dummy3), []).
rule(case_dummy3_f4, simlarCodeObfuscation(dummy3_m1, dummy3_m2), []).
rule(case_dummy3_f5, malwareLinkedTo(dummy3_m2, yourCountry), []).
rule(case_dummy3_f8, hasMotive(yourCountry,dummy3), []).
rule(case_dummy3_f9, attackSourceIP(dummy3_ip, dummy3), []).
rule(case_dummy3_f10, ipGeoloc(yourCountry, dummy3_ip), []).
rule(case_dummy3_f12, attackSourceIP(dummy3_ip1, dummy3), []).
rule(case_dummy3_f13, ipGeoloc(hisCountry, dummy3_ip1), []).




