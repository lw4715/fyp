:- multifile rule/3.

% us bank hack evidences
%% expected: iran (hasMotive)
%% https://www.aljazeera.com/news/middleeast/2012/02/20122616342323385.html
rule(case1_f1(),targetCountry(united_states_of_america, usbankhack),[]).
rule(case1_f3(),imposedSanctions(united_states_of_america,iran,[2012,2]),[]).
rule(case1_f4(),hijackCorporateClouds(usbankhack),[]).
rule(case1_f5(),sophisticatedMalware(itsoknoproblembro),[]).
rule(case1_f6(),malwareUsedInAttack(itsoknoproblembro, usbankhack),[]).
rule(case1_f7(),attackPeriod(usbankhack,[2012,9]),[]).
rule(case1_f7(),target(us_banks, usbankhack),[]).
rule(case1_f8(),industry(banking, us_banks),[]).


% APT1
%% expected: china (social,location,hasMotive)
rule(case2_f1(),majorityIpOrigin(china,apt1),[]).
rule(case2_f2(),sysLanguage(chinese,apt1),[]).
rule(case2_f3(),firstLanguage(chinese,china),[]).
rule(case2_f4(),infraRegisteredIn(china,apt1_infra),[]).
rule(case2_f5(),infraUsed(apt1_infra,apt1),[]).
rule(case2_f6(),hasEconomicMotive(china,infocomm),[]).
rule(case2_f7(),industry(infocomm,victims),[]).
rule(case2_f8(),target(victims,apt1),[]).
rule(case2_f9(),largeNumberOfVictims(apt1),[]).
rule(case2_f10(),highVolumeAttack(apt1),[]).
rule(case2_f11(),longDurationAttack(apt1),[]).
rule(case2_f12(),geolocatedInGovFacility(superhard,china),[]).
rule(case2_f13(),publicCommentsRelatedToGov(dota,china),[]).
rule(case2_f14(),identifiedIndividualInAttack(superhard,apt1),[]).
rule(case2_f15(),identifiedIndividualInAttack(dota,apt1),[]).

%  gauss 
%% https://www.computerworld.com/article/2597456/security0/gauss-malware--nation-state-cyber-espionage-banking-trojan-related-to-flame--stuxnet.html
%% expected: equationGroup (linkedMalware)
%% online banking Trojan functionality. The ability to steal online banking credentials is something we havent previously seen in nation-state sponsored malware attacks
rule(case3_f1(),sophisticatedMalware(gauss),[]).
rule(case3_f2(),malwareUsedInAttack(gauss,gaussattack),[]).
rule(case3_f7(),targetCountry(middleEast,gaussattack),[]).
rule(case3_f9(),targetCountry(lebanon,gaussattack),[]). % Note: other countries were attacked too,but focus is on lebanon
rule(case3_f12(),infectionMethod(usb,gauss),[]).
rule(case3_f13(),commandAndControlEasilyFingerprinted(gauss),[]).
rule(case3_f16(),ccServer(gowin7, gauss),[]).
rule(case3_f17(),ccServer(secuurity, gauss),[]).
rule(case3_f18(),domainRegisteredDetails(gowin7, adolph_dybevek, prinsen_gate_6),[]).
rule(case3_f19(),domainRegisteredDetails(secuurity, adolph_dybevek, prinsen_gate_6),[]).
rule(case3_f20(),attackPeriod(gaussattack,[2011,9]),[]).

%  stuxnet 
%% expected: united_states_of_america,israel (hasMotive,hasCapability)
rule(case4_f0(),industry(nuclear,iranian_org),[]).
rule(case4_f1(),target(iranian_org,stuxnetattack),[]).
rule(case4_f2(),infectionMethod(usb,stuxnetattack),[]).
rule(case4_f3(),spreadingMechanism(localNetwork,stuxnetattack),[]).
rule(case4_f4(),stolenValidSignedCertificates(stuxnetattack),[]).
rule(case4_f6(),targetCountry(iran,stuxnetattack),[]).
rule(case4_f7(),usesZeroDayVulnerabilities(stuxnet),[]).
rule(case4_f8(),news(nuclear,iran,ongoing),[]).
rule(case4_f9(),causeOfConflict(united_states_of_america, iran, nuclear),[]).
rule(case4_f10(),causeOfConflict(israel, iran, nuclear),[]).
rule(case4_f11(),attackPeriod(stuxnetattack,[2010,7]),[]).
rule(case4_f12(),malwareUsedInAttack(stuxnet, stuxnetattack),[]).
rule(case4_f13(),specificConfigInMalware(stuxnet),[]).
rule(case4_f14(),infectionMethod(usb,stuxnet),[]).
rule(case4_f15(),target(iran_nuclear_facilities, stuxnetattack),[]).
rule(case4_f16(),industry(nuclear, iran_nuclear_facilities),[]).


%  sony 
%% expected: guardiansOfPeace (claimResponsibility),north_korea (hasMotive,location)
rule(case5_f1(),claimedResponsibility(guardiansOfPeace, sonyhack),[]).
rule(case5_f2(),target(sony, sonyhack),[]).
rule(case5_f3(),targetCountry(united_states_of_america, sonyhack),[]).
rule(case5_f4(),news(theInterview, sony,[2013,10]),[]).
rule(case5_f5(),attackPeriod(sonyhack,[2014,11]),[]).
rule(case5_f6(),causeOfConflict(north_korea, sony, theInterview),[]).
rule(case5_f7(),majorityIpOrigin(north_korea, sonyhack),[]).
rule(case5_f8(),malwareUsedInAttack(trojanVolgmer, sonyhack),[]).
rule(case5_f9(),malwareUsedInAttack(backdoorDestover, sonyhack),[]).

%  wannacry 
%% expected: lazarusGrp (linkedMalware)
rule(case6_f1(),malwareUsedInAttack(wannacry, wannacryattack),[]).
rule(case6_f2(),malwareUsedInAttack(trojanAlphanc, wannacryattack),[]).
rule(case6_f3(),malwareModifiedFrom(trojanAlphanc, backdoorDuuzer),[]).
rule(case6_f5(),malwareUsedInAttack(trojanBravonc, wannacryattack),[]).
rule(case6_f6(),similarCodeObfuscation(backdoorBravonc, infostealerFakepude),[]).
rule(case6_f7(),sharedCode(wannacry, backdoorCantopee),[]).
rule(case6_f8(),attackPeriod(wannacryattack,[2017,5]),[]).
rule(case6_f9(),neg(specificTarget(wannacryattack)),[]).
rule(case6_f10(),target(nhs,wannacryattack),[]).
rule(case6_f11(),targetCountry(united_kingdom,wannacryattack),[]).
%% rule(case6_f10(),hasKillSwitch(wannacry),[]).
%% rule(case6_f10(),numComputersAffected(wannacryattack,200000),[]).
%% rule(case6_f10,numCountriesAffected(wannacryattack,100),[]).


% DNC intrusion,expected culprits: fancyBear,cozyBear,russia
%% http://time.com/4600177/election-hack-russia-hillary-clinton-donald-trump/
%% http://time.com/4597457/the-downside-of-donald-trumps-fight-with-the-intelligence-community/
%% rule(case7_f1,claimedResponsibility('Guccifer2.0',dnc_hack),[]).





%% example0
%% expected: 
%% randomGroup (claimResp)
rule(case_example0_f1(),claimedResponsibility(randomGroup,example0),[]).

%% example1 
%% expected: 
%% randomGroup (claimResp)
%% yourCountry (motive and location,linkedMalware)
rule(case_example1_f1(),claimedResponsibility(randomGroup,example1),[]).
rule(case_example1_f1a(),malwareUsedInAttack(example1m,example1),[]).
rule(case_example1_f2(),targetCountry(myCountry,example1),[]).
rule(case_example1_f3(),malwareUsedInAttack(example1_m1,example1),[]).
rule(case_example1_f4(),simlarCodeObfuscation(example1_m1,example1_m2),[]).
rule(case_example1_f5(),malwareLinkedTo(example1_m2,yourCountry),[]).
rule(case_example1_f8(),hasMotive(yourCountry,example1),[]).
rule(case_example1_f9(),attackSourceIP([123,123,123,102],example1m),[]).
rule(case_example1_f10(),ipGeoloc(yourCountry,[123,123,123,102]),[]).
rule(case_example1_f11(),ip([123,123,123,102]),[]).

%% example2
%% expected: 
%% randomGroup (claimResp)
%% yourCountry is the only target,assume attacker won't target itself 
rule(case_example2_f1(),claimedResponsibility(randomGroup,example2),[]).
rule(case_example2_f1a(),malwareUsedInAttack(example2m,example2),[]).
rule(case_example2_f2(),targetCountry(yourCountry,example2),[]).
rule(case_example2_f3(),malwareUsedInAttack(example2_m1,example2),[]).
rule(case_example2_f4(),simlarCodeObfuscation(example2_m1,example2_m2),[]).
rule(case_example2_f5(),malwareLinkedTo(example2_m2,yourCountry),[]).
rule(case_example2_f8(),hasMotive(yourCountry,example2),[]).
rule(case_example2_f9(),attackSourceIP([123,123,123,100],example2m),[]).
rule(case_example2_f10(),ipGeoloc(yourCountry,[123,123,123,100]),[]).
rule(case_example2_f11(),ip([123,123,123,100]),[]).

%% example2b
%% expected: 
%% randomGroup (claimResp)
%% yourCountry
%% (yourCountry is not the only target => not specific attack => yourCountry might be culprit) 
rule(case_example2b_f1(),claimedResponsibility(randomGroup,example2b),[]).
rule(case_example2b_f1a(),malwareUsedInAttack(example2bm,example2b),[]).
rule(case_example2b_f2(),targetCountry(yourCountry,example2b),[]).
rule(case_example2b_f2b(),targetCountry(myCountry,example2b),[]).
rule(case_example2b_f3(),malwareUsedInAttack(example2b_m1,example2b),[]).
rule(case_example2b_f4(),simlarCodeObfuscation(example2b_m1,example2b_m2),[]).
rule(case_example2b_f5(),malwareLinkedTo(example2b_m2,yourCountry),[]).
rule(case_example2b_f8(),hasMotive(yourCountry,example2b),[]).
rule(case_example2b_f9(),attackSourceIP([123,123,123,125],example2bm),[]).
rule(case_example2b_f10(),ipGeoloc(yourCountry,[123,123,123,125]),[]).
rule(case_example2b_f11(),ip([123,123,123,125]),[]).

%% example3
%% expected: 
%% randomGroup (claimResp)
%% targetItself is preferred over linkedMalware
%% more than one ipgeolocation doesnt give location information about attack 
rule(case_example3_f1(),claimedResponsibility(randomGroup,example3),[]).
rule(case_example3_f1(),malwareUsedInAttack(example3m,example3),[]).
rule(case_example3_f2(),targetCountry(yourCountry,example3),[]).
rule(case_example3_f3(),malwareUsedInAttack(example3_m1,example3),[]).
rule(case_example3_f4(),simlarCodeObfuscation(example3_m1,example3_m2),[]).
rule(case_example3_f5(),malwareLinkedTo(example3_m2,yourCountry),[]).
rule(case_example3_f8(),hasMotive(yourCountry,example3),[]).
rule(case_example3_f9(),attackSourceIP([123,123,123,123],example3),[]).
rule(case_example3_f10(),ipGeoloc(yourCountry,[123,123,123,123]),[]).
rule(case_example3_f12(),attackSourceIP([103,1,206,109],example3m),[]).
rule(case_example3_f13(),ipGeoloc(hisCountry,[103,1,206,109]),[]).
rule(case_example3_f14(),ip([123,123,123,123]),[]).
rule(case_example3_f15(),ip([103,1,206,109]),[]).



%% example4
%% expected: 
%% yourCountry (location)
rule(case_example4_f1(),claimedResponsibility(yourCountry,example4),[]).
rule(case_example4_f1(),malwareUsedInAttack(example4m,example4),[]).
rule(case_example4_f2(),noPriorHistory(yourCountry),[]).
rule(case_example4_f3(),hasResources(yourCountry),[]).
rule(case_example4_f4(),neg(requireHighResource(example4)),[]).
rule(case_example4_f5(),ipGeoloc(yourCountry,[103,5,206,109]),[]).
rule(case_example4_f6(),attackSourceIP([103,5,206,109],example4m),[]).
rule(case_example4_f7(),ip([103,5,206,109]),[]).

%% governmentLinked(P,C),identifiedIndividualInAttack(P,Att)

%% example5
%% exptected: someGroup
%% torIP([103,1,206,100]) is true, 103.1.206.100 is a spoofed IP
rule(case_example5_f1(),claimedResponsibility(someGroup,example5),[]).
rule(case_example5_f1a(),malwareUsedInAttack(example5m,example5),[]).
rule(case_example5_f2(),ipGeoloc(yourCountry,[103,1,206,101]),[]).
rule(case_example5_f3(),attackSourceIP([103,1,206,101],example5m),[]).
rule(case_example5_f4(),ip([103,1,206,101]),[]).

%% example6
rule(case_example6_f1(),attackSourceIP([69,195,124,58],test),[]).
rule(case_example6_f2(),targetServerIP([173,194,36,104],test),[]).
rule(case_example6_f3(),ip([69,195,124,58]),[]).
rule(case_example6_f4(),ip([173,194,36,104]),[]).

%% example7
%% expected: 
%% yourCountry
rule(case_example7_f1a(),malwareUsedInAttack(example7m,example7),[]).
rule(case_example7_f2b(),targetCountry(myCountry,example7),[]).
rule(case_example7_f3(),malwareUsedInAttack(example7_m1,example7),[]).
rule(case_example7_f4(),simlarCodeObfuscation(example7_m1,example7_m2),[]).
rule(case_example7_f5(),malwareLinkedTo(example7_m2,yourCountry),[]).



