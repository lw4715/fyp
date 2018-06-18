:- multifile rule/3.

% us bank hack evidences
%% expected: iran (hasMotive)
%% https://www.aljazeera.com/news/middleeast/2012/02/20122616342323385.html
rule(case1_f1(),targetCountry(united_states, usbankhack),[]).
rule(case1_f3(),imposedSanctions(united_states,iran,[2012,2]),[]).
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
%% expected: united_states,israel (hasMotive,hasCapability)
rule(case4_f0(),industry(nuclear,iranian_org),[]).
rule(case4_f1(),target(iranian_org,stuxnetattack),[]).
%% rule(case4_f2(),infectionMethod(usb,stuxnetattack),[]).
%% rule(case4_f3(),spreadingMechanism(localNetwork,stuxnetattack),[]).
rule(case4_f6(),targetCountry(iran,stuxnetattack),[]).
rule(case4_f7(),usesZeroDayVulnerabilities(stuxnet),[]).
rule(case4_f8(),news(nuclear,iran,ongoing),[]).
rule(case4_f9(),causeOfConflict(united_states, iran, nuclear),[]).
rule(case4_f10(),causeOfConflict(israel, iran, nuclear),[]).
rule(case4_f11(),attackPeriod(stuxnetattack,[2010,7]),[]).
rule(case4_f12(),malwareUsedInAttack(stuxnet, stuxnetattack),[]).
rule(case4_f13(),specificConfigInMalware(stuxnet),[]).
rule(case4_f14(),infectionMethod(usb,stuxnet),[]).


%  sony 
%% expected: guardiansOfPeace (claimResponsibility),north_korea (hasMotive,location)
rule(case5_f1(),claimedResponsibility(guardiansOfPeace, sonyhack),[]).
rule(case5_f2(),target(sony, sonyhack),[]).
rule(case5_f3(),targetCountry(united_states, sonyhack),[]).
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
%% countryX (motive and location,linkedMalware)
rule(case_example1_f1(),claimedResponsibility(randomGroup, example1),[]).
rule(case_example1_f2(),malwareUsedInAttack(example1_m1, example1),[]).
rule(case_example1_f3(),simlarCodeObfuscation(example1_m1, example1_m2),[]).
rule(case_example1_f4(),malwareLinkedTo(example1_m2, countryX),[]).
rule(case_example1_f5(),hasMotive(countryX, example1),[]).
rule(case_example1_f6(),attackSourceIP([123,123,123,102], example1),[]).
rule(case_example1_f7(),ipGeoloc(countryX, [123,123,123,102]),[]).
%% rule(case_example1_f1(),claimedResponsibility(randomGroup,example1),[]).
%% rule(case_example1_f1a(),malwareUsedInAttack(example1m,example1),[]).
%% rule(case_example1_f2(),targetCountry(countryY,example1),[]).
%% rule(case_example1_f3(),malwareUsedInAttack(example1_m1,example1),[]).
%% rule(case_example1_f4(),simlarCodeObfuscation(example1_m1,example1_m2),[]).
%% rule(case_example1_f5(),malwareLinkedTo(example1_m2,countryX),[]).
%% rule(case_example1_f8(),hasMotive(countryX,example1),[]).
%% rule(case_example1_f9(),attackSourceIP([123,123,123,102],example1),[]).
%% rule(case_example1_f10(),ipGeoloc(countryX,[123,123,123,102]),[]).
%% rule(case_example1_f11(),ip([123,123,123,102]),[]).

%% example1b
%% expected: 
%% randomGroup (claimResp)
%% countryX is the only target,assume attacker won't target itself 
rule(case_example1b_f1(),claimedResponsibility(randomGroup,example1b),[]).
rule(case_example1b_f2(),malwareUsedInAttack(example1b_m1,example1b),[]).
rule(case_example1b_f3(),simlarCodeObfuscation(example1b_m1,example1b_m2),[]).
rule(case_example1b_f4(),malwareLinkedTo(example1b_m2,countryX),[]).
rule(case_example1b_f5(),hasMotive(countryX,example1b),[]).
rule(case_example1b_f6(),attackSourceIP([123,123,123,102],example1b),[]).
rule(case_example1b_f7(),ipGeoloc(countryX,[123,123,123,102]),[]).
%% added evidence
rule(case_example1b_f8(),targetCountry(countryX,example1b),[]).

%% rule(case_example1_f7(),ipGeoloc(countryX,[123,123,123,102]),[]).
%% rule(case_example1b_f1(),claimedResponsibility(randomGroup,example1b),[]).
%% rule(case_example1b_f1a(),malwareUsedInAttack(example1bm,example1b),[]).
%% rule(case_example1b_f2(),targetCountry(countryX,example1b),[]).
%% rule(case_example1b_f3(),malwareUsedInAttack(example1b_m1,example1b),[]).
%% rule(case_example1b_f4(),simlarCodeObfuscation(example1b_m1,example1b_m2),[]).
%% rule(case_example1b_f5(),malwareLinkedTo(example1b_m2,countryX),[]).
%% rule(case_example1b_f8(),hasMotive(countryX,example1b),[]).
%% rule(case_example1b_f9(),attackSourceIP([123,123,123,100],example1b),[]).
%% rule(case_example1b_f10(),ipGeoloc(countryX,[123,123,123,100]),[]).
%% rule(case_example1b_f11(),ip([123,123,123,100]),[]).

%% example1c
%% expected: 
%% randomGroup (claimResp)
%% countryX
%% (countryX is not the only target => not specific attack => countryX might be culprit) 
rule(case_example1c_f1(),claimedResponsibility(randomGroup, example1c),[]).
rule(case_example1c_f2(),malwareUsedInAttack(example1c_m1, example1c),[]).
rule(case_example1c_f3(),simlarCodeObfuscation(example1c_m1, example1c_m2),[]).
rule(case_example1c_f4(),malwareLinkedTo(example1c_m2, countryX),[]).
rule(case_example1c_f5(),hasMotive(countryX, example1c),[]).
rule(case_example1c_f6(),attackSourceIP([123,123,123,102], example1c),[]).
rule(case_example1c_f7(),ipGeoloc(countryX,[123,123,123,102]),[]).
rule(case_example1c_f8(),targetCountry(countryX, example1c),[]).
% added evidence
rule(case_example1c_f9(),targetCountry(countryY, example1c),[]).


%% rule(case_example1c_f1(),claimedResponsibility(randomGroup,example1c),[]).
%% rule(case_example1c_f1a(),malwareUsedInAttack(example1cm,example1c),[]).
%% rule(case_example1c_f2(),targetCountry(countryX,example1c),[]).
%% rule(case_example1c_f2b(),targetCountry(countryY,example1c),[]).
%% rule(case_example1c_f3(),malwareUsedInAttack(example1c_m1,example1c),[]).
%% rule(case_example1c_f4(),simlarCodeObfuscation(example1c_m1,example1c_m2),[]).
%% rule(case_example1c_f5(),malwareLinkedTo(example1c_m2,countryX),[]).
%% rule(case_example1c_f8(),hasMotive(countryX,example1c),[]).
%% rule(case_example1c_f9(),attackSourceIP([123,123,123,125],example1c),[]).
%% rule(case_example1c_f10(),ipGeoloc(countryX,[123,123,123,125]),[]).
%% rule(case_example1c_f11(),ip([123,123,123,125]),[]).


%% example2
%% expected:
%% fancyBear (claimResp)
%% russian_federation (APT group link to origin country, has motive and capability)
rule(case_example2_f1(),claimedResponsibility(fancyBear,example2),[]).
rule(case_example2_f2(),targetCountry(countryX,example2),[]).
rule(case_example2_f3(),attackPeriod(example2, [2018,6]),[]).
rule(case_example2_f4(),malwareUsedInAttack(example2_m1,example2),[]).
rule(case_example2_f5(),imposedSanctions(countryX, russian_federation, ongoing),[]).
rule(case_example2_f6(),sophisticatedMalware(example2_m1),[]).


%% example2b
%% expected:
%% fancyBear (claimResp)
rule(case_example2b_f1(),claimedResponsibility(fancyBear,example2b),[]).
rule(case_example2b_f2(),targetCountry(countryX,example2b),[]).
rule(case_example2b_f3(),attackPeriod(example2b, [2018,6]),[]).
rule(case_example2b_f4(),malwareUsedInAttack(example2b_m1,example2b),[]).
rule(case_example2b_f5(),imposedSanctions(countryX, russian_federation, ongoing),[]).




%% example2
%% %% expected: 
%% %% randomGroup (claimResp)
%% %% targetItself is preferred over linkedMalware
%% %% more than one ipgeolocation doesnt give location information about attack 
%% rule(case_example2_f1(),claimedResponsibility(randomGroup,example2),[]).
%% rule(case_example2_f1(),malwareUsedInAttack(example2m,example2),[]).
%% rule(case_example2_f2(),targetCountry(countryX,example2),[]).
%% rule(case_example2_f3(),malwareUsedInAttack(example2_m1,example2),[]).
%% rule(case_example2_f4(),simlarCodeObfuscation(example2_m1,example2_m2),[]).
%% rule(case_example2_f5(),malwareLinkedTo(example2_m2,countryX),[]).
%% rule(case_example2_f8(),hasMotive(countryX,example2),[]).
%% rule(case_example2_f9(),attackSourceIP([123,123,123,123],example2),[]).
%% rule(case_example2_f10(),ipGeoloc(countryX,[123,123,123,123]),[]).
%% rule(case_example2_f12(),attackSourceIP([103,1,206,109],example2),[]).
%% rule(case_example2_f13(),ipGeoloc(hisCountry,[103,1,206,109]),[]).
%% %% rule(case_example2_f14(),ip([123,123,123,123]),[]).
%% %% rule(case_example2_f15(),ip([103,1,206,109]),[]).



%% example4
%% expected: 
%% countryX (location)
rule(case_example4_f1(),claimedResponsibility(countryX,example4),[]).
rule(case_example4_f1(),malwareUsedInAttack(example4m,example4),[]).
rule(case_example4_f2(),noPriorHistory(countryX),[]).
rule(case_example4_f3(),hasResources(countryX),[]).
rule(case_example4_f4(),neg(requireHighResource(example4)),[]).
rule(case_example4_f5(),ipGeoloc(countryX,[103,5,206,109]),[]).
rule(case_example4_f6(),attackSourceIP([103,5,206,109],example4),[]).
%% rule(case_example4_f7(),ip([103,5,206,109]),[]).

%% %% governmentLinked(P,C),identifiedIndividualInAttack(P,Att)

%% example5
%% exptected: someGroup, youtCountry
rule(case_example5_f1(),claimedResponsibility(someGroup,example5),[]).
rule(case_example5_f1a(),malwareUsedInAttack(example5m,example5),[]).
rule(case_example5_f2(),ipGeoloc(countryX,[103,1,206,100]),[]).
rule(case_example5_f3(),attackSourceIP([103,1,206,100],example5),[]).
%% rule(case_example5_f4(),ip([103,1,206,100]),[]).

%% %% example7
%% %% expected: 
%% %% countryX
rule(case_example7_f1a(),malwareUsedInAttack(example7m,example7),[]).
rule(case_example7_f2b(),targetCountry(countryY,example7),[]).
rule(case_example7_f3(),malwareUsedInAttack(example7_m1,example7),[]).
rule(case_example7_f4(),simlarCodeObfuscation(example7_m1,example7_m2),[]).
rule(case_example7_f5(),malwareLinkedTo(example7_m2,countryX),[]).

%% %% example8
%% %% expected: 
%% %% countryX (hasMotiveAndCapability)
%% rule(case_example8_f1(),targetCountry(countryY,example8),[]).
%% rule(case_example8_f2(),imposedSanctions(countryY, countryX, ongoing),[]).
%% rule(case_example8_f3(),attackPeriod(example8,[2018,5]),[]).

%% auto geolocation example
%% expected: hong_kong (loc)
rule(case_autogeoloc_ex_f1(),attackSourceIP([103,234,220,195],autogeoloc_ex),[]).
rule(case_autogeoloc_ex_f3(),ip([103,234,220,195]),[]).
%% rule(case_autogeoloc_ex_f4(),claimedResponsibility(countryX, autogeoloc_ex),[]).

%% tor_ex
%% expected: no culprit (spoof)
rule(case_tor_ex_f2(), attackSourceIP([103,234,220,195],tor_ex),[]).
rule(case_tor_ex_f3(), ip([103,234,220,195]),[]).
rule(case_tor_ex_f4(), targetServerIP([72,111,1,30], tor_ex),[]).
%% rule(case_tor_ex_f5(), claimedResponsibility(countryX, tor_ex),[]).


%% virustotal_ex
%% expected: 
%% us (loc)
%% countryY (linkedMalware)
rule(case_virustotal_ex_f0(),malwareUsedInAttack(virustotal_ex_malware, virustotal_ex),[]).
rule(case_virustotal_ex_f1(),attackSourceIP([8,8,8,8],virustotal_ex),[]).
rule(case_virustotal_ex_f2(),ip([8,8,8,8],[2018,5]),[]). % ip([IP],[YYYY,MM]) for auto resolution using virustotal
rule(case_virustotal_ex_f3(),ccServer('00027.hk', example_past_attack_m),[]).
rule(case_virustotal_ex_f4(),malwareLinkedTo(example_past_attack_m, countryY),[]).

%% ex
rule(case_snort_ex_f0(),malwareUsedInAttack(ex_malware, ex),[]).
rule(case_snort_ex_f1(),attackSourceIP([8,8,8,8], ex),[]).
rule(case_snort_ex_f2(),ip([8,8,8,8]),[]).

%% rule(case_snort_ex_f1(),dummyPred(someone, ex),[]).


%% https://en.wikipedia.org/wiki/Global_surveillance_disclosures_(2013%E2%80%93present)#Disclosures
%% https://en.wikipedia.org/wiki/Office_of_Personnel_Management_data_breach
rule(f1(),attackPossibleOrigin(country1, attack),[]).
rule(f2(),attackPossibleOrigin(country2, attack),[]).
rule(f3(),country(country1),[]).
rule(f4(),country(country2),[]).
