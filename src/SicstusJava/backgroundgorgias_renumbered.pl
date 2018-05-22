:- multifile rule/3.

%% for examples
rule(bg0(),country(myCountry),[]).
rule(bg1(),country(yourCountry),[]).
rule(bg2(),country(hisCountry),[]).

attackTypeList([ddos,espionage,defacement,data_destruction,sabotage,doxing]).
malwareTypeList([bot,ransomware,rootkit,spyware,trojan,virus,worm,keyloggers,grayware]).
spreadMechanismList([driveByDownloads,homogeneity,vulnerability,backdoor]).
attackMechanismList([zeroday,exploits,priviledgeEscalation,evasion,blended]).
%% rule(bg2,target(X,Att),[targets(L,Att)]) :-  member(X,L),\+ is_list(X),is_list(L).


natoCountriesList([belgium,canada,denmark,france,iceland,italy,luxembourg,netherlands,norway,portugal,united_kingdom,united_states,greece,turkey,spain]).
euCountriesList([austria,belgium,bulgaria,croatia,cyprus,czech_republic,denmark,estonia,finland,france,germany,greece,hungary,ireland,italy,latvia,lithuania,luxembourg,malta,netherlands,poland,portugal,romania,slovakia,slovenia,spain,sweden,united_kingdom]).
%% https://brilliantmaps.com/us-allies-enemies/
%% https://www.msn.com/en-gb/news/photos/which-countries-are-allies-and-which-are-enemies/ss-BBBNVNJ
%% https://today.yougov.com/topics/politics/articles-reports/2017/02/02/americas-friends-and-enemies
poorRelationList(united_states,[north_korea,iran,syria,iraq,afghanistan,russian_federation,libya,somalia,pakistan,palestine]).
poorRelationList(north_korea,[united_states,south_korea]).
rule(bg3(),poorRelation(X,Y),[]) :- poorRelationList(X,L),member(Y,L).
rule(bg4(),poorRelation(X,russian_federation),[]) :- natoCountriesList(L),member(X,L).
rule(bg5(),poorRelation(iran,saudi_arabia),[]).

goodRelationList(united_states,[canada,australia,united_kingdom,france,italy,ireland,israel,norway,sweden,germany,saudi_arabia,south_korea,cuba]).
goodRelationList(china,[north_korea]).
rule(bg6(),goodRelation(X,Y),[]) :- natoCountriesList(L),member(X,L),member(Y,L),X\=Y.
rule(bg7(),goodRelation(X,Y),[]) :- euCountriesList(L),member(X,L),member(Y,L),X\=Y.
rule(bg8(),goodRelation(X,Y),[]) :- goodRelationList(X,L),member(Y,L).


rule(bg9(),knownVulnerabilities([eternalBlue]),[]). %% TODO: find comprehensive list of knownVulnerabilities

rule(bg10(),malwareUsedInAttack(notPetya,notPetyaAttack),[]).
rule(bg11(),sha256(notPetya,'027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745'),[]).
rule(bg12(),sha256(notPetya,'64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1'),[]).
rule(bg13(),attackMechanism(notPetya,trojan),[]).
rule(bg14(),attackMechanism(notPetya,ransomware),[]).
%% rule(bg_1_6,,[]).
%% rule(bg_1_6,,[]).
%% rule(bg_1_6,,[]).
%% rule(bg_1_6,,[]).


rule(bg15(),sha256(goldenEye,'027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745'),[]).


rule(bg16(),prominentGroup(fancyBear),[]).
rule(bg17(),groupOrigin(fancyBear ,russian_federation),[]).
rule(bg18(),pastMotives(fancyBear ,[ espionage,doxing ]),[]).
rule(bg19(),pastTargets(fancyBear ,[georgia,france,jordan,united_states,hungary,world_antidoping_agency,
	nato,ukraine,belgium,pakistan,asia_pacific_economic_cooperation,osce,united_kingdom,
	germany,poland,european_commission]),[]).
rule(bg20(),targetCategory(fancyBear,government,military),[]).

rule(bg21(),prominentGroup(cozyBear),[]).
rule(bg22(),groupOrigin(cozyBear,russian_federation),[]).
rule(bg23(),pastTargets(cozyBear,[government,diplomatic_organizations,defense,energy,financial,insurance,legal,pharmaceutical,research,technology,brazil,china,japan,mexico,new_zealand,south_korea,turkey]),[]).
rule(bg24(),malwareLinkedTo(trojanMiniduke,cozyBear),[]).
rule(bg25(),malwareLinkedTo(trojanCozyduke,cozyBear),[]).
rule(bg26(),malwareLinkedTo(trojanSeaduke,cozyBear),[]).


rule(bg27(),prominentGroup(lazarusGrp),[]).
rule(bg28(),groupOrigin(lazarusGrp ,north_korea),[]).
rule(bg29(),malwareLinkedTo(backdoorDuuzer ,lazarusGrp),[]).
rule(bg30(),malwareLinkedTo(backdoorDestover ,lazarusGrp),[]).
rule(bg31(),malwareLinkedTo(infostealerFakepude ,lazarusGrp),[]).
rule(bg32(),malwareLinkedTo(backdoorContopee ,lazarusGrp),[]).

rule(bg33(),prominentGroup(equationGrp),[]).
rule(bg34(),groupOrigin(equationGrp ,united_states),[]).
rule(bg35(),pastTargets(equationGrp ,[ iran ,russian_federation ,pakistan ,afghanistan ,india ,syria ,mali ]),[]).

%% https://www.trendmicro.com/vinfo/us/security/definition/exploit-kit
%% rule(bg22,prominentGroup(anglerEK),[]).
%% rule(bg23,groupOrigin(anglerEK ,ussr),[]).
%% rule(bg24,groupAttackMethods(anglerEK ,[ driveByDownloads ]),[]).
%% rule(bg25,pastMotives(anglerEK ,[ undergroundBusiness ]),[]).

rule(bg36(),prominentGroup(deepPanda),[]).
rule(bg37(),groupOrigin(deepPanda ,china),[]).
rule(bg38(),groupAttackMethods(deepPanda ,[ zeroday ,wateringHole ,customMalware ]),[]).
rule(bg39(),pastTargets(deepPanda ,[united_states]),[]).
rule(bg40(),targetCategory(deepPanda ,[ aerospace ,energy ,healthcare,military,privateSector ]),[]).
rule(bg41(),pastMotives(deepPanda ,[ cyberespionage ]),[]).

rule(bg42(),prominentGroup(butterfly),[]).
rule(bg43(),groupOrigin(butterfly ,china),[]).
rule(bg44(),groupAttackMethods(butterfly ,[ zeroday ,customMalware ]),[]).
rule(bg45(),pastTargets(butterfly ,[ twitter ,facebook ,apple ,microsoft ,pharmaceutical,
	technology ,law ,oil ,preciousMetalMining ]),[]).
rule(bg46(),pastMotives(butterfly ,[ cyberespionage ,undergroundBusiness ]),[]).

rule(bg47(),prominentGroup(dragonfly),[]).
rule(bg48(),groupOrigin(dragonfly ,eastEurope),[]).
rule(bg49(),groupAttackMethods(dragonfly ,[ spamEmail ,wateringHole ,customMalware ]),[]).
rule(bg50(),pastTargets(dragonfly ,[ defense ,aerospace ,energy ]),[]).
rule(bg51(),pastMotives(dragonfly ,[ cyberespionage ,spy ,sabotage ]),[]).


rule(bg52(),prominentGroup(govRAT),[]).
rule(bg53(),groupOrigin(govRAT ,china),[]).
rule(bg54(),groupAttackMethods(govRAT ,[ clientSideExploits ]),[]).
rule(bg55(),pastTargets(govRAT ,[united_states,taiwan,united_kingdom,singapore,india,canada,
	japan,indonesia,hong_kong,united_nations,south_korea,switzerland,vietnam,germany,
	international_olympic_committee]),[]).
rule(bg56(),targetCategory([ govOfficials ,militaryOfficials ,enterprises ]),[]).
rule(bg57(),pastMotives(govRAT ,[ cyberespionage ]),[]).


rule(bg58(),prominentGroup(pawnStorm),[]).
rule(bg59(),groupAttackMethods(pawnStorm ,[ spearphishing ,phishingWebsites ,ios ,exploits ,zeroday ]),[]).
rule(bg60(),pastTargets(pawnStorm ,[ nato ,govOfficials ,militaryOfficials ,russian_federation ,ukraine ]),[]).
rule(bg61(),pastMotives(pawnStorm ,[ cyberespionage ]),[]).

rule(bg62(),prominentGroup(waterbug),[]).
rule(bg63(),groupAttackMethods(waterbug ,[ zeroday ,email ,stolenCertificates ,wateringHole ]),[]).
rule(bg64(),pastTargets(waterbug ,[ govInstitutions ,embassies ,education ,research ]),[]).
rule(bg65(),pastMotives(waterbug ,[ cyberespionage ,spy ,intelligenceGathering ]),[]).



listCountries([afghanistan,andorra,angola,armenia,bahamas,barbados,belize,benin,bhutan,bolivia,
	bosnia_herzegovina,burkina_faso,burundi,cambodia,cape,verde,central_african_republic,chad,comoros,congo,
	cuba,democratic_republic_of_the_congo,djibouti,dominica,dominican_republic,el_salvador,equatorial_guinea,
	eritrea,ethiopia,fiji,gabon,gambia,grenada,guatemala,guinea,guinea_bissau,guyana,haiti,honduras,iraq,jordan,
	kiribati,kuwait,kyrgyzstan,lebanon,lesotho,liberia,libya,liechtenstein,madagascar,malawi,maldives,mali,
	marshall_islands,mauritania,micronesia,monaco,mongolia,mozambique,myanmar,namibia,nauru,nepal,nicaragua,niger,
	palau,state_of_palestine,papua_new_guinea ,saint_kitts_and_nevis ,saint_lucia,saint_vincent_and_the_grenadines,
	samoa,san_marino,saotome_and_principe,seychelles,sierra_leone,solomon_islands,somalia,southsudan,sudan,suriname,
	swaziland,syrian_arab_republic,tajikistan,timor_leste,togo,tonga,trinidad_and_tobago,turkmenistan,tuvalu,
	uzbekistan,vanuatu,vatican,viet,nam,yemen,zambia,zimbabwe,albania,ghana,peru,algeria,greece,philippines,argentina,
	hungary,poland,austria,iceland,portugal,azerbaijan,india,qatar,bahrain,indonesia,romania,bangladesh,iran,rwanda,
	belarus,ireland,saudi_arabia,belgium,israel,senegal,botswana,italy,serbia ,brazil,jamaica,slovakia,brunei_darussalam,
	kazakhstan,slovenia,bulgaria,kenya,southafrica,cameroon,laos,spain,chile,latvia,sri,lanka,china,lithuania,tanzania,
	colombia,luxembourg,thailand,costa_rica,malta,cote_divoire,mexico,tunisia,croatia,moldova,turkey,cyprus,montenegro,
	uganda,czech_republic,morocco,ukraine,north_korea,nigeria,united_arab_emirates,denmark,pakistan,uruguay,ecuador,
	panama,venezuela,germany,paraguay,australia,japan,oman ,canada,south_korea,russian_federation,egypt,malaysia,singapore,estonia,
	mauritius,sweden,finland,netherlands,switzerland,france,new_zealand,united_kingdom,georgia,norway,united_states,hong_kong]).

cybersuperpowerlist([ china ,israel ,iran ,united_states ,north_korea]).
rule(bg66(),cybersuperpower(X),[]) :- cybersuperpowerlist(L),member(X,L).
%% rule(bg65b,listNegHasResources([ indonesia,saudi_arabia,india,southafrica,turkey ]),[]).
listNormalIndustries([ telecom, banking, infocomm ]).
listPoliticalIndustries([ military, nuclear, water, electricity, transport]).

rule(bg67(),country(X),[]) :- listCountries(L),member(X,L).
rule(bg68(),industry(X),[]) :- listNormalIndustries(L),member(X,L).
rule(bg69(),industry(X),[]) :- listPoliticalIndustries(L),member(X,L).
rule(bg70(),normalIndustry(X),[]) :- listNormalIndustries(L),member(X,L).
rule(bg71(),politicalIndustry(X),[]) :- listPoliticalIndustries(L),member(X,L).

%% rule(bg72,hasResources(X),[listHasResources(L),member(X,L)]).
%% rule(bg72b,neg(hasResources(X)),[listNegHasResources(L),member(X,L)]).
listChineseCountries([ china ]).
listEnglishCountries([ united_states ,united_kingdom ]).

rule(bg72(),firstLanguage(chinese,X),[]) :- listChineseCountries(L),member(X,L).
rule(bg73(),firstLanguage(english,X),[]) :- listEnglishCountries(L),member(X,L).

%% part of nsa
%% have support of us gov/ has relations
rule(bg74(),isInfrastructure(nuclear),[]).
rule(bg75(),isInfrastructure(electricity),[]).
rule(bg76(),isInfrastructure(water),[]).
rule(bg77(),informationRich(banking),[]).
rule(bg78(),informationRich(infocomm),[]).
rule(bg79(),informationRich(consumer),[]).

rule(bg80(),typeOfAttack(sabotage ,Att),[isInfrastructure(Ind),industry(Ind,V),target(V,Att)]).
rule(bg81(),typeOfAttack(espionage ,Att),[informationRich(Ind),industry(Ind,V),target(V,Att)]).


%% rule(bg78,isCulprit(equationGroup ,flameattack),[]). 
rule(bg82(),malwareLinkedTo(flame,equationGrp),[]). 

%% rule(bg94,isCulprit([ united_states ,israel ],flameattack),[]).
rule(bg83(),target(middleeast ,flameattack),[]).
rule(bg84(),malwareUsedInAttack(flame ,flameattack),[]).
rule(bg85(),ccServer(gowin7 ,flame),[]).
rule(bg86(),ccServer(secuurity ,flame),[]).
rule(bg87(),domainRegisteredDetails(gowin7 ,adolph_dybevek ,prinsen_gate_6),[]).
rule(bg88(),domainRegisteredDetails(secuurity ,adolph_dybevek ,prinsen_gate_6),[]).
%% rule(bg89(),addressType(prinsen_gate_6 ,hotel),[]).

%% fireeye tech
rule(bg90(),fileCharaMalware(wannacry_filechara1,wannacry),[]).
rule(bg91(),fileChara('mssecsvcexe','db349b97c37d22f5ea1d1841e3c89eb4','3723264','2010-11-20T09:03:08Z','Loader+WormComponent','EXE',wannacry_filechara1),[]).
rule(bg92(),fileCharaMalware(wannacry_filechara2,wannacry),[]).
rule(bg93(),fileChara('taskscheexe','84c82835a5d21bbcf75a61706d8ab549','3514368','2010-11-20T09:05:05Z','Loader','EXE',wannacry_filechara2),[]).
rule(bg94(),fileCharaMalware(wannacry_filechara3,wannacry),[]).
rule(bg95(),fileChara('Unavailable','f351e1fcca0c4ea05fc44d15a17f8b36','65536','2009-07-1401:12:55Z','Encryptor','DLL',wannacry_filechara3),[]).
rule(bg96(),fileCharaMalware(wannacry_filechara4,wannacry),[]).
rule(bg97(),fileChara('@WanaDecryptor@exe','7bf2b57f2a205768755c07f238fb32cc','245760','2009-07-1323:19:35Z','Decryptor','EXE',wannacry_filechara4),[]).

%% Global Cybersecurity Index
list_gci_initiating([afghanistan,andorra,angola,armenia,bahamas,barbados,belize,benin,bhutan,bolivia,
	bosnia_herzegovina,burkina_faso,burundi,cambodia,cape,verde,central_african_republic,chad,comoros,congo,cuba,
	democratic_republic_of_the_congo,djibouti,dominica,dominican_republic,el_salvador,equatorial_guinea,eritrea,
	ethiopia,fiji,gabon,gambia,grenada,guatemala,guinea,guinea_bissau,guyana,haiti,honduras,iraq,jordan,kiribati,
	kuwait,kyrgyzstan,lebanon,lesotho,liberia,libya,liechtenstein,madagascar,malawi,maldives,mali,marshall_islands,
	mauritania,micronesia,monaco,mongolia,mozambique,myanmar,namibia,nauru,nepal,nicaragua,niger,palau,state_of_palestine,
	papua_new_guinea,saint_kitts_and_nevis,saint_lucia,saint_vincent_and_the_grenadines,samoa,san_marino,saotome_and_principe,
	seychelles,sierra_leone,solomon_islands,somalia,southsudan,sudan,suriname,swaziland,syrian_arab_republic,tajikistan,
	timor_leste,togo,tonga,trinidad_and_tobago,turkmenistan,tuvalu,uzbekistan,vanuatu,vatican,viet,nam,yemen,zambia,zimbabwe]).
list_gci_maturing([albania,ghana,peru,algeria,greece,philippines,argentina,hungary,poland,austria,iceland,portugal,
	azerbaijan,india,qatar,bahrain,indonesia,romania,bangladesh,iran,rwanda,belarus,ireland,saudi_arabia,belgium,israel,senegal,
	botswana,italy,serbia,brazil,jamaica,slovakia,brunei_darussalam,kazakhstan,slovenia,bulgaria,kenya,southafrica,cameroon,laos,
	spain,chile,latvia,sri,lanka,china,lithuania,tanzania,colombia,luxembourg,thailand,costa_rica,malta,cote_divoire,mexico,
	tunisia,croatia,moldova,turkey,cyprus,montenegro,uganda,czech_republic,morocco,ukraine,north_korea,nigeria,
	united_arab_emirates,denmark,pakistan,uruguay,ecuador,panama,venezuela,germany,paraguay]).
list_gci_leading([australia,japan,oman,canada,south_korea,russian_federation,egypt,malaysia,singapore,estonia,mauritius,sweden,
	finland,netherlands,switzerland,france,new_zealand,united_kingdom,georgia,norway,united_states]).
rule(bg98(),gci_tier(X,initiating),[]) :- list_gci_initiating(L),member(X,L).
rule(bg99(),gci_tier(X,maturing),[]) :- list_gci_maturing(L),member(X,L).
rule(bg100(),gci_tier(X,leading),[]) :- list_gci_leading(L),member(X,L).