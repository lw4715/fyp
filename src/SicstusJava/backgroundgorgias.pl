:- multifile rule/3.
rule(bg1a, attackTypeList([ddos, espionage, defacement, data_destruction, sabotage, doxing]), []).
rule(bg1b, malwareTypeList([bot, ransomware, rootkit, spyware, trojan, virus, worm, keyloggers, grayware]), []).
rule(bg1c, spreadMechanismList([driveByDownloads, homogeneity, vulnerability, backdoor]), []).
rule(bg1d, attackMechanismList([zeroday, exploits, priviledgeEscalation, evasion, blended]), []).
rule(bg2, target(X,Att), [targets(L,Att), member(X,L), \+ is_list(X), is_list(L)]).


rule(bg1z, knownVulnerabilities([eternalBlue]), []). %% TODO: find comprehensive list of knownVulnerabilities

rule(bg_1_1, malwareUsedInAttack(notPetya, notPetyaAttack), []).
rule(bg_1_2, sha256(notPetya, '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745'),[]).
rule(bg_1_3, sha256(notPetya, '64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1'),[]).
rule(bg_1_4, attackMechanism(notPetya, trojan),[]).
rule(bg_1_5, attackMechanism(notPetya, ransomware),[]).
%% rule(bg_1_6, ,[]).
%% rule(bg_1_6, ,[]).
%% rule(bg_1_6, ,[]).
%% rule(bg_1_6, ,[]).


rule(bg_2_2, sha256(goldenEye, '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745'),[]).


rule(bg2, prominentGroup( fancyBear ), []).
rule(bg3, groupOrigin( fancyBear , russia ), []).
rule(bg4, pastMotives( fancyBear ,[ espionage, doxing ]), []).
rule(bg5, pastTargets( fancyBear ,[georgia,france,jordan,usa,hungary,world_antidoping_agency,
	nato,ukraine,belgium,pakistan,asia_pacific_economic_cooperation,osce,united_kingdom,
	germany,poland,european_commission]), []).
rule(bg6, targetCategory(fancyBear, government,military), []).

rule(bg7a, prominentGroup( cozyBear ), []).
rule(bg7b, groupOrigin(cozyBear, russia), []).
rule(bg7c, pastTargets(cozyBear, [government, diplomatic_organizations, defense, energy, financial, insurance, legal, pharmaceutical, research, technology, brazil, china, japan, mexico, new_zealand, southkorea, turkey]), []).
rule(bg7x, malwareLinkedTo(trojanMiniduke, cozyBear), []).
rule(bg7y, malwareLinkedTo(trojanCozyduke, cozyBear), []).
rule(bg7z, malwareLinkedTo(trojanSeaduke, cozyBear), []).


rule(bg8, prominentGroup( lazarusGrp ), []).
rule(bg9, groupOrigin( lazarusGrp , northkorea ), []).
rule(bg10, malwareLinkedTo( backdoorDuuzer , lazarusGrp ), []).
rule(bg11, malwareLinkedTo( backdoorDestover , lazarusGrp ), []).
rule(bg12, malwareLinkedTo( infostealerFakepude , lazarusGrp ), []).
rule(bg13, malwareLinkedTo( backdoorContopee , lazarusGrp ), []).

rule(bg16, prominentGroup( equationGrp ), []).
rule(bg17, groupOrigin( equationGrp , usa ), []).
rule(bg18, pastTargets( equationGrp ,[ iran , russia , pakistan , afghanistan , india , syria , mali ]), []).

%% https://www.trendmicro.com/vinfo/us/security/definition/exploit-kit
%% rule(bg22, prominentGroup( anglerEK ), []).
%% rule(bg23, groupOrigin( anglerEK , ussr ), []).
%% rule(bg24, groupAttackMethods( anglerEK ,[ driveByDownloads ]), []).
%% rule(bg25, pastMotives( anglerEK ,[ undergroundBusiness ]), []).

rule(bg28, prominentGroup( deepPanda ), []).
rule(bg29, groupOrigin( deepPanda , china ), []).
rule(bg30, groupAttackMethods( deepPanda ,[ zeroday , wateringHole , customMalware ]), []).
rule(bg31, pastTargets( deepPanda ,[usa]), []).
rule(bg31, targetCategory( deepPanda ,[ aerospace , energy , healthcare, military, privateSector ]), []).
rule(bg32, pastMotives( deepPanda ,[ cyberespionage ]), []).

rule(bg34, prominentGroup( butterfly ), []).
rule(bg35, groupOrigin( butterfly , china ), []).
rule(bg36, groupAttackMethods( butterfly ,[ zeroday , customMalware ]), []).
rule(bg37, pastTargets( butterfly ,[ twitter , facebook , apple , microsoft , pharmaceutical, 
	technology , law , oil , preciousMetalMining ]), []).
rule(bg38, pastMotives( butterfly ,[ cyberespionage , undergroundBusiness ]), []).

rule(bg41, prominentGroup( dragonfly ), []).
rule(bg42, groupOrigin( dragonfly , eastEurope ), []).
rule(bg43, groupAttackMethods( dragonfly ,[ spamEmail , wateringHole , customMalware ]), []).
rule(bg44, pastTargets( dragonfly ,[ defense , aerospace , energy ]), []).
rule(bg45, pastMotives( dragonfly ,[ cyberespionage , spy , sabotage ]), []).


rule(bg47, prominentGroup( govRAT ), []).
rule(bg48, groupOrigin( govRAT , china ), []).
rule(bg49, groupAttackMethods( govRAT ,[ clientSideExploits ]), []).
rule(bg50, pastTargets( govRAT ,[usa, taiwan, united_kingdom, singapore, india, canada, 
	japan, indonesia, hong_kong, united_nations, southkorea, switzerland, vietnam, germany, 
	international_olympic_committee]), []).
rule(bg51, targetCategory([ govOfficials , militaryOfficials , enterprises ]), []).
rule(bg52, pastMotives( govRAT ,[ cyberespionage ]), []).


rule(bg53, prominentGroup( pawnStorm ), []).
rule(bg54, groupAttackMethods( pawnStorm ,[ spearphishing , phishingWebsites , ios , exploits , zeroday ]), []).
rule(bg55, pastTargets( pawnStorm ,[ nato , govOfficials , militaryOfficials , russia , ukraine ]), []).
rule(bg56, pastMotives( pawnStorm ,[ cyberespionage ]), []).

rule(bg58, prominentGroup( waterbug ), []).
rule(bg59, groupAttackMethods( waterbug ,[ zeroday , email , stolenCertificates , wateringHole ]), []).
rule(bg60, pastTargets( waterbug ,[ govInstitutions , embassies , education , research ]), []).
rule(bg61, pastMotives( waterbug ,[ cyberespionage , spy , intelligenceGathering ]), []).



rule(bg64, listCountries([afghanistan,andorra,angola,armenia,bahamas,barbados,belize,benin,bhutan,bolivia,
	bosnia_herzegovina,burkina_faso,burundi,cambodia,cape,verde,central_african_republic,chad,comoros,congo,
	cuba,democratic_republic_of_the_congo,djibouti,dominica,dominican_republic,el_salvador,equatorial_guinea,
	eritrea,ethiopia,fiji,gabon,gambia,grenada,guatemala,guinea,guinea_bissau,guyana,haiti,honduras,iraq,jordan,
	kiribati,kuwait,kyrgyzstan,lebanon,lesotho,liberia,libya, liechtenstein,madagascar,malawi,maldives,mali,
	marshall_islands,mauritania,micronesia,monaco, mongolia,mozambique,myanmar,namibia,nauru,nepal,nicaragua,niger,
	palau,state_of_palestine, papua_new_guinea ,saint_kitts_and_nevis ,saint_lucia,saint_vincent_and_the_grenadines,
	samoa,san_marino,saotome_and_principe,seychelles,sierra_leone,solomon_islands,somalia,southsudan,sudan,suriname,
	swaziland,syrian_arab_republic,tajikistan,timor_leste,togo,tonga, trinidad_and_tobago,turkmenistan,tuvalu,
	uzbekistan,vanuatu,vatican,viet,nam,yemen,zambia,zimbabwe,albania,ghana,peru,algeria,greece,philippines,argentina,
	hungary,poland,austria, iceland,portugal,azerbaijan,india,qatar,bahrain,indonesia,romania,bangladesh,iran,rwanda,
	belarus, ireland,saudi_arabia,belgium,israel,senegal,botswana,italy,serbia ,brazil,jamaica,slovakia,brunei_darussalam,
	kazakhstan,slovenia,bulgaria,kenya,southafrica,cameroon,laos,spain,chile,latvia, sri,lanka,china,lithuania,tanzania,
	colombia,luxembourg,thailand,costa_rica,malta,cote_divoire, mexico,tunisia,croatia,moldova,turkey,cyprus,montenegro,
	uganda,czech_republic,morocco,ukraine, northkorea,nigeria,united_arab_emirates,denmark,pakistan,uruguay,ecuador,
	panama,venezuela,germany,paraguay,australia,japan,oman ,canada,southkorea,russia,egypt,malaysia,singapore,estonia,
	mauritius,sweden,finland,netherlands,switzerland,france,new_zealand,united_kingdom,georgia,norway,usa]), []).

rule(bg65, cybersuperpowerlist([ china , israel , iran , usa , northkorea ]), []).
rule(bg65b, cybersuperpower(X), [cybersuperpowerlist(L), member(X,L)]).
%% rule(bg65b, listNegHasResources([ indonesia, saudi_arabia, india, southafrica, turkey ]), []).
rule(bg66, listIndustries([ infocomm ]), []).
rule(bg67, listChineseCountries([ china ]), []).
rule(bg68, listEnglishCountries([ usa , united_kingdom ]), []).

rule(bg70, country(X), [listCountries(L),member(X,L)]).
rule(bg71, industry(X), [listIndustries(L),member(X,L)]).
%% rule(bg72, hasResources(X), [listHasResources(L),member(X,L)]).
%% rule(bg72b, neg(hasResources(X)), [listNegHasResources(L),member(X,L)]).
rule(bg73, firstLanguage(chinese,X), [listChineseCountries(L),member(X,L)]).
rule(bg74, firstLanguage(english,X), [listEnglishCountries(L),member(X,L)]).

%% part of nsa
%% have support of us gov/ has relations
rule(bg81, isInfrastructure( nuclear ), []).
rule(bg82, isInfrastructure( electricity ), []).
rule(bg83, isInfrastructure( water ), []).
rule(bg84, informationRich( banking ), []).
rule(bg85, informationRich( infocomm ), []).
rule(bg86, informationRich( consumer ), []).

rule(bg88, possibleMotive( sabotage ,Att), [isInfrastructure(Ind),industry(Ind,V),target(V,Att)]).
rule(bg89, possibleMotive( espionage ,Att), [informationRich(Ind),industry(Ind,V),target(V,Att)]).

%% rule(bg78, isCulprit( equationGroup , flameattack ), []). 
rule(bg78, malwareLinkedTo(flame, equationGroup), []). 

%% rule(bg94, isCulprit([ usa , israel ], flameattack ), []).
rule(bg95, target( middleeast , flameattack ), []).
rule(bg96, malwareUsedInAttack( flame , flameattack ), []).
rule(bg97, ccServer( gowin7 , flame ), []).
rule(bg98, ccServer( secuurity , flame ), []).
rule(bg99, domainRegisteredDetails( gowin7 , adolph_dybevek , prinsen_gate_6 ), []).
rule(bg100, domainRegisteredDetails( secuurity , adolph_dybevek , prinsen_gate_6 ), []).
rule(bg101, addressType( prinsen_gate_6 , hotel ), []).

%% fireeye tech
rule(bg104, fileCharaMalware(wannacry_filechara1,wannacry), []).
rule(bg105, fileChara('mssecsvcexe','db349b97c37d22f5ea1d1841e3c89eb4','3723264','2010-11-20T09:03:08Z','Loader+WormComponent','EXE',wannacry_filechara1), []).
rule(bg106, fileCharaMalware(wannacry_filechara2,wannacry), []).
rule(bg107, fileChara('taskscheexe','84c82835a5d21bbcf75a61706d8ab549','3514368','2010-11-20T09:05:05Z','Loader','EXE',wannacry_filechara2), []).
rule(bg108, fileCharaMalware(wannacry_filechara3,wannacry), []).
rule(bg109, fileChara('Unavailable','f351e1fcca0c4ea05fc44d15a17f8b36','65536','2009-07-1401:12:55Z','Encryptor','DLL',wannacry_filechara3), []).
rule(bg110, fileCharaMalware(wannacry_filechara4,wannacry), []).
rule(bg111, fileChara('@WanaDecryptor@exe','7bf2b57f2a205768755c07f238fb32cc','245760','2009-07-1323:19:35Z','Decryptor','EXE',wannacry_filechara4), []).

%% Global Cybersecurity Index
rule(bg112, list_gci_initiating([afghanistan,andorra,angola,armenia,bahamas,barbados,belize,benin,bhutan,bolivia,
	bosnia_herzegovina,burkina_faso,burundi,cambodia,cape,verde,central_african_republic,chad,comoros,congo,cuba,
	democratic_republic_of_the_congo,djibouti,dominica,dominican_republic,el_salvador,equatorial_guinea,eritrea,
	ethiopia,fiji,gabon,gambia,grenada,guatemala,guinea,guinea_bissau,guyana,haiti,honduras,iraq,jordan,kiribati,
	kuwait,kyrgyzstan,lebanon,lesotho,liberia,libya,liechtenstein,madagascar,malawi,maldives,mali,marshall_islands,
	mauritania,micronesia,monaco,mongolia,mozambique,myanmar,namibia,nauru,nepal,nicaragua,niger,palau,state_of_palestine,
	papua_new_guinea,saint_kitts_and_nevis,saint_lucia,saint_vincent_and_the_grenadines,samoa,san_marino,saotome_and_principe,
	seychelles,sierra_leone,solomon_islands,somalia,southsudan,sudan,suriname,swaziland,syrian_arab_republic,tajikistan,
	timor_leste,togo,tonga,trinidad_and_tobago,turkmenistan,tuvalu,uzbekistan,vanuatu,vatican,viet,nam,yemen,zambia,zimbabwe]), []).
rule(bg113, list_gci_maturing([albania,ghana,peru,algeria,greece,philippines,argentina,hungary,poland,austria,iceland,portugal,
	azerbaijan,india,qatar,bahrain,indonesia,romania,bangladesh,iran,rwanda,belarus,ireland,saudi_arabia,belgium,israel,senegal,
	botswana,italy,serbia,brazil,jamaica,slovakia,brunei_darussalam,kazakhstan,slovenia,bulgaria,kenya,southafrica,cameroon,laos,
	spain,chile,latvia,sri,lanka,china,lithuania,tanzania,colombia,luxembourg,thailand,costa_rica,malta,cote_divoire,mexico,
	tunisia,croatia,moldova,turkey,cyprus,montenegro,uganda,czech_republic,morocco,ukraine,northkorea,nigeria,
	united_arab_emirates,denmark,pakistan,uruguay,ecuador,panama,venezuela,germany,paraguay]), []).
rule(bg114, list_gci_leading([australia,japan,oman,canada,southkorea,russia,egypt,malaysia,singapore,estonia,mauritius,sweden,
	finland,netherlands,switzerland,france,new_zealand,united_kingdom,georgia,norway,usa]), []).
rule(bg115, gci_tier(X,initiating), [list_gci_initiating(L),member(X,L)]).
rule(bg116, gci_tier(X,maturing), [list_gci_maturing(L),member(X,L)]).
rule(bg117, gci_tier(X,leading), [list_gci_leading(L),member(X,L)]).

