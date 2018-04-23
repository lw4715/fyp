:- multifile rule/3.
rule(bg0, attackTypeList([ddos, espionage, defacement, data_destruction, sabotage, doxing]), []).
rule(bg1, malwareTypeList([bot, ransomware, rootkit, spyware, trojan, virus, worm, keyloggers, grayware]), []).
rule(bg2, spreadMechanismList([driveByDownloads, homogeneity, vulnerability, backdoor]), []).
rule(bg3, attackMechanismList([zeroday, exploits, priviledgeEscalation, evasion, blended]), []).
rule(bg4, target(X,Att), [targets(L,Att), member(X,L)]).


rule(bg5, knownVulnerabilities([eternalBlue]), []). %% TODO: find comprehensive list of knownVulnerabilities

rule(bg6, malwareUsedInAttack(notPetya, notPetyaAttack), []).
rule(bg7, sha256(notPetya, '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745'),[]).
rule(bg8, sha256(notPetya, '64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1'),[]).
rule(bg9, attackMechanism(notPetya, trojan),[]).
rule(bg10, attackMechanism(notPetya, ransomware),[]).
%% rule(bg_1_6, ,[]).
%% rule(bg_1_6, ,[]).
%% rule(bg_1_6, ,[]).
%% rule(bg_1_6, ,[]).


rule(bg11, sha256(goldenEye, '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745'),[]).


rule(bg12, prominentGroup( fancyBear ), []).
rule(bg13, groupOrigin( fancyBear , russia ), []).
rule(bg14, pastMotives( fancyBear ,[ espionage, doxing ]), []).
rule(bg15, pastTargets( fancyBear ,[georgia,france,jordan,usa,hungary,world_antidoping_agency,
	nato,ukraine,belgium,pakistan,asia_pacific_economic_cooperation,osce,united_kingdom,
	germany,poland,european_commission]), []).
rule(bg16, targetCategory(fancyBear, government,military), []).

rule(bg17, prominentGroup( cozyBear ), []).
rule(bg18, groupOrigin(cozyBear, russia), []).
rule(bg19, pastTargets(cozyBear, [government, diplomatic_organizations, defense, energy, financial, insurance, legal, pharmaceutical, research, technology, brazil, china, japan, mexico, new_zealand, southkorea, turkey]), []).
rule(bg20, malwareLinkedTo(trojanMiniduke, cozyBear), []).
rule(bg21, malwareLinkedTo(trojanCozyduke, cozyBear), []).
rule(bg22, malwareLinkedTo(trojanSeaduke, cozyBear), []).


rule(bg23, prominentGroup( lazarusGrp ), []).
rule(bg24, groupOrigin( lazarusGrp , northkorea ), []).
rule(bg25, malwareLinkedTo( backdoorDuuzer , lazarusGrp ), []).
rule(bg26, malwareLinkedTo( backdoorDestover , lazarusGrp ), []).
rule(bg27, malwareLinkedTo( infostealerFakepude , lazarusGrp ), []).
rule(bg28, malwareLinkedTo( backdoorContopee , lazarusGrp ), []).

rule(bg29, prominentGroup( equationGrp ), []).
rule(bg30, groupOrigin( equationGrp , usa ), []).
rule(bg31, pastTargets( equationGrp ,[ iran , russia , pakistan , afghanistan , india , syria , mali ]), []).

%% https://www.trendmicro.com/vinfo/us/security/definition/exploit-kit
%% rule(bg22, prominentGroup( anglerEK ), []).
%% rule(bg23, groupOrigin( anglerEK , ussr ), []).
%% rule(bg24, groupAttackMethods( anglerEK ,[ driveByDownloads ]), []).
%% rule(bg25, pastMotives( anglerEK ,[ undergroundBusiness ]), []).

rule(bg32, prominentGroup( deepPanda ), []).
rule(bg33, groupOrigin( deepPanda , china ), []).
rule(bg34, groupAttackMethods( deepPanda ,[ zeroday , wateringHole , customMalware ]), []).
rule(bg35, pastTargets( deepPanda ,[usa]), []).
rule(bg36, targetCategory( deepPanda ,[ aerospace , energy , healthcare, military, privateSector ]), []).
rule(bg37, pastMotives( deepPanda ,[ cyberespionage ]), []).

rule(bg38, prominentGroup( butterfly ), []).
rule(bg39, groupOrigin( butterfly , china ), []).
rule(bg40, groupAttackMethods( butterfly ,[ zeroday , customMalware ]), []).
rule(bg41, pastTargets( butterfly ,[ twitter , facebook , apple , microsoft , pharmaceutical, 
	technology , law , oil , preciousMetalMining ]), []).
rule(bg42, pastMotives( butterfly ,[ cyberespionage , undergroundBusiness ]), []).

rule(bg43, prominentGroup( dragonfly ), []).
rule(bg44, groupOrigin( dragonfly , eastEurope ), []).
rule(bg45, groupAttackMethods( dragonfly ,[ spamEmail , wateringHole , customMalware ]), []).
rule(bg46, pastTargets( dragonfly ,[ defense , aerospace , energy ]), []).
rule(bg47, pastMotives( dragonfly ,[ cyberespionage , spy , sabotage ]), []).


rule(bg48, prominentGroup( govRAT ), []).
rule(bg49, groupOrigin( govRAT , china ), []).
rule(bg50, groupAttackMethods( govRAT ,[ clientSideExploits ]), []).
rule(bg51, pastTargets( govRAT ,[usa, taiwan, united_kingdom, singapore, india, canada, 
	japan, indonesia, hong_kong, united_nations, southkorea, switzerland, vietnam, germany, 
	international_olympic_committee]), []).
rule(bg52, targetCategory([ govOfficials , militaryOfficials , enterprises ]), []).
rule(bg53, pastMotives( govRAT ,[ cyberespionage ]), []).


rule(bg54, prominentGroup( pawnStorm ), []).
rule(bg55, groupAttackMethods( pawnStorm ,[ spearphishing , phishingWebsites , ios , exploits , zeroday ]), []).
rule(bg56, pastTargets( pawnStorm ,[ nato , govOfficials , militaryOfficials , russia , ukraine ]), []).
rule(bg57, pastMotives( pawnStorm ,[ cyberespionage ]), []).

rule(bg58, prominentGroup( waterbug ), []).
rule(bg59, groupAttackMethods( waterbug ,[ zeroday , email , stolenCertificates , wateringHole ]), []).
rule(bg60, pastTargets( waterbug ,[ govInstitutions , embassies , education , research ]), []).
rule(bg61, pastMotives( waterbug ,[ cyberespionage , spy , intelligenceGathering ]), []).



rule(bg62, listCountries([afghanistan,andorra,angola,armenia,bahamas,barbados,belize,benin,bhutan,bolivia,
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

rule(bg63, cybersuperpowerlist([ china , israel , iran , usa , northkorea ]), []).
rule(bg64, cybersuperpower(X), [cybersuperpowerlist(L), member(X,L)]).
%% rule(bg65b, listNegHasResources([ indonesia, saudi_arabia, india, southafrica, turkey ]), []).
rule(bg65, listIndustries([ infocomm ]), []).
rule(bg66, listChineseCountries([ china ]), []).
rule(bg67, listEnglishCountries([ usa , united_kingdom ]), []).

rule(bg68, country(X), [listCountries(L),member(X,L)]).
rule(bg69, industry(X), [listIndustries(L),member(X,L)]).
%% rule(bg72, hasResources(X), [listHasResources(L),member(X,L)]).
%% rule(bg72b, neg(hasResources(X)), [listNegHasResources(L),member(X,L)]).
rule(bg70, firstLanguage(chinese,X), [listChineseCountries(L),member(X,L)]).
rule(bg71, firstLanguage(english,X), [listEnglishCountries(L),member(X,L)]).

%% part of nsa
%% have support of us gov/ has relations
rule(bg72, isInfrastructure( nuclear ), []).
rule(bg73, isInfrastructure( electricity ), []).
rule(bg74, isInfrastructure( water ), []).
rule(bg75, informationRich( banking ), []).
rule(bg76, informationRich( infocomm ), []).
rule(bg77, informationRich( consumer ), []).

rule(bg78, possibleMotive( sabotage ,Att), [isInfrastructure(Ind),industry(Ind,V),target(V,Att)]).
rule(bg79, possibleMotive( espionage ,Att), [informationRich(Ind),industry(Ind,V),target(V,Att)]).

%% rule(bg78, isCulprit( equationGroup , flameattack ), []). 
rule(bg80, malwareLinkedTo(flame, equationGroup), []). 

%% rule(bg94, isCulprit([ usa , israel ], flameattack ), []).
rule(bg81, target( middleeast , flameattack ), []).
rule(bg82, malwareUsedInAttack( flame , flameattack ), []).
rule(bg83, ccServer( gowin7 , flame ), []).
rule(bg84, ccServer( secuurity , flame ), []).
rule(bg85, domainRegisteredDetails( gowin7 , adolph_dybevek , prinsen_gate_6 ), []).
rule(bg86, domainRegisteredDetails( secuurity , adolph_dybevek , prinsen_gate_6 ), []).
rule(bg87, addressType( prinsen_gate_6 , hotel ), []).

%% fireeye tech
rule(bg88, fileCharaMalware(wannacry_filechara1,wannacry), []).
rule(bg89, fileChara('mssecsvcexe','db349b97c37d22f5ea1d1841e3c89eb4','3723264','2010-11-20T09:03:08Z','Loader+WormComponent','EXE',wannacry_filechara1), []).
rule(bg90, fileCharaMalware(wannacry_filechara2,wannacry), []).
rule(bg91, fileChara('taskscheexe','84c82835a5d21bbcf75a61706d8ab549','3514368','2010-11-20T09:05:05Z','Loader','EXE',wannacry_filechara2), []).
rule(bg92, fileCharaMalware(wannacry_filechara3,wannacry), []).
rule(bg93, fileChara('Unavailable','f351e1fcca0c4ea05fc44d15a17f8b36','65536','2009-07-1401:12:55Z','Encryptor','DLL',wannacry_filechara3), []).
rule(bg94, fileCharaMalware(wannacry_filechara4,wannacry), []).
rule(bg95, fileChara('@WanaDecryptor@exe','7bf2b57f2a205768755c07f238fb32cc','245760','2009-07-1323:19:35Z','Decryptor','EXE',wannacry_filechara4), []).

%% Global Cybersecurity Index
rule(bg96, list_gci_initiating([afghanistan,andorra,angola,armenia,bahamas,barbados,belize,benin,bhutan,bolivia,
	bosnia_herzegovina,burkina_faso,burundi,cambodia,cape,verde,central_african_republic,chad,comoros,congo,cuba,
	democratic_republic_of_the_congo,djibouti,dominica,dominican_republic,el_salvador,equatorial_guinea,eritrea,
	ethiopia,fiji,gabon,gambia,grenada,guatemala,guinea,guinea_bissau,guyana,haiti,honduras,iraq,jordan,kiribati,
	kuwait,kyrgyzstan,lebanon,lesotho,liberia,libya,liechtenstein,madagascar,malawi,maldives,mali,marshall_islands,
	mauritania,micronesia,monaco,mongolia,mozambique,myanmar,namibia,nauru,nepal,nicaragua,niger,palau,state_of_palestine,
	papua_new_guinea,saint_kitts_and_nevis,saint_lucia,saint_vincent_and_the_grenadines,samoa,san_marino,saotome_and_principe,
	seychelles,sierra_leone,solomon_islands,somalia,southsudan,sudan,suriname,swaziland,syrian_arab_republic,tajikistan,
	timor_leste,togo,tonga,trinidad_and_tobago,turkmenistan,tuvalu,uzbekistan,vanuatu,vatican,viet,nam,yemen,zambia,zimbabwe]), []).
rule(bg97, list_gci_maturing([albania,ghana,peru,algeria,greece,philippines,argentina,hungary,poland,austria,iceland,portugal,
	azerbaijan,india,qatar,bahrain,indonesia,romania,bangladesh,iran,rwanda,belarus,ireland,saudi_arabia,belgium,israel,senegal,
	botswana,italy,serbia,brazil,jamaica,slovakia,brunei_darussalam,kazakhstan,slovenia,bulgaria,kenya,southafrica,cameroon,laos,
	spain,chile,latvia,sri,lanka,china,lithuania,tanzania,colombia,luxembourg,thailand,costa_rica,malta,cote_divoire,mexico,
	tunisia,croatia,moldova,turkey,cyprus,montenegro,uganda,czech_republic,morocco,ukraine,northkorea,nigeria,
	united_arab_emirates,denmark,pakistan,uruguay,ecuador,panama,venezuela,germany,paraguay]), []).
rule(bg98, list_gci_leading([australia,japan,oman,canada,southkorea,russia,egypt,malaysia,singapore,estonia,mauritius,sweden,
	finland,netherlands,switzerland,france,new_zealand,united_kingdom,georgia,norway,usa]), []).
rule(bg99, gci_tier(X,initiating), [list_gci_initiating(L),member(X,L)]).
rule(bg100, gci_tier(X,maturing), [list_gci_maturing(L),member(X,L)]).
rule(bg101, gci_tier(X,leading), [list_gci_leading(L),member(X,L)]).

