:- multifile rule/3.
rule(bg0, attackTypeList([ddos, espionage, defacement, data_destruction, sabotage, doxing]), []).
rule(bg1, malwareTypeList([bot, ransomware, rootkit, spyware, trojan, virus, worm, keyloggers, grayware]), []).
rule(bg2, spreadMechanismList([driveByDownloads, homogeneity, vulnerability, backdoor]), []).
rule(bg3, attackMechanismList([zeroday, exploits, priviledgeEscalation, evasion, blended]), []).
rule(bg4, target(X,Att), [targets(L,Att), member(X,L), \+ is_list(X), is_list(L)]).


rule(bg5, natoCountriesList([belgium, canada, denmark, france, iceland, italy, luxembourg, netherlands, norway, portugal, uk, usa, greece, turkey, spain]), []).
rule(bg6, euCountriesList([austria, belgium, bulgaria, croatia, cyprus, czech_republic, denmark, estonia, finland, france, germany, greece, hungary, ireland, italy, latvia, lithuania, luxembourg, malta, netherlands, poland, portugal, romania, slovakia, slovenia, spain, sweden, uk]), []).
%% https://brilliantmaps.com/us-allies-enemies/
%% https://www.msn.com/en-gb/news/photos/which-countries-are-allies-and-which-are-enemies/ss-BBBNVNJ
%% https://today.yougov.com/topics/politics/articles-reports/2017/02/02/americas-friends-and-enemies
rule(bg7, poorRelationList(usa,[northkorea, iran, syria, iraq, afghanistan, russia, libya, somalia, pakistan, palestine]), []).
rule(bg8, poorRelationList(northkorea,[usa, southkorea]), []).
rule(bg9, poorRelation(X,Y), [poorRelationList(X,L), member(Y,L)]).
rule(bg10, poorRelation(X,russia), [natoCountriesList(L), member(X,L)]).
rule(bg11, poorRelation(iran,saudi_arabia), []).

rule(bg12, goodRelationList(usa, [canada, australia, uk, france, italy, ireland, israel, norway, sweden, germany, saudi_arabia, southkorea, cuba]), []).
rule(bg13, goodRelationList(china, [northkorea]), []).
rule(bg14, goodRelation(X,Y), [natoCountriesList(L), member(X,L), member(Y,L), X\=Y]).
rule(bg15, goodRelation(X,Y), [euCountriesList(L), member(X,L), member(Y,L), X\=Y]).
rule(bg16, goodRelation(X,Y), [goodRelationList(X,L), member(Y,L)]).


rule(bg17, knownVulnerabilities([eternalBlue]), []). %% TODO: find comprehensive list of knownVulnerabilities

rule(bg18, malwareUsedInAttack(notPetya, notPetyaAttack), []).
rule(bg19, sha256(notPetya, '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745'),[]).
rule(bg20, sha256(notPetya, '64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1'),[]).
rule(bg21, attackMechanism(notPetya, trojan),[]).
rule(bg22, attackMechanism(notPetya, ransomware),[]).
%% rule(bg_1_6, ,[]).
%% rule(bg_1_6, ,[]).
%% rule(bg_1_6, ,[]).
%% rule(bg_1_6, ,[]).


rule(bg23, sha256(goldenEye, '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745'),[]).


rule(bg24, prominentGroup( fancyBear ), []).
rule(bg25, groupOrigin( fancyBear , russia ), []).
rule(bg26, pastMotives( fancyBear ,[ espionage, doxing ]), []).
rule(bg27, pastTargets( fancyBear ,[georgia,france,jordan,usa,hungary,world_antidoping_agency,
	nato,ukraine,belgium,pakistan,asia_pacific_economic_cooperation,osce,united_kingdom,
	germany,poland,european_commission]), []).
rule(bg28, targetCategory(fancyBear, government,military), []).

rule(bg29, prominentGroup( cozyBear ), []).
rule(bg30, groupOrigin(cozyBear, russia), []).
rule(bg31, pastTargets(cozyBear, [government, diplomatic_organizations, defense, energy, financial, insurance, legal, pharmaceutical, research, technology, brazil, china, japan, mexico, new_zealand, southkorea, turkey]), []).
rule(bg32, malwareLinkedTo(trojanMiniduke, cozyBear), []).
rule(bg33, malwareLinkedTo(trojanCozyduke, cozyBear), []).
rule(bg34, malwareLinkedTo(trojanSeaduke, cozyBear), []).


rule(bg35, prominentGroup( lazarusGrp ), []).
rule(bg36, groupOrigin( lazarusGrp , northkorea ), []).
rule(bg37, malwareLinkedTo( backdoorDuuzer , lazarusGrp ), []).
rule(bg38, malwareLinkedTo( backdoorDestover , lazarusGrp ), []).
rule(bg39, malwareLinkedTo( infostealerFakepude , lazarusGrp ), []).
rule(bg40, malwareLinkedTo( backdoorContopee , lazarusGrp ), []).

rule(bg41, prominentGroup( equationGrp ), []).
rule(bg42, groupOrigin( equationGrp , usa ), []).
rule(bg43, pastTargets( equationGrp ,[ iran , russia , pakistan , afghanistan , india , syria , mali ]), []).

%% https://www.trendmicro.com/vinfo/us/security/definition/exploit-kit
%% rule(bg22, prominentGroup( anglerEK ), []).
%% rule(bg23, groupOrigin( anglerEK , ussr ), []).
%% rule(bg24, groupAttackMethods( anglerEK ,[ driveByDownloads ]), []).
%% rule(bg25, pastMotives( anglerEK ,[ undergroundBusiness ]), []).

rule(bg44, prominentGroup( deepPanda ), []).
rule(bg45, groupOrigin( deepPanda , china ), []).
rule(bg46, groupAttackMethods( deepPanda ,[ zeroday , wateringHole , customMalware ]), []).
rule(bg47, pastTargets( deepPanda ,[usa]), []).
rule(bg48, targetCategory( deepPanda ,[ aerospace , energy , healthcare, military, privateSector ]), []).
rule(bg49, pastMotives( deepPanda ,[ cyberespionage ]), []).

rule(bg50, prominentGroup( butterfly ), []).
rule(bg51, groupOrigin( butterfly , china ), []).
rule(bg52, groupAttackMethods( butterfly ,[ zeroday , customMalware ]), []).
rule(bg53, pastTargets( butterfly ,[ twitter , facebook , apple , microsoft , pharmaceutical, 
	technology , law , oil , preciousMetalMining ]), []).
rule(bg54, pastMotives( butterfly ,[ cyberespionage , undergroundBusiness ]), []).

rule(bg55, prominentGroup( dragonfly ), []).
rule(bg56, groupOrigin( dragonfly , eastEurope ), []).
rule(bg57, groupAttackMethods( dragonfly ,[ spamEmail , wateringHole , customMalware ]), []).
rule(bg58, pastTargets( dragonfly ,[ defense , aerospace , energy ]), []).
rule(bg59, pastMotives( dragonfly ,[ cyberespionage , spy , sabotage ]), []).


rule(bg60, prominentGroup( govRAT ), []).
rule(bg61, groupOrigin( govRAT , china ), []).
rule(bg62, groupAttackMethods( govRAT ,[ clientSideExploits ]), []).
rule(bg63, pastTargets( govRAT ,[usa, taiwan, united_kingdom, singapore, india, canada, 
	japan, indonesia, hong_kong, united_nations, southkorea, switzerland, vietnam, germany, 
	international_olympic_committee]), []).
rule(bg64, targetCategory([ govOfficials , militaryOfficials , enterprises ]), []).
rule(bg65, pastMotives( govRAT ,[ cyberespionage ]), []).


rule(bg66, prominentGroup( pawnStorm ), []).
rule(bg67, groupAttackMethods( pawnStorm ,[ spearphishing , phishingWebsites , ios , exploits , zeroday ]), []).
rule(bg68, pastTargets( pawnStorm ,[ nato , govOfficials , militaryOfficials , russia , ukraine ]), []).
rule(bg69, pastMotives( pawnStorm ,[ cyberespionage ]), []).

rule(bg70, prominentGroup( waterbug ), []).
rule(bg71, groupAttackMethods( waterbug ,[ zeroday , email , stolenCertificates , wateringHole ]), []).
rule(bg72, pastTargets( waterbug ,[ govInstitutions , embassies , education , research ]), []).
rule(bg73, pastMotives( waterbug ,[ cyberespionage , spy , intelligenceGathering ]), []).



rule(bg74, listCountries([afghanistan,andorra,angola,armenia,bahamas,barbados,belize,benin,bhutan,bolivia,
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

rule(bg75, cybersuperpowerlist([ china , israel , iran , usa , northkorea ]), []).
rule(bg76, cybersuperpower(X), [cybersuperpowerlist(L), member(X,L)]).
%% rule(bg65b, listNegHasResources([ indonesia, saudi_arabia, india, southafrica, turkey ]), []).
rule(bg77, listIndustries([ infocomm ]), []).
rule(bg78, listChineseCountries([ china ]), []).
rule(bg79, listEnglishCountries([ usa , united_kingdom ]), []).

rule(bg80, country(X), [listCountries(L),member(X,L)]).
rule(bg81, industry(X), [listIndustries(L),member(X,L)]).
%% rule(bg72, hasResources(X), [listHasResources(L),member(X,L)]).
%% rule(bg72b, neg(hasResources(X)), [listNegHasResources(L),member(X,L)]).
rule(bg82, firstLanguage(chinese,X), [listChineseCountries(L),member(X,L)]).
rule(bg83, firstLanguage(english,X), [listEnglishCountries(L),member(X,L)]).

%% part of nsa
%% have support of us gov/ has relations
rule(bg84, isInfrastructure( nuclear ), []).
rule(bg85, isInfrastructure( electricity ), []).
rule(bg86, isInfrastructure( water ), []).
rule(bg87, informationRich( banking ), []).
rule(bg88, informationRich( infocomm ), []).
rule(bg89, informationRich( consumer ), []).

rule(bg90, possibleMotive( sabotage ,Att), [isInfrastructure(Ind),industry(Ind,V),target(V,Att)]).
rule(bg91, possibleMotive( espionage ,Att), [informationRich(Ind),industry(Ind,V),target(V,Att)]).

%% rule(bg78, isCulprit( equationGroup , flameattack ), []). 
rule(bg92, malwareLinkedTo(flame, equationGrp), []). 

%% rule(bg94, isCulprit([ usa , israel ], flameattack ), []).
rule(bg93, target( middleeast , flameattack ), []).
rule(bg94, malwareUsedInAttack( flame , flameattack ), []).
rule(bg95, ccServer( gowin7 , flame ), []).
rule(bg96, ccServer( secuurity , flame ), []).
rule(bg97, domainRegisteredDetails( gowin7 , adolph_dybevek , prinsen_gate_6 ), []).
rule(bg98, domainRegisteredDetails( secuurity , adolph_dybevek , prinsen_gate_6 ), []).
rule(bg99, addressType( prinsen_gate_6 , hotel ), []).

%% fireeye tech
rule(bg100, fileCharaMalware(wannacry_filechara1,wannacry), []).
rule(bg101, fileChara('mssecsvcexe','db349b97c37d22f5ea1d1841e3c89eb4','3723264','2010-11-20T09:03:08Z','Loader+WormComponent','EXE',wannacry_filechara1), []).
rule(bg102, fileCharaMalware(wannacry_filechara2,wannacry), []).
rule(bg103, fileChara('taskscheexe','84c82835a5d21bbcf75a61706d8ab549','3514368','2010-11-20T09:05:05Z','Loader','EXE',wannacry_filechara2), []).
rule(bg104, fileCharaMalware(wannacry_filechara3,wannacry), []).
rule(bg105, fileChara('Unavailable','f351e1fcca0c4ea05fc44d15a17f8b36','65536','2009-07-1401:12:55Z','Encryptor','DLL',wannacry_filechara3), []).
rule(bg106, fileCharaMalware(wannacry_filechara4,wannacry), []).
rule(bg107, fileChara('@WanaDecryptor@exe','7bf2b57f2a205768755c07f238fb32cc','245760','2009-07-1323:19:35Z','Decryptor','EXE',wannacry_filechara4), []).

%% Global Cybersecurity Index
rule(bg108, list_gci_initiating([afghanistan,andorra,angola,armenia,bahamas,barbados,belize,benin,bhutan,bolivia,
	bosnia_herzegovina,burkina_faso,burundi,cambodia,cape,verde,central_african_republic,chad,comoros,congo,cuba,
	democratic_republic_of_the_congo,djibouti,dominica,dominican_republic,el_salvador,equatorial_guinea,eritrea,
	ethiopia,fiji,gabon,gambia,grenada,guatemala,guinea,guinea_bissau,guyana,haiti,honduras,iraq,jordan,kiribati,
	kuwait,kyrgyzstan,lebanon,lesotho,liberia,libya,liechtenstein,madagascar,malawi,maldives,mali,marshall_islands,
	mauritania,micronesia,monaco,mongolia,mozambique,myanmar,namibia,nauru,nepal,nicaragua,niger,palau,state_of_palestine,
	papua_new_guinea,saint_kitts_and_nevis,saint_lucia,saint_vincent_and_the_grenadines,samoa,san_marino,saotome_and_principe,
	seychelles,sierra_leone,solomon_islands,somalia,southsudan,sudan,suriname,swaziland,syrian_arab_republic,tajikistan,
	timor_leste,togo,tonga,trinidad_and_tobago,turkmenistan,tuvalu,uzbekistan,vanuatu,vatican,viet,nam,yemen,zambia,zimbabwe]), []).
rule(bg109, list_gci_maturing([albania,ghana,peru,algeria,greece,philippines,argentina,hungary,poland,austria,iceland,portugal,
	azerbaijan,india,qatar,bahrain,indonesia,romania,bangladesh,iran,rwanda,belarus,ireland,saudi_arabia,belgium,israel,senegal,
	botswana,italy,serbia,brazil,jamaica,slovakia,brunei_darussalam,kazakhstan,slovenia,bulgaria,kenya,southafrica,cameroon,laos,
	spain,chile,latvia,sri,lanka,china,lithuania,tanzania,colombia,luxembourg,thailand,costa_rica,malta,cote_divoire,mexico,
	tunisia,croatia,moldova,turkey,cyprus,montenegro,uganda,czech_republic,morocco,ukraine,northkorea,nigeria,
	united_arab_emirates,denmark,pakistan,uruguay,ecuador,panama,venezuela,germany,paraguay]), []).
rule(bg110, list_gci_leading([australia,japan,oman,canada,southkorea,russia,egypt,malaysia,singapore,estonia,mauritius,sweden,
	finland,netherlands,switzerland,france,new_zealand,united_kingdom,georgia,norway,usa]), []).
rule(bg111, gci_tier(X,initiating), [list_gci_initiating(L),member(X,L)]).
rule(bg112, gci_tier(X,maturing), [list_gci_maturing(L),member(X,L)]).
rule(bg113, gci_tier(X,leading), [list_gci_leading(L),member(X,L)]).

