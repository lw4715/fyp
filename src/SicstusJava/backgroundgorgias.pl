:- multifile rule/3.

rule(bg8, prominentGroup( lazarusGrp ), []).
rule(bg9, country( lazarusGrp , northkorea ), []).
rule(bg10, malwareLinkedTo( backdoorDuuzer , lazarusGrp ), []).
rule(bg11, malwareLinkedTo( backdoorDestover , lazarusGrp ), []).
rule(bg12, malwareLinkedTo( infostealerFakepude , lazarusGrp ), []).
rule(bg13, malwareLinkedTo( backdoorContopee , lazarusGrp ), []).

rule(bg16, prominentGroup( equationGrp ), []).
rule(bg17, country( equationGrp , usa ), []).
rule(bg18, pastTargets( equationGrp ,[ iran , russia , pakistan , afghanistan , india , syria , mali ]), []).

rule(bg22, prominentGroup( anglerEK ), []).
rule(bg23, country( anglerEK , ussr ), []).
rule(bg24, pastAttackMethods( anglerEK ,[ driveByDownloads ]), []).
rule(bg25, pastMotives( anglerEK ,[ undergroundBusiness ]), []).

rule(bg28, prominentGroup( blackVine ), []).
rule(bg29, country( blackVine , china ), []).
rule(bg30, pastAttackMethods( blackVine ,[ zeroday , wateringHole , customMalware ]), []).
rule(bg31, pastTargets( blackVine ,[ aerospace , energy , healthcare ]), []).
rule(bg32, pastMotives( blackVine ,[ cyberespionage ]), []).

rule(bg34, prominentGroup( butterfly ), []).
rule(bg35, country( butterfly , china ), []).
rule(bg36, pastAttackMethods( butterfly ,[ zeroday , customMalware ]), []).
rule(bg37, pastTargets( butterfly ,[ twitter , facebook , apple , microsoft , pharmaceutical , technology , law , oil , preciousMetalMining ]), []).
rule(bg38, pastMotives( butterfly ,[ cyberespionage , undergroundBusiness ]), []).

rule(bg41, prominentGroup( dragonfly ), []).
rule(bg42, country( dragonfly , eastEurope ), []).
rule(bg43, pastAttackMethods( dragonfly ,[ spamEmail , wateringHole , customMalware ]), []).
rule(bg44, pastTargets( dragonfly ,[ defense , aerospace , energy ]), []).
rule(bg45, pastMotives( dragonfly ,[ cyberespionage , spy , sabotage ]), []).


rule(bg48, prominentGroup( govRAT ), []).
rule(bg49, pastAttackMethods( govRAT ,[ clientSideExploits ]), []).
rule(bg50, pastTargets( govRAT ,[ govOfficials , militaryOfficials , enterprises ]), []).
rule(bg51, pastMotives( govRAT ,[ cyberespionage ]), []).

rule(bg53, prominentGroup( pawnStorm ), []).
rule(bg54, pastAttackMethods( pawnStorm ,[ spearphishing , phishingWebsites , ios , exploits , zeroday ]), []).
rule(bg55, pastTargets( pawnStorm ,[ nato , govOfficials , militaryOfficials , russia , ukraine ]), []).
rule(bg56, pastMotives( pawnStorm ,[ cyberespionage ]), []).

rule(bg58, prominentGroup( waterbug ), []).
rule(bg59, pastAttackMethods( waterbug ,[ zeroday , email , stolenCertificates , wateringHole ]), []).
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
	mauritius,sweden,finland,netherlands,switzerland,france,new_zealand,uk,georgia,norway,usa]), []).

%% rule(bg65, listHasResources([ china , israel , iran , usa , northkorea ]), []).
%% rule(bg65b, listNegHasResources([ indonesia, saudi_arabia, india, southafrica, turkey ]), []).
rule(bg66, listIndustries([ infocomm ]), []).
rule(bg67, listChineseCountries([ china ]), []).
rule(bg68, listEnglishCountries([ usa , uk ]), []).

rule(bg70, isCountry(X), [listCountries(L),member(X,L)]).
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

rule(bg78, isCulprit( equationGroup , flameattack ), []). 
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
	finland,netherlands,switzerland,france,new_zealand,uk,georgia,norway,usa]), []).
rule(bg115, gci_tier(X,initiating), [list_gci_initiating(L),member(X,L)]).
rule(bg116, gci_tier(X,maturing), [list_gci_maturing,member(X,L)]).
rule(bg117, gci_tier(X,leading), [list_gci_leading,member(X,L)]).

