:- multifile rule/3.
%% :- multifile hasResources/1.
%% :- multifile malwareUsedInAttack/2.
%% :- multifile target/2.

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


rule(bg64, listCountries([ china , israel , iran , usa , uk , northkorea , southkorea ]), []).
rule(bg65, listHasResources([ china , israel , iran , usa , northkorea ]), []).
rule(bg65b, listNegHasResources([ indonesia, saudiarabia, india, southafrica, turkey ]), []).
rule(bg66, listIndustries([ infocomm ]), []).
rule(bg67, listChineseCountries([ china ]), []).
rule(bg68, listEnglishCountries([ usa , uk ]), []).

rule(bg70, isCountry(X), [listCountries(L),member(X,L)]).
rule(bg71, industry(X), [listIndustries(L),member(X,L)]).
rule(bg72, hasResources(X), [listHasResources(L),member(X,L)]).
rule(bg72b, neg(hasResources(X)), [listNegHasResources(L),member(X,L)]).
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
