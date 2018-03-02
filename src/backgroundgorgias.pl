:- multifile rule/3.

rule(bg8, prominentGroup(equationGrp), []).
rule(bg9, country(equationGrp,usa), []).
rule(bg10, pastTargets(equationGrp,[iran,russia,pakistan,afghanistan,india,syria,mali]), []).

rule(bg14, prominentGroup(anglerEK), []).
rule(bg15, country(anglerEK,ussr), []).
rule(bg16, pastAttackMethods(anglerEK,[driveByDownloads]), []).
rule(bg17, pastMotives(anglerEK,[undergroundBusiness]), []).

rule(bg20, prominentGroup(blackVine), []).
rule(bg21, country(blackVine,china), []).
rule(bg22, pastAttackMethods(blackVine,[zeroday,wateringHole,customMalware]), []).
rule(bg23, pastTargets(blackVine,[aerospace,energy,healthcare]), []).
rule(bg24, pastMotives(blackVine,[cyberespionage]), []).

rule(bg26, prominentGroup(butterfly), []).
rule(bg27, country(butterfly,china), []).
rule(bg28, pastAttackMethods(butterfly,[zeroday,customMalware]), []).
rule(bg29, pastTargets(butterfly,[twitter,facebook,apple,microsoft,pharmaceutical,technology,law,oil,preciousMetalMining]), []).
rule(bg30, pastMotives(butterfly,[cyberespionage,undergroundBusiness]), []).

rule(bg33, prominentGroup(dragonfly), []).
rule(bg34, country(dragonfly,eastEurope), []).
rule(bg35, pastAttackMethods(dragonfly,[spamEmail,wateringHole,customMalware]), []).
rule(bg36, pastTargets(dragonfly,[defense,aerospace,energy]), []).
rule(bg37, pastMotives(dragonfly,[cyberespionage,spy,sabotage]), []).


rule(bg40, prominentGroup(govRAT), []).
rule(bg41, pastAttackMethods(govRAT,[clientSideExploits]), []).
rule(bg42, pastTargets(govRAT,[govOfficials,militaryOfficials,enterprises]), []).
rule(bg43, pastMotives(govRAT,[cyberespionage]), []).

rule(bg45, prominentGroup(pawnStorm), []).
rule(bg46, pastAttackMethods(pawnStorm,[spearphishing,phishingWebsites,ios,exploits,zeroday]), []).
rule(bg47, pastTargets(pawnStorm,[nato,govOfficials,militaryOfficials,russia,ukraine]), []).
rule(bg48, pastMotives(pawnStorm,[cyberespionage]), []).

rule(bg50, prominentGroup(waterbug), []).
rule(bg51, pastAttackMethods(waterbug,[zeroday,email,stolenCertificates,wateringHole]), []).
rule(bg52, pastTargets(waterbug,[govInstitutions,embassies,education,research]), []).
rule(bg53, pastMotives(waterbug,[cyberespionage,spy,intelligenceGathering]), []).


rule(bg56, listCountries([china,israel,iran,usa,uk,northkorea,southkorea]), []).
rule(bg57, listHasResources([china,israel,iran,usa,northkorea]), []).
rule(bg58, listIndustries([infocomm]), []).
rule(bg59, listChineseCountries([china]), []).
rule(bg60, listEnglishCountries([usa,uk]), []).

rule(bg62, isCountry(X), [listCountries(L),member(X,L)]).
rule(bg63, industry(X), [listIndustries(L),member(X,L)]).
rule(bg64, hasResources(X), [listHasResources(L),member(X,L)]).
rule(bg65, firstLanguage(chinese,X), [listChineseCountries(L),member(X,L)]).
rule(bg66, firstLanguage(english,X), [listEnglishCountries(L),member(X,L)]).

rule(bg70, isCulprit(equationGroup,flameattack), []).
rule(bg71, malwareUsedInAttack(flame,flameattack), []).

rule(bg73, isInfrastructure(nuclear), []).
rule(bg74, isInfrastructure(electricity), []).
rule(bg75, isInfrastructure(water), []).
rule(bg76, informationRich(banking), []).
rule(bg77, informationRich(infocomm), []).
rule(bg78, informationRich(consumer), []).

rule(bg80, possibleMotive(sabotage,Att), [isInfrastructure(Ind),industry(Ind,V),target(V,Att)]).
rule(bg81, possibleMotive(espionage,Att), [informationRich(Ind),industry(Ind,V),target(V,Att)]).

rule(bg86, isCulprit([usa,israel],flameattack), []).
rule(bg87, target(middleeast,flameattack), []).
rule(bg88, malwareUsedInAttack(flame,flameattack), []).
rule(bg89, ccServer('gowin7', flame), []).
% rule(bg90, ccServer('secuurity', flame), []).
rule(bg91, domainRegisteredDetails(gowin7, 'adolph dybevek', 'prinsen gate 6'), []).
rule(bg92, domainRegisteredDetails(secuurity, 'adolph dybevek', 'prinsen gate 6'), []).
rule(bg93, addressType('prinsen gate 6', hotel), []).
